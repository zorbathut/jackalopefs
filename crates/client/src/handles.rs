//! Client-side table of open handles. The client chooses handle ids and never reuses one, so when an open's outcome is unknown (timeout, lost connection) the client can simply ask the server to release that id: releasing an id the server never opened is harmless, and releasing one it did closes the fd the client would otherwise never learn about.
//!
//! The table's held, dead and owed handles are modelled in `spec/session.qnt`; a change to them updates the model, or its commit says why not (`spec/README.md`, "Keeping it in sync").

use crate::inodes::KeyNode;
use jackalopefs_proto::control::{HandlesProcess, HandlesTotals};
use jackalopefs_proto::{Name, Path, Request, Response};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::watch;

/// The process that opened a handle: its thread group's id and name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Opener {
    pub pid: u32,
    pub name: String,
}

/// One row per opener of `handles`, each given as its opener (`None` when it could not be named), whether it is a directory, and its path; the largest rows first.
fn processes<'a>(
    handles: impl IntoIterator<Item = (Option<&'a Opener>, bool, &'a Path)>,
) -> Vec<HandlesProcess> {
    #[derive(Default)]
    struct Row<'a> {
        files: u64,
        dirs: u64,
        /// Handles under each directory, counted at every ancestor of the one each is in.
        under: HashMap<&'a [Name], u64>,
    }
    let mut rows: HashMap<Option<&Opener>, Row> = HashMap::new();
    for (opener, dir, path) in handles {
        let row = rows.entry(opener).or_default();
        if dir {
            row.dirs += 1;
        } else {
            row.files += 1;
        }
        let names = path.names();
        let parent = &names[..names.len().saturating_sub(1)];
        for depth in 0..=parent.len() {
            *row.under.entry(&parent[..depth]).or_default() += 1;
        }
    }
    let mut out: Vec<HandlesProcess> = rows
        .into_iter()
        .map(|(opener, row)| {
            let total = row.files + row.dirs;
            let within = row
                .under
                .iter()
                .filter(|(_, n)| 2 * **n >= total)
                .map(|(dir, _)| *dir)
                .max_by(|a, b| a.len().cmp(&b.len()).then_with(|| b.cmp(a)))
                .unwrap_or(&[]);
            HandlesProcess {
                pid: opener.map_or(0, |o| o.pid),
                name: opener.map_or_else(String::new, |o| o.name.clone()),
                files: row.files,
                dirs: row.dirs,
                within: fmt_within(within),
            }
        })
        .collect();
    out.sort_by(|a, b| {
        (b.files + b.dirs)
            .cmp(&(a.files + a.dirs))
            .then(a.pid.cmp(&b.pid))
    });
    out
}

/// A directory relative to the mount, `/` being its root.
fn fmt_within(names: &[Name]) -> String {
    let mut out = String::new();
    for name in names {
        out.push('/');
        out.push_str(&String::from_utf8_lossy(name.as_bytes()));
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleKind {
    File,
    Dir,
}

#[derive(Debug)]
pub struct HandleRec {
    pub nodeid: u64,
    /// The file the handle was opened on, which a reopen must find at the path again.
    pub key: KeyNode,
    pub path: Path,
    /// The flags the server opened with, which is how the file is reopened after a lost session and what says whether this handle writes; the kernel's own flags differ in access mode and append.
    pub flags: i32,
    pub kind: HandleKind,
    /// The process whose open made the handle, `None` when it could not be named; known to this client alone.
    pub opener: Option<Opener>,
    /// Set when a reopen after a lost session found a different inode (or nothing) at the path; every later use fails with `ESTALE`.
    dead: AtomicBool,
}

impl HandleRec {
    pub fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }

    /// Whether the server opened the handle to append, placing every write at its own end of file.
    pub fn appends(&self) -> bool {
        self.flags & libc::O_APPEND != 0
    }

    fn mark_dead(&self) {
        self.dead.store(true, Ordering::Relaxed);
    }

    /// The request that reopens this handle after the server lost it: creation flags are dropped, the id is reused.
    pub fn reopen_request(&self, fh: u64) -> Request {
        match self.kind {
            HandleKind::File => Request::Open {
                fh,
                path: self.path.clone(),
                flags: self.flags & !(libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC),
            },
            HandleKind::Dir => Request::Opendir {
                fh,
                path: self.path.clone(),
            },
        }
    }
}

/// A release owed, and the generation of the connection it is being sent on, if it is.
struct OwedRelease {
    req: Request,
    sending_on: Option<u64>,
}

#[derive(Default)]
pub struct HandleTable {
    next: AtomicU64,
    map: Mutex<HashMap<u64, Arc<HandleRec>>>,
    /// Releases that failed for want of a connection, or timed out, by handle id, until the server answers one: the connection's release task sends each once on its connection, and a session that resumes gets those its last connection could not deliver.
    owed: Mutex<BTreeMap<u64, OwedRelease>>,
    /// Counts the releases ever owed, so the connection's release task wakes for each.
    owed_count: watch::Sender<u64>,
    /// The handles in `map` of each kind, changed under its lock.
    files: AtomicU64,
    dirs: AtomicU64,
    /// Where the releases owed are recorded in the session model's terms.
    #[cfg(feature = "spec-trace")]
    recorder: std::sync::OnceLock<Arc<jackalopefs_perf::spec_trace::Recorder>>,
}

impl HandleTable {
    #[cfg(feature = "spec-trace")]
    pub fn trace(&self, recorder: Arc<jackalopefs_perf::spec_trace::Recorder>) {
        assert!(
            self.recorder.set(recorder).is_ok(),
            "a handle table is traced once"
        );
    }

    /// A fresh id; ids are never reused within a client's lifetime.
    pub fn alloc(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed) + 1
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &self,
        fh: u64,
        nodeid: u64,
        key: KeyNode,
        path: Path,
        flags: i32,
        kind: HandleKind,
        opener: Option<Opener>,
    ) -> Arc<HandleRec> {
        let rec = Arc::new(HandleRec {
            nodeid,
            key,
            path,
            flags,
            kind,
            opener,
            dead: AtomicBool::new(false),
        });
        let mut map = self.map.lock();
        self.count(kind).fetch_add(1, Ordering::Relaxed);
        if let Some(old) = map.insert(fh, rec.clone()) {
            self.count(old.kind).fetch_sub(1, Ordering::Relaxed);
            tracing::error!(fh, "handle id reused; this is a bug");
        }
        rec
    }

    fn count(&self, kind: HandleKind) -> &AtomicU64 {
        match kind {
            HandleKind::File => &self.files,
            HandleKind::Dir => &self.dirs,
        }
    }

    /// The handles open, by kind.
    pub fn totals(&self) -> HandlesTotals {
        HandlesTotals {
            files: self.files.load(Ordering::Relaxed),
            dirs: self.dirs.load(Ordering::Relaxed),
        }
    }

    /// The handles open, by the process that opened them, the largest first; the walk is outside the table's lock, which every call on a handle takes.
    pub fn processes(&self) -> Vec<HandlesProcess> {
        let recs: Vec<Arc<HandleRec>> = self.map.lock().values().cloned().collect();
        processes(
            recs.iter()
                .map(|r| (r.opener.as_ref(), r.kind == HandleKind::Dir, &r.path)),
        )
    }

    pub fn get(&self, fh: u64) -> Option<Arc<HandleRec>> {
        self.map.lock().get(&fh).cloned()
    }

    pub fn remove(&self, fh: u64) -> Option<Arc<HandleRec>> {
        let mut map = self.map.lock();
        let rec = map.remove(&fh)?;
        self.count(rec.kind).fetch_sub(1, Ordering::Relaxed);
        Some(rec)
    }

    /// Owe `release`, which from now on is sent in the background and so is ordered ([`Request::Release`]); a release already owed stays as it is.
    pub fn owe_release(&self, release: Request) {
        let release = match release {
            Request::Release { fh, .. } => Request::Release { fh, ordered: true },
            Request::Releasedir { fh, .. } => Request::Releasedir { fh, ordered: true },
            other => unreachable!("only releases are owed: {other:?}"),
        };
        let fh = release.fhs()[0].expect("a release names its handle");
        #[cfg(feature = "spec-trace")]
        if let Some(recorder) = self.recorder.get() {
            recorder.record(jackalopefs_perf::spec_trace::EventSpec::Owed { fh });
        }
        let owed = match self.owed.lock().entry(fh) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(OwedRelease {
                    req: release,
                    sending_on: None,
                });
                true
            }
            std::collections::btree_map::Entry::Occupied(_) => false,
        };
        if owed {
            self.owed_count.send_modify(|count| *count += 1);
        }
    }

    /// Changes whenever a release is owed from now on.
    pub fn owed_changes(&self) -> watch::Receiver<u64> {
        self.owed_count.subscribe()
    }

    /// The handles whose release is owed and not being sent: those a connection may send.
    pub fn owed_sendable(&self) -> Vec<u64> {
        self.owed
            .lock()
            .iter()
            .filter(|(_, owed)| owed.sending_on.is_none())
            .map(|(fh, _)| *fh)
            .collect()
    }

    /// The release owed of `fh`, now being sent on the connection of `generation`.
    pub fn owed_send(&self, fh: u64, generation: u64) -> Request {
        let mut owed = self.owed.lock();
        let owed = owed.get_mut(&fh).expect("a release sent is owed");
        owed.sending_on = Some(generation);
        owed.req.clone()
    }

    /// The release of `fh` sent on the connection of `generation` was answered, and is owed no more. One that was not stays owed, sending on that connection until it ends.
    pub fn owed_delivered(&self, fh: u64, generation: u64) {
        let mut owed = self.owed.lock();
        if owed
            .get(&fh)
            .is_some_and(|o| o.sending_on == Some(generation))
        {
            owed.remove(&fh);
        }
    }

    /// The connection of `generation` has ended: what it did not deliver may go on the next.
    pub fn owed_connection_ended(&self, generation: u64) {
        for owed in self.owed.lock().values_mut() {
            if owed.sending_on == Some(generation) {
                owed.sending_on = None;
            }
        }
    }

    /// A new session holds none of the old one's handles, so the releases owed to that one are moot.
    pub fn owed_moot(&self) {
        self.owed.lock().clear();
    }

    pub fn len(&self) -> usize {
        self.map.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Any live handle on `nodeid`, for an operation that arrives without one after the node's last name is gone (`fstat`, `fchmod` and the like on an unlinked file).
    pub fn any_live_for(&self, nodeid: u64) -> Option<u64> {
        self.map
            .lock()
            .iter()
            .find(|(_, r)| r.nodeid == nodeid && !r.is_dead())
            .map(|(fh, _)| *fh)
    }

    /// Whether a live handle on `nodeid` was opened for writing, in which case the kernel may hold dirty pages for it that it can still write back; through a dead handle a write fails at once, so [`Self::may_be_dirty`] is the question when the pages themselves matter.
    pub fn has_writer(&self, nodeid: u64) -> bool {
        self.map.lock().values().any(|r| {
            r.nodeid == nodeid && !r.is_dead() && r.flags & libc::O_ACCMODE != libc::O_RDONLY
        })
    }

    /// Whether the kernel may hold pages for `nodeid` that the server has not seen: some handle on it was opened for writing and the kernel has not released it. A dead handle counts, since what a reconnect did to the handle did nothing to the kernel's pages.
    pub fn may_be_dirty(&self, nodeid: u64) -> bool {
        self.map
            .lock()
            .values()
            .any(|r| r.nodeid == nodeid && r.flags & libc::O_ACCMODE != libc::O_RDONLY)
    }

    /// Node ids of every live handle, for post-reconnect invalidation.
    pub fn open_nodeids(&self) -> Vec<u64> {
        self.map
            .lock()
            .values()
            .filter(|r| !r.is_dead())
            .map(|r| r.nodeid)
            .collect()
    }

    /// Everything that needs reopening when the server did not resume our session.
    pub fn live(&self) -> Vec<(u64, Arc<HandleRec>)> {
        self.map
            .lock()
            .iter()
            .filter(|(_, r)| !r.is_dead())
            .map(|(fh, r)| (*fh, r.clone()))
            .collect()
    }

    /// Every handle is stale: what the paths led to is gone.
    pub fn kill_all(&self) {
        for rec in self.map.lock().values() {
            rec.mark_dead();
        }
    }

    /// Judge a reopen reply: the same file keeps the handle alive, anything else kills it. The same inode number is not the same file: numbers are recycled, and a server restart is ample time.
    pub fn apply_reopen(
        &self,
        fh: u64,
        rec: &HandleRec,
        outcome: Result<Response, crate::client::Error>,
    ) {
        match outcome {
            Ok(Response::Opened { attr }) if rec.key.describes(&attr) => {}
            Ok(Response::Opened { attr }) => {
                tracing::warn!(fh, path = ?rec.path, was = ?rec.key, now = ?KeyNode::of(&attr), "path now names a different file; handle is stale");
                rec.mark_dead();
            }
            Ok(other) => {
                tracing::warn!(fh, path = ?rec.path, "unexpected reply to reopen: {other:?}; handle is stale");
                rec.mark_dead();
            }
            Err(e) => {
                tracing::warn!(fh, path = ?rec.path, "reopen failed: {e}; handle is stale");
                rec.mark_dead();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jackalopefs_proto::{Attr, FileKind, TimeSpec};

    fn attr(ino: u64) -> Attr {
        let t = TimeSpec { sec: 0, nsec: 0 };
        Attr {
            ino,
            size: 0,
            blocks: 0,
            atime: t,
            mtime: t,
            ctime: t,
            kind: FileKind::Regular,
            perm: 0o644,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            xattr_names: None,
            identity: jackalopefs_proto::Identity {
                handle_type: 1,
                handle: ino.to_le_bytes().to_vec(),
            },
            foreign: false,
        }
    }

    fn release(fh: u64) -> Request {
        Request::Release { fh, ordered: false }
    }

    #[test]
    fn a_release_owed_is_sent_once_per_connection_until_one_delivers_it() {
        let table = HandleTable::default();
        let mut changes = table.owed_changes();
        table.owe_release(release(1));
        assert!(
            changes.has_changed().unwrap(),
            "owing wakes the release task"
        );
        changes.borrow_and_update();
        table.owe_release(release(1));
        assert!(
            !changes.has_changed().unwrap(),
            "a release already owed is not owed again"
        );
        assert_eq!(table.owed_sendable(), vec![1]);
        assert_eq!(
            table.owed_send(1, 1),
            Request::Release {
                fh: 1,
                ordered: true
            },
            "a release owed is sent ordered"
        );
        assert!(
            table.owed_sendable().is_empty(),
            "not sent twice on one connection"
        );
        assert!(
            table.owed_sendable().is_empty(),
            "one undelivered is not sent again on the connection that failed it"
        );
        table.owed_connection_ended(1);
        assert_eq!(
            table.owed_sendable(),
            vec![1],
            "the next connection sends it"
        );
        table.owed_send(1, 2);
        table.owed_delivered(1, 2);
        assert!(table.owed_sendable().is_empty());
        table.owed_connection_ended(2);
        assert!(
            table.owed_sendable().is_empty(),
            "delivered, it is owed no more"
        );
    }

    #[test]
    fn a_new_session_makes_the_releases_owed_moot() {
        let table = HandleTable::default();
        table.owe_release(release(1));
        table.owe_release(release(2));
        table.owed_send(1, 1);
        table.owed_moot();
        assert!(table.owed_sendable().is_empty());
        table.owe_release(release(1));
        table.owed_delivered(1, 1);
        assert_eq!(
            table.owed_sendable(),
            vec![1],
            "the old connection's answer settles nothing owed since"
        );
    }

    #[test]
    fn reopen_verifies_identity() {
        let table = HandleTable::default();
        let fh = table.alloc();
        let rec = table.insert(
            fh,
            42,
            KeyNode::of(&attr(42)),
            Path::root(),
            libc::O_RDWR | libc::O_TRUNC | libc::O_CREAT,
            HandleKind::File,
            None,
        );
        assert!(
            matches!(rec.reopen_request(fh), Request::Open { flags, .. } if flags == libc::O_RDWR)
        );
        table.apply_reopen(fh, &rec, Ok(Response::Opened { attr: attr(42) }));
        assert!(!rec.is_dead());
        table.apply_reopen(fh, &rec, Ok(Response::Opened { attr: attr(43) }));
        assert!(rec.is_dead());
        let recycled = table.alloc();
        let rec = table.insert(
            recycled,
            42,
            KeyNode::of(&attr(42)),
            Path::root(),
            libc::O_RDONLY,
            HandleKind::File,
            None,
        );
        let mut same_number = attr(42);
        same_number.identity.handle.push(1);
        table.apply_reopen(recycled, &rec, Ok(Response::Opened { attr: same_number }));
        assert!(rec.is_dead(), "the same inode number is not the same file");
        assert!(table.open_nodeids().is_empty());
        assert!(table.live().is_empty());
        assert!(table.alloc() > fh);
    }

    #[test]
    fn any_live_handle_for_a_node() {
        let table = HandleTable::default();
        let a = table.alloc();
        let rec_a = table.insert(
            a,
            42,
            KeyNode::of(&attr(42)),
            Path::root(),
            libc::O_RDONLY,
            HandleKind::File,
            None,
        );
        let b = table.alloc();
        table.insert(
            b,
            43,
            KeyNode::of(&attr(43)),
            Path::root(),
            libc::O_RDONLY,
            HandleKind::File,
            None,
        );
        assert_eq!(table.any_live_for(42), Some(a));
        assert_eq!(table.any_live_for(43), Some(b));
        assert_eq!(table.any_live_for(44), None);
        table.apply_reopen(a, &rec_a, Ok(Response::Opened { attr: attr(99) }));
        assert!(rec_a.is_dead());
        assert_eq!(table.any_live_for(42), None);
    }

    #[test]
    fn a_writer_is_a_live_file_handle_that_can_write() {
        let table = HandleTable::default();
        let r = table.alloc();
        table.insert(
            r,
            42,
            KeyNode::of(&attr(42)),
            Path::root(),
            libc::O_RDONLY,
            HandleKind::File,
            None,
        );
        let d = table.alloc();
        table.insert(
            d,
            42,
            KeyNode::of(&attr(42)),
            Path::root(),
            libc::O_RDONLY | libc::O_DIRECTORY,
            HandleKind::Dir,
            None,
        );
        assert!(!table.has_writer(42));
        assert!(!table.may_be_dirty(42));
        let w = table.alloc();
        let rec_w = table.insert(
            w,
            42,
            KeyNode::of(&attr(42)),
            Path::root(),
            libc::O_RDWR,
            HandleKind::File,
            None,
        );
        assert!(table.has_writer(42));
        assert!(!table.has_writer(43));
        assert!(table.may_be_dirty(42));
        assert!(!table.may_be_dirty(43));
        table.apply_reopen(w, &rec_w, Ok(Response::Opened { attr: attr(99) }));
        assert!(rec_w.is_dead());
        assert!(!table.has_writer(42));
        assert!(
            table.may_be_dirty(42),
            "the kernel still holds what was written through a handle that died"
        );
        table.remove(w);
        assert!(!table.may_be_dirty(42));
        let w2 = table.alloc();
        table.insert(
            w2,
            42,
            KeyNode::of(&attr(42)),
            Path::root(),
            libc::O_WRONLY | libc::O_CREAT,
            HandleKind::File,
            None,
        );
        assert!(table.has_writer(42));
        table.remove(w2);
        assert!(!table.has_writer(42));
    }

    #[test]
    fn totals_and_processes_follow_inserts_and_removes() {
        let table = HandleTable::default();
        let find = Opener {
            pid: 7,
            name: "find".into(),
        };
        let dir = |name: &str| {
            Path::from_names(vec![
                jackalopefs_proto::Name::new("tree").unwrap(),
                jackalopefs_proto::Name::new(name).unwrap(),
            ])
            .unwrap()
        };
        let mut dirs = Vec::new();
        for name in ["a", "b", "c"] {
            let fh = table.alloc();
            table.insert(
                fh,
                42,
                KeyNode::of(&attr(42)),
                dir(name),
                libc::O_RDONLY | libc::O_DIRECTORY,
                HandleKind::Dir,
                Some(find.clone()),
            );
            dirs.push(fh);
        }
        let file = table.alloc();
        table.insert(
            file,
            43,
            KeyNode::of(&attr(43)),
            Path::root(),
            libc::O_RDONLY,
            HandleKind::File,
            None,
        );
        assert_eq!(table.totals(), HandlesTotals { files: 1, dirs: 3 });
        let rows = table.processes();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (rows[0].pid, rows[0].dirs, rows[0].within.as_str()),
            (7, 3, "/tree")
        );
        assert_eq!((rows[1].pid, rows[1].files), (0, 1));
        table.remove(dirs[0]);
        table.remove(file);
        assert!(table.remove(file).is_none());
        assert_eq!(table.totals(), HandlesTotals { files: 0, dirs: 2 });
        assert_eq!(table.processes().len(), 1);
    }

    fn path_of(text: &str) -> Path {
        Path::from_names(
            text.split('/')
                .filter(|s| !s.is_empty())
                .map(|s| Name::new(s).unwrap())
                .collect(),
        )
        .unwrap()
    }

    fn opener(pid: u32, name: &str) -> Opener {
        Opener {
            pid,
            name: name.into(),
        }
    }

    #[test]
    fn rows_are_per_opener_largest_first_with_kinds_counted() {
        let find = opener(10, "find");
        let torrent = opener(20, "qbittorrent");
        let paths: Vec<Path> = (0..5).map(|i| path_of(&format!("a/d{i}"))).collect();
        let file = path_of("v/x.mkv");
        let mut handles: Vec<(Option<&Opener>, bool, &Path)> =
            paths.iter().map(|p| (Some(&find), true, p)).collect();
        handles.push((Some(&torrent), false, &file));
        handles.push((Some(&torrent), false, &file));
        handles.push((Some(&find), false, &file));
        handles.push((None, true, &file));
        let rows = processes(handles);
        let summary: Vec<(u32, &str, u64, u64)> = rows
            .iter()
            .map(|r| (r.pid, r.name.as_str(), r.files, r.dirs))
            .collect();
        assert_eq!(
            summary,
            vec![(10, "find", 1, 5), (20, "qbittorrent", 2, 0), (0, "", 0, 1)]
        );
    }

    #[test]
    fn within_is_the_deepest_directory_holding_half() {
        let walker = opener(1, "walker");
        let deep: Vec<Path> = (0..6)
            .map(|i| path_of(&format!("video/old/show/s{i}")))
            .collect();
        let elsewhere: Vec<Path> = (0..4).map(|i| path_of(&format!("music/a{i}"))).collect();
        let handles = deep
            .iter()
            .chain(&elsewhere)
            .map(|p| (Some(&walker), true, p));
        assert_eq!(processes(handles)[0].within, "/video/old/show");

        let spread: Vec<Path> = ["a/x", "b/x", "c/x"].iter().map(|p| path_of(p)).collect();
        let handles = spread.iter().map(|p| (Some(&walker), true, p));
        assert_eq!(processes(handles)[0].within, "/");

        let root = Path::root();
        assert_eq!(
            processes([(Some(&walker), true, &root)])[0].within,
            "/",
            "the root's place is the root"
        );
    }
}
