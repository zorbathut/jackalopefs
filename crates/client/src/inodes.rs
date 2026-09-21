//! The client's inode table. A node is one file on the server, known by its inode number and its identity together ([`KeyNode`]): inode numbers alone are recycled, and repeat between a snapshot and its origin. Each node has one number, which the kernel knows it by and userspace sees as `st_ino` (fuser reports `attr.ino` as both): the file's real inode number wherever that tells it apart, a substitute derived from its identity where it cannot (see [`NodeTable::id_for`]). Hardlinks share a node. What else the table keeps is how to *address* each node on the wire, the `(parent, name)` aliases it has been reached through, and the kernel's lookup count.
//!
//! Lock discipline: the owner wraps the table in a `parking_lot::Mutex`, takes it briefly to compute a path or apply a result, and never holds it across an `.await` or a notifier call.

use jackalopefs_proto::{Attr, FileKind, Identity, Name, Path};
use std::collections::HashMap;

/// The FUSE root nodeid. A server knows the export root by its own inode number; the client rewrites that to this as replies come in.
pub const ROOT: u64 = 1;

/// What a node is: one file on the server.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct KeyNode {
    pub ino: u64,
    pub identity: Identity,
}

/// A file as a reply describes it, as far as the table cares.
#[derive(Clone, Copy, Debug)]
pub struct Seen<'a> {
    pub ino: u64,
    pub identity: &'a Identity,
    /// Outside the export root's subvolume, where inode numbers repeat the root subvolume's.
    pub foreign: bool,
    pub kind: FileKind,
}

impl<'a> From<&'a Attr> for Seen<'a> {
    fn from(attr: &'a Attr) -> Seen<'a> {
        Seen {
            ino: attr.ino,
            identity: &attr.identity,
            foreign: attr.foreign,
            kind: attr.kind,
        }
    }
}

impl KeyNode {
    pub fn of(attr: &Attr) -> KeyNode {
        Seen::from(attr).key()
    }

    /// Whether `attr` describes this file.
    pub fn describes(&self, attr: &Attr) -> bool {
        self.ino == attr.ino && self.identity == attr.identity
    }
}

impl Seen<'_> {
    fn key(&self) -> KeyNode {
        KeyNode {
            ino: self.ino,
            identity: self.identity.clone(),
        }
    }
}

/// Where the substitutes for a file start: a 64-bit FNV-1a of its handle, moved off the two numbers the kernel reserves (0 for "no entry", 1 for the root). Fixed, so that every mount gives a file outside the root's subvolume the same number.
fn substitute(identity: &Identity) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in identity
        .handle_type
        .to_le_bytes()
        .iter()
        .chain(&identity.handle)
    {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash.max(2)
}

/// Guard against an alias chain that never reaches the root; a real tree can't be deeper than `PATH_MAX` single-byte components.
const MAX_DEPTH: usize = jackalopefs_proto::PATH_MAX / 2;

#[derive(Debug)]
pub struct Node {
    /// Every `(parent, name)` this node has been looked up through, oldest first; the newest one is used to address it.
    pub aliases: Vec<(u64, Name)>,
    pub lookup_count: u64,
    /// `None` for the root until a reply has described it.
    pub key: Option<KeyNode>,
    /// The last alias this client knew went away (unlink, rmdir, rename-over, or the name found to lead elsewhere), so there is no path to address the node by. The file may well live on under a name this client never saw.
    pub unlinked: bool,
    pub kind: FileKind,
    pub children: HashMap<Name, u64>,
}

pub struct NodeTable {
    nodes: HashMap<u64, Node>,
    by_key: HashMap<KeyNode, u64>,
}

impl Default for NodeTable {
    fn default() -> Self {
        NodeTable::new()
    }
}

impl NodeTable {
    pub fn new() -> NodeTable {
        let mut nodes = HashMap::new();
        nodes.insert(
            ROOT,
            Node {
                aliases: Vec::new(),
                lookup_count: 1,
                key: None,
                unlinked: false,
                kind: FileKind::Directory,
                children: HashMap::new(),
            },
        );
        NodeTable {
            nodes,
            by_key: HashMap::new(),
        }
    }

    /// The node a file is, or would be if it were registered now; nothing is registered. A file already known keeps its node. A new one goes by its real inode number if it is in the root's subvolume and no other file's node has that number; otherwise by a substitute from its identity, the next free number from there if that one is taken too. Only a file whose inode number is held by another's node depends on what was seen first: it shows its substitute until both are forgotten. (`docs/design.md`, "Node table".)
    pub fn id_for(&self, seen: Seen<'_>) -> u64 {
        if seen.ino == ROOT
            && self.nodes[&ROOT]
                .key
                .as_ref()
                .is_none_or(|k| k.identity == *seen.identity)
        {
            return ROOT;
        }
        if let Some(id) = self.by_key.get(&seen.key()) {
            return *id;
        }
        if !seen.foreign && seen.ino > ROOT && !self.nodes.contains_key(&seen.ino) {
            return seen.ino;
        }
        let mut id = substitute(seen.identity);
        while self.nodes.contains_key(&id) {
            id = id.wrapping_add(1).max(2);
        }
        id
    }

    pub fn get(&self, ino: u64) -> Option<&Node> {
        self.nodes.get(&ino)
    }

    /// Record that the kernel was told `parent/name` is this file (a lookup, create, mkdir, link, or accepted readdirplus entry) and will count one lookup for it. Returns the node, [`Self::id_for`]'s answer, or `None` if that is the root, which can never be a child.
    pub fn insert_lookup(&mut self, parent: u64, name: Name, seen: Seen<'_>) -> Option<u64> {
        let id = self.id_for(seen);
        if id == ROOT {
            return None;
        }
        if let Some(previous) = self
            .nodes
            .get_mut(&parent)
            .and_then(|p| p.children.insert(name.clone(), id))
        {
            if previous != id {
                self.drop_alias(previous, parent, &name);
            }
        }
        let node = self.nodes.entry(id).or_insert_with(|| Node {
            aliases: Vec::new(),
            lookup_count: 0,
            key: Some(seen.key()),
            unlinked: false,
            kind: seen.kind,
            children: HashMap::new(),
        });
        self.by_key.insert(seen.key(), id);
        node.unlinked = false;
        node.kind = seen.kind;
        node.lookup_count += 1;
        let alias = (parent, name);
        node.aliases.retain(|a| *a != alias);
        node.aliases.push(alias);
        Some(id)
    }

    /// The root as a reply described it.
    pub fn root_seen(&mut self, identity: &Identity) {
        let root = self.nodes.get_mut(&ROOT).expect("the root is always there");
        root.key = Some(KeyNode {
            ino: ROOT,
            identity: identity.clone(),
        });
    }

    /// The kernel dropped `n` lookups; at zero the node is forgotten, and the caller is told so.
    pub fn forget(&mut self, ino: u64, n: u64) -> bool {
        if ino == ROOT {
            return false;
        }
        let Some(node) = self.nodes.get_mut(&ino) else {
            return false;
        };
        node.lookup_count = node.lookup_count.saturating_sub(n);
        if node.lookup_count > 0 {
            return false;
        }
        let node = self.nodes.remove(&ino).expect("present");
        if let Some(key) = &node.key {
            self.by_key.remove(key);
        }
        for (parent, name) in node.aliases {
            if let Some(p) = self.nodes.get_mut(&parent) {
                if p.children.get(&name) == Some(&ino) {
                    p.children.remove(&name);
                }
            }
        }
        true
    }

    /// Path to address `ino` on the wire: through its newest alias whose directory can itself be addressed. The kernel forgets a directory nothing holds, and a file with a name in it may still be held through a name elsewhere. `None` once no alias leads to the root (unlinked, or replaced under every name we knew).
    pub fn path_of(&self, ino: u64) -> Option<Path> {
        Path::from_names(self.names_to(ino, 0)?).ok()
    }

    /// The names leading from the root to `ino`, newest aliases first at every step.
    fn names_to(&self, ino: u64, depth: usize) -> Option<Vec<Name>> {
        if ino == ROOT {
            return Some(Vec::new());
        }
        if depth > MAX_DEPTH {
            tracing::error!(ino, "alias chain does not reach the root");
            return None;
        }
        self.nodes
            .get(&ino)?
            .aliases
            .iter()
            .rev()
            .find_map(|(parent, name)| {
                let mut names = self.names_to(*parent, depth + 1)?;
                names.push(name.clone());
                Some(names)
            })
    }

    pub fn child(&self, parent: u64, name: &Name) -> Option<u64> {
        self.nodes.get(&parent)?.children.get(name).copied()
    }

    /// Follow `path` from the root through known children; `None` if any component is unknown.
    pub fn resolve_path(&self, path: &Path) -> Option<u64> {
        let mut current = ROOT;
        for name in path.names() {
            current = self.child(current, name)?;
        }
        Some(current)
    }

    fn drop_alias(&mut self, ino: u64, parent: u64, name: &Name) {
        if let Some(node) = self.nodes.get_mut(&ino) {
            node.aliases.retain(|(p, n)| !(*p == parent && n == name));
            if node.aliases.is_empty() {
                node.unlinked = true;
            }
        }
    }

    /// `path`, which [`Self::path_of`] gave for `id`, led to another file: forget the alias it ended in, so the node is addressed by another name if it has one, and say which alias that was. The file itself may be perfectly well; it is a name that went stale, renamed or replaced by someone else. The alias is found by its path because it need not be the newest: `path_of` passes over names it cannot spell.
    pub fn alias_was_wrong(&mut self, id: u64, path: &Path) -> Option<(u64, Name)> {
        let (dir, last) = path.names().split_last().map(|(last, dir)| (dir, last))?;
        let node = self.nodes.get(&id)?;
        let at = node.aliases.iter().rposition(|(parent, name)| {
            name == last && self.names_to(*parent, 0).is_some_and(|names| names == dir)
        })?;
        let node = self.nodes.get_mut(&id)?;
        let (parent, name) = node.aliases.remove(at);
        if node.aliases.is_empty() {
            node.unlinked = true;
        }
        if let Some(p) = self.nodes.get_mut(&parent) {
            if p.children.get(&name) == Some(&id) {
                p.children.remove(&name);
            }
        }
        Some((parent, name))
    }

    /// `parent/name` was removed through this client.
    pub fn unlink(&mut self, parent: u64, name: &Name) {
        let Some(child) = self
            .nodes
            .get_mut(&parent)
            .and_then(|p| p.children.remove(name))
        else {
            return;
        };
        self.drop_alias(child, parent, name);
    }

    /// `parent/name` became `newparent/newname` through this client; whatever was at the target is gone. Renaming a hardlink onto another link of the same inode is a no-op for the kernel and so for the table.
    pub fn rename(&mut self, parent: u64, name: &Name, newparent: u64, newname: Name) {
        let Some(child) = self.child(parent, name) else {
            return;
        };
        if self.child(newparent, &newname) == Some(child) {
            return;
        }
        if let Some(p) = self.nodes.get_mut(&parent) {
            p.children.remove(name);
        }
        if let Some(replaced) = self
            .nodes
            .get_mut(&newparent)
            .and_then(|p| p.children.insert(newname.clone(), child))
        {
            self.drop_alias(replaced, newparent, &newname);
        }
        if let Some(node) = self.nodes.get_mut(&child) {
            node.aliases.retain(|(p, n)| !(*p == parent && n == name));
            node.aliases.push((newparent, newname));
        }
    }

    /// `RENAME_EXCHANGE`: the two entries swap inodes.
    pub fn exchange(&mut self, parent: u64, name: &Name, newparent: u64, newname: &Name) {
        let a = self.child(parent, name);
        let b = self.child(newparent, newname);
        let (Some(a), Some(b)) = (a, b) else {
            self.unlink(parent, name);
            self.unlink(newparent, newname);
            return;
        };
        if a == b {
            return;
        }
        if let Some(p) = self.nodes.get_mut(&parent) {
            p.children.insert(name.clone(), b);
        }
        if let Some(p) = self.nodes.get_mut(&newparent) {
            p.children.insert(newname.clone(), a);
        }
        if let Some(node) = self.nodes.get_mut(&a) {
            node.aliases.retain(|(p, n)| !(*p == parent && n == name));
            node.aliases.push((newparent, newname.clone()));
        }
        if let Some(node) = self.nodes.get_mut(&b) {
            node.aliases
                .retain(|(p, n)| !(*p == newparent && n == newname));
            node.aliases.push((parent, name.clone()));
        }
    }

    /// Up to `limit` known directory entries, for a bounded whole-cache invalidation.
    pub fn entries(&self, limit: usize) -> Vec<(u64, Name, u64)> {
        let mut out = Vec::new();
        for (parent, node) in &self.nodes {
            for (name, child) in &node.children {
                if out.len() >= limit {
                    return out;
                }
                out.push((*parent, name.clone(), *child));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::new(s.as_bytes()).unwrap()
    }

    /// The file with inode number `ino` in its `generation`th life, as ext4 would put it in a handle.
    fn identity(ino: u64, generation: u32) -> Identity {
        Identity {
            handle_type: 1,
            handle: [(ino as u32).to_le_bytes(), generation.to_le_bytes()].concat(),
        }
    }

    fn seen(ino: u64, identity: &Identity, kind: FileKind) -> Seen<'_> {
        Seen {
            ino,
            identity,
            foreign: false,
            kind,
        }
    }

    /// A lookup of the first file ever to have inode number `ino`.
    fn look(t: &mut NodeTable, parent: u64, name: Name, ino: u64, kind: FileKind) -> Option<u64> {
        t.insert_lookup(parent, name, seen(ino, &identity(ino, 0), kind))
    }

    fn p(s: &str) -> Path {
        if s.is_empty() {
            return Path::root();
        }
        Path::from_names(s.split('/').map(n).collect()).unwrap()
    }

    #[test]
    fn lookup_path_and_forget() {
        let mut t = NodeTable::new();
        assert_eq!(
            look(&mut t, ROOT, n("a"), 10, FileKind::Directory),
            Some(10)
        );
        assert_eq!(look(&mut t, 10, n("b"), 11, FileKind::Regular), Some(11));
        assert_eq!(t.path_of(11), Some(p("a/b")));
        assert_eq!(t.path_of(ROOT), Some(Path::root()));
        assert_eq!(t.resolve_path(&p("a/b")), Some(11));
        assert_eq!(t.resolve_path(&p("a/zz")), None);
        assert_eq!(look(&mut t, 10, n("b"), 11, FileKind::Regular), Some(11));
        assert_eq!(t.get(11).unwrap().lookup_count, 2);
        t.forget(11, 1);
        assert!(t.get(11).is_some());
        t.forget(11, 1);
        assert!(t.get(11).is_none());
        assert_eq!(
            t.child(10, &n("b")),
            None,
            "forgotten nodes leave no dangling child entry"
        );
        assert_eq!(
            look(&mut t, ROOT, n("x"), ROOT, FileKind::Directory),
            None,
            "the root cannot be a child"
        );
        t.forget(ROOT, 1);
        assert!(t.get(ROOT).is_some());
    }

    #[test]
    fn hardlinks_share_a_node() {
        let mut t = NodeTable::new();
        look(&mut t, ROOT, n("x"), 10, FileKind::Regular);
        look(&mut t, ROOT, n("y"), 10, FileKind::Regular);
        assert_eq!(t.entries(100).len(), 2);
        assert_eq!(t.get(10).unwrap().aliases.len(), 2);
        assert_eq!(t.path_of(10), Some(p("y")));
        t.unlink(ROOT, &n("y"));
        assert_eq!(t.path_of(10), Some(p("x")));
        assert!(!t.get(10).unwrap().unlinked);
        t.unlink(ROOT, &n("x"));
        assert_eq!(t.path_of(10), None);
        assert!(t.get(10).unwrap().unlinked);
    }

    #[test]
    fn unlink_then_create_same_name() {
        let mut t = NodeTable::new();
        look(&mut t, ROOT, n("f"), 10, FileKind::Regular);
        t.unlink(ROOT, &n("f"));
        assert_eq!(t.child(ROOT, &n("f")), None);
        assert!(t.get(10).unwrap().unlinked);
        assert_eq!(look(&mut t, ROOT, n("f"), 11, FileKind::Regular), Some(11));
        assert_eq!(t.child(ROOT, &n("f")), Some(11));
    }

    /// One file, two names, only one of them known: unlinking that one leaves the node without a path, and finding the other gives the same node back, which is what keeps a descriptor opened through the first name working.
    #[test]
    fn a_file_found_again_by_another_name_is_the_same_node() {
        let mut t = NodeTable::new();
        look(&mut t, ROOT, n("a"), 10, FileKind::Regular);
        t.unlink(ROOT, &n("a"));
        assert_eq!(t.path_of(10), None);
        assert_eq!(look(&mut t, ROOT, n("b"), 10, FileKind::Regular), Some(10));
        assert!(!t.get(10).unwrap().unlinked, "it has a name again");
        assert_eq!(t.path_of(10), Some(p("b")));
        assert_eq!(t.get(10).unwrap().lookup_count, 2);
    }

    /// An inode number that comes back with another identity is another file. While the kernel still remembers the first, the second goes by a substitute; once both are forgotten the number is free again.
    #[test]
    fn a_recycled_inode_number_is_another_node() {
        let mut t = NodeTable::new();
        let (first, second) = (identity(10, 0), identity(10, 1));
        look(&mut t, ROOT, n("f"), 10, FileKind::Regular);
        t.unlink(ROOT, &n("f"));
        let probed = t.id_for(seen(10, &second, FileKind::Regular));
        let other = t
            .insert_lookup(ROOT, n("g"), seen(10, &second, FileKind::Regular))
            .unwrap();
        assert_eq!(other, probed, "asking first changes nothing");
        assert_ne!(other, 10);
        assert!(other > ROOT);
        assert_eq!(
            t.get(10).unwrap().key.as_ref().unwrap().identity,
            first,
            "the first node is untouched"
        );
        assert!(t.get(10).unwrap().unlinked);
        assert_eq!(t.path_of(other), Some(p("g")));
        assert_eq!(
            t.insert_lookup(ROOT, n("g"), seen(10, &second, FileKind::Regular)),
            Some(other),
            "and it keeps its number while it lives"
        );
        assert!(t.forget(10, 1));
        assert!(t.forget(other, 2));
        assert_eq!(
            t.insert_lookup(ROOT, n("g"), seen(10, &second, FileKind::Regular)),
            Some(10),
            "with both forgotten the file goes by its real number"
        );
    }

    /// A file outside the root's subvolume shares its inode number with whatever has that number inside it, so it never goes by the number, whatever the table holds: its number must not depend on what was looked up first.
    #[test]
    fn a_file_outside_the_roots_subvolume_always_goes_by_a_substitute() {
        let snapshot = identity(10, 7);
        let foreign = Seen {
            foreign: true,
            ..seen(10, &snapshot, FileKind::Regular)
        };
        let mut alone = NodeTable::new();
        let id = alone.insert_lookup(ROOT, n("snap"), foreign).unwrap();
        assert_ne!(id, 10);
        let mut after_origin = NodeTable::new();
        look(&mut after_origin, ROOT, n("origin"), 10, FileKind::Regular);
        assert_eq!(
            after_origin.insert_lookup(ROOT, n("snap"), foreign),
            Some(id)
        );
        assert_eq!(after_origin.path_of(10), Some(p("origin")));
    }

    /// A substitute can sit on a number that is some other file's real inode number; that file then needs a substitute of its own, and nothing is ever shared.
    #[test]
    fn a_number_taken_by_a_substitute_is_taken() {
        let mut t = NodeTable::new();
        let snapshot = identity(10, 7);
        let foreign = Seen {
            foreign: true,
            ..seen(10, &snapshot, FileKind::Regular)
        };
        let squatter = t.insert_lookup(ROOT, n("snap"), foreign).unwrap();
        let genuine = look(&mut t, ROOT, n("real"), squatter, FileKind::Regular).unwrap();
        assert_ne!(genuine, squatter);
        assert_eq!(t.path_of(squatter), Some(p("snap")));
        assert_eq!(t.path_of(genuine), Some(p("real")));
    }

    /// FNV-1a, 64 bits, over the handle type (four bytes, little-endian) and the handle, computed outside this program.
    const GOLDEN_SUBSTITUTE: u64 = 0x750a_976a_808e_6259;

    #[test]
    fn substitutes_avoid_the_numbers_the_kernel_reserves() {
        for ino in 0..2000u64 {
            assert!(substitute(&identity(ino, 3)) >= 2);
        }
        assert_ne!(substitute(&identity(10, 7)), substitute(&identity(10, 8)));
        // Pinned: a change here renumbers every file outside the root's subvolume for whoever recorded its `st_ino`.
        assert_eq!(substitute(&identity(10, 7)), GOLDEN_SUBSTITUTE);
    }

    /// The kernel forgets a directory nothing holds; a file held through a name elsewhere is still to be found by that name.
    #[test]
    fn a_name_in_a_forgotten_directory_is_passed_over() {
        let mut t = NodeTable::new();
        look(&mut t, ROOT, n("d"), 5, FileKind::Directory);
        look(&mut t, ROOT, n("e"), 6, FileKind::Directory);
        look(&mut t, 5, n("a"), 10, FileKind::Regular);
        look(&mut t, 6, n("b"), 10, FileKind::Regular);
        assert_eq!(t.path_of(10), Some(p("e/b")));
        assert!(t.forget(6, 1));
        assert_eq!(t.path_of(10), Some(p("d/a")));
        assert!(t.forget(5, 1));
        assert_eq!(t.path_of(10), None);
    }

    #[test]
    fn a_wrong_name_falls_back_to_the_one_before() {
        let mut t = NodeTable::new();
        look(&mut t, ROOT, n("d"), 5, FileKind::Directory);
        look(&mut t, 5, n("a"), 10, FileKind::Regular);
        look(&mut t, ROOT, n("b"), 10, FileKind::Regular);
        assert_eq!(t.path_of(10), Some(p("b")));
        assert_eq!(t.alias_was_wrong(10, &p("b")), Some((ROOT, n("b"))));
        assert_eq!(t.child(ROOT, &n("b")), None);
        assert_eq!(t.path_of(10), Some(p("d/a")));
        assert!(!t.get(10).unwrap().unlinked);
        assert_eq!(t.alias_was_wrong(10, &p("d/a")), Some((5, n("a"))));
        assert!(t.get(10).unwrap().unlinked, "no name left");
        assert_eq!(t.alias_was_wrong(10, &p("d/a")), None);
        assert_eq!(t.alias_was_wrong(ROOT, &Path::root()), None);
    }

    /// The name that led elsewhere is the one that was used, which is not the newest when the newest could not be spelled.
    #[test]
    fn the_wrong_name_is_the_one_that_was_used() {
        let mut t = NodeTable::new();
        look(&mut t, ROOT, n("d"), 5, FileKind::Directory);
        look(&mut t, ROOT, n("e"), 6, FileKind::Directory);
        look(&mut t, 5, n("a"), 10, FileKind::Regular);
        look(&mut t, 6, n("b"), 10, FileKind::Regular);
        assert!(t.forget(6, 1));
        let used = t.path_of(10).unwrap();
        assert_eq!(used, p("d/a"));
        assert_eq!(t.alias_was_wrong(10, &used), Some((5, n("a"))));
        assert_eq!(
            t.get(10).unwrap().aliases,
            vec![(6, n("b"))],
            "the name not used is kept"
        );
        assert!(!t.get(10).unwrap().unlinked);
        assert_eq!(t.path_of(10), None, "though it cannot be spelled for now");
    }

    /// The root is node 1 whatever inode number it has on the server, and a file that really is numbered 1 is not the root.
    #[test]
    fn the_root_is_node_one_and_inode_one_is_just_a_file() {
        let mut t = NodeTable::new();
        let root = identity(4096, 0);
        t.root_seen(&root);
        assert_eq!(t.id_for(seen(ROOT, &root, FileKind::Directory)), ROOT);
        let one = look(&mut t, ROOT, n("one"), 1, FileKind::Regular).unwrap();
        assert!(one > ROOT);
        assert_eq!(t.path_of(one), Some(p("one")));
        assert_eq!(
            t.insert_lookup(ROOT, n("self"), seen(ROOT, &root, FileKind::Directory)),
            None
        );
    }

    #[test]
    fn rename_moves_alias_and_rename_over_orphans_target() {
        let mut t = NodeTable::new();
        look(&mut t, ROOT, n("a"), 10, FileKind::Regular);
        look(&mut t, ROOT, n("b"), 11, FileKind::Regular);
        look(&mut t, ROOT, n("d"), 20, FileKind::Directory);
        t.rename(ROOT, &n("a"), 20, n("a2"));
        assert_eq!(t.path_of(10), Some(p("d/a2")));
        assert_eq!(t.child(ROOT, &n("a")), None);
        t.rename(20, &n("a2"), ROOT, n("b"));
        assert_eq!(t.path_of(10), Some(p("b")));
        assert_eq!(t.path_of(11), None);
        assert!(t.get(11).unwrap().unlinked);
        assert_eq!(t.child(ROOT, &n("b")), Some(10));
    }

    #[test]
    fn renaming_a_link_onto_its_twin_changes_nothing() {
        let mut t = NodeTable::new();
        look(&mut t, ROOT, n("a"), 10, FileKind::Regular);
        look(&mut t, ROOT, n("b"), 10, FileKind::Regular);
        t.rename(ROOT, &n("a"), ROOT, n("b"));
        assert_eq!(t.child(ROOT, &n("a")), Some(10));
        assert_eq!(t.child(ROOT, &n("b")), Some(10));
        assert_eq!(t.get(10).unwrap().aliases.len(), 2);
        t.exchange(ROOT, &n("a"), ROOT, &n("b"));
        assert_eq!(t.get(10).unwrap().aliases.len(), 2);
        assert!(!t.get(10).unwrap().unlinked);
    }

    #[test]
    fn directory_rename_carries_children() {
        let mut t = NodeTable::new();
        look(&mut t, ROOT, n("d"), 20, FileKind::Directory);
        look(&mut t, 20, n("f"), 30, FileKind::Regular);
        t.rename(ROOT, &n("d"), ROOT, n("e"));
        assert_eq!(t.path_of(30), Some(p("e/f")));
        assert_eq!(t.resolve_path(&p("e/f")), Some(30));
    }

    #[test]
    fn exchange_swaps_entries() {
        let mut t = NodeTable::new();
        look(&mut t, ROOT, n("a"), 10, FileKind::Regular);
        look(&mut t, ROOT, n("b"), 11, FileKind::Regular);
        t.exchange(ROOT, &n("a"), ROOT, &n("b"));
        assert_eq!(t.path_of(10), Some(p("b")));
        assert_eq!(t.path_of(11), Some(p("a")));
        assert_eq!(t.child(ROOT, &n("a")), Some(11));
    }

    #[test]
    fn server_side_rename_discovered_through_lookup() {
        let mut t = NodeTable::new();
        look(&mut t, ROOT, n("a"), 10, FileKind::Regular);
        look(&mut t, ROOT, n("b"), 10, FileKind::Regular);
        assert_eq!(t.path_of(10), Some(p("b")));
        assert_eq!(
            look(&mut t, ROOT, n("a"), 12, FileKind::Regular),
            Some(12),
            "the old name now belongs to another inode"
        );
        assert_eq!(t.get(10).unwrap().aliases, vec![(ROOT, n("b"))]);
        assert!(!t.get(10).unwrap().unlinked);
        look(&mut t, ROOT, n("b"), 13, FileKind::Regular);
        assert!(
            t.get(10).unwrap().unlinked,
            "replaced under every known name"
        );
        assert_eq!(t.path_of(10), None);
    }

    #[test]
    fn bounded_entry_snapshot() {
        let mut t = NodeTable::new();
        for i in 0..50u64 {
            look(
                &mut t,
                ROOT,
                n(&format!("f{i}")),
                100 + i,
                FileKind::Regular,
            );
        }
        assert_eq!(t.entries(10).len(), 10);
        assert_eq!(t.entries(1000).len(), 50);
    }
}
