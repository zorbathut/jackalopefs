//! The client's inode table. A nodeid *is* the server's inode number (fuser reports `attr.ino` as the nodeid, and userspace sees it as `st_ino`), so hardlinks share a node and `st_ino` is stable. What the table adds is how to *address* each node on the wire: the `(parent, name)` aliases it has been reached through, the kernel's lookup count, and a generation that changes when the server recycles an inode number for a different file.
//!
//! Lock discipline: the owner wraps the table in a `parking_lot::Mutex`, takes it briefly to compute a path or apply a result, and never holds it across an `.await` or a notifier call.

use jackalopefs_proto::{FileKind, Name, Path};
use std::collections::HashMap;

/// The FUSE root nodeid; the server maps the export root's inode number to it.
pub const ROOT: u64 = 1;

/// Guard against an alias chain that never reaches the root; a real tree can't be deeper than `PATH_MAX` single-byte components.
const MAX_DEPTH: usize = jackalopefs_proto::PATH_MAX / 2;

#[derive(Debug)]
pub struct Node {
    /// Every `(parent, name)` this node has been looked up through, oldest first; the newest one is used to address it.
    pub aliases: Vec<(u64, Name)>,
    pub lookup_count: u64,
    /// Bumped when a lookup returns this inode number for a file we know to be a different one.
    pub generation: u64,
    /// The last alias went away through this client (unlink, rmdir, rename-over), so the server may reuse the inode number.
    pub unlinked: bool,
    pub kind: FileKind,
    pub children: HashMap<Name, u64>,
}

pub struct NodeTable {
    nodes: HashMap<u64, Node>,
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
                generation: 0,
                unlinked: false,
                kind: FileKind::Directory,
                children: HashMap::new(),
            },
        );
        NodeTable { nodes }
    }

    pub fn get(&self, ino: u64) -> Option<&Node> {
        self.nodes.get(&ino)
    }

    /// Record that the kernel was told `parent/name` is `ino` (a lookup, create, mkdir, link, or accepted readdirplus entry) and will count one lookup for it. Returns the generation to reply with, or `None` if `ino` is the root, which can never be a child.
    pub fn insert_lookup(
        &mut self,
        parent: u64,
        name: Name,
        ino: u64,
        kind: FileKind,
    ) -> Option<u64> {
        if ino == ROOT {
            return None;
        }
        if let Some(previous) = self
            .nodes
            .get_mut(&parent)
            .and_then(|p| p.children.insert(name.clone(), ino))
        {
            if previous != ino {
                self.drop_alias(previous, parent, &name);
            }
        }
        let node = self.nodes.entry(ino).or_insert_with(|| Node {
            aliases: Vec::new(),
            lookup_count: 0,
            generation: 0,
            unlinked: false,
            kind,
            children: HashMap::new(),
        });
        if node.unlinked {
            node.generation += 1;
            node.unlinked = false;
            node.aliases.clear();
            node.children.clear();
        }
        node.kind = kind;
        node.lookup_count += 1;
        let alias = (parent, name);
        node.aliases.retain(|a| *a != alias);
        node.aliases.push(alias);
        Some(node.generation)
    }

    /// The generation [`Self::insert_lookup`] would return for `ino` right now, without registering anything; readdirplus needs it before it knows whether the kernel accepted the entry.
    pub fn generation_for_lookup(&self, ino: u64) -> u64 {
        match self.nodes.get(&ino) {
            Some(node) if node.unlinked => node.generation + 1,
            Some(node) => node.generation,
            None => 0,
        }
    }

    /// The kernel dropped `n` lookups; at zero the node is forgotten.
    pub fn forget(&mut self, ino: u64, n: u64) {
        if ino == ROOT {
            return;
        }
        let Some(node) = self.nodes.get_mut(&ino) else {
            return;
        };
        node.lookup_count = node.lookup_count.saturating_sub(n);
        if node.lookup_count > 0 {
            return;
        }
        let node = self.nodes.remove(&ino).expect("present");
        for (parent, name) in node.aliases {
            if let Some(p) = self.nodes.get_mut(&parent) {
                if p.children.get(&name) == Some(&ino) {
                    p.children.remove(&name);
                }
            }
        }
    }

    /// Path to address `ino` on the wire, through its newest alias; `None` once it has no alias (unlinked, or replaced under every name we knew).
    pub fn path_of(&self, ino: u64) -> Option<Path> {
        let mut names = Vec::new();
        let mut current = ino;
        while current != ROOT {
            let (parent, name) = self.nodes.get(&current)?.aliases.last()?;
            names.push(name.clone());
            current = *parent;
            if names.len() > MAX_DEPTH {
                tracing::error!(ino, "alias chain does not reach the root");
                return None;
            }
        }
        names.reverse();
        Path::from_names(names).ok()
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
            t.insert_lookup(ROOT, n("a"), 10, FileKind::Directory),
            Some(0)
        );
        assert_eq!(t.insert_lookup(10, n("b"), 11, FileKind::Regular), Some(0));
        assert_eq!(t.path_of(11), Some(p("a/b")));
        assert_eq!(t.path_of(ROOT), Some(Path::root()));
        assert_eq!(t.resolve_path(&p("a/b")), Some(11));
        assert_eq!(t.resolve_path(&p("a/zz")), None);
        assert_eq!(t.insert_lookup(10, n("b"), 11, FileKind::Regular), Some(0));
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
            t.insert_lookup(ROOT, n("x"), ROOT, FileKind::Directory),
            None,
            "the root cannot be a child"
        );
        t.forget(ROOT, 1);
        assert!(t.get(ROOT).is_some());
    }

    #[test]
    fn hardlinks_share_a_node() {
        let mut t = NodeTable::new();
        t.insert_lookup(ROOT, n("x"), 10, FileKind::Regular);
        t.insert_lookup(ROOT, n("y"), 10, FileKind::Regular);
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
    fn unlink_then_create_same_name_and_inode_reuse() {
        let mut t = NodeTable::new();
        t.insert_lookup(ROOT, n("f"), 10, FileKind::Regular);
        t.unlink(ROOT, &n("f"));
        assert_eq!(t.child(ROOT, &n("f")), None);
        assert_eq!(
            t.insert_lookup(ROOT, n("f"), 11, FileKind::Regular),
            Some(0)
        );
        assert_eq!(t.child(ROOT, &n("f")), Some(11));
        assert_eq!(t.generation_for_lookup(10), 1);
        assert_eq!(
            t.insert_lookup(ROOT, n("g"), 10, FileKind::Regular),
            Some(1),
            "a recycled inode number gets a new generation"
        );
        assert_eq!(t.generation_for_lookup(10), 1);
        assert_eq!(t.generation_for_lookup(999), 0);
        assert_eq!(t.path_of(10), Some(p("g")));
        assert_eq!(
            t.insert_lookup(ROOT, n("g"), 10, FileKind::Regular),
            Some(1),
            "and keeps it while it lives"
        );
    }

    #[test]
    fn rename_moves_alias_and_rename_over_orphans_target() {
        let mut t = NodeTable::new();
        t.insert_lookup(ROOT, n("a"), 10, FileKind::Regular);
        t.insert_lookup(ROOT, n("b"), 11, FileKind::Regular);
        t.insert_lookup(ROOT, n("d"), 20, FileKind::Directory);
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
        t.insert_lookup(ROOT, n("a"), 10, FileKind::Regular);
        t.insert_lookup(ROOT, n("b"), 10, FileKind::Regular);
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
        t.insert_lookup(ROOT, n("d"), 20, FileKind::Directory);
        t.insert_lookup(20, n("f"), 30, FileKind::Regular);
        t.rename(ROOT, &n("d"), ROOT, n("e"));
        assert_eq!(t.path_of(30), Some(p("e/f")));
        assert_eq!(t.resolve_path(&p("e/f")), Some(30));
    }

    #[test]
    fn exchange_swaps_entries() {
        let mut t = NodeTable::new();
        t.insert_lookup(ROOT, n("a"), 10, FileKind::Regular);
        t.insert_lookup(ROOT, n("b"), 11, FileKind::Regular);
        t.exchange(ROOT, &n("a"), ROOT, &n("b"));
        assert_eq!(t.path_of(10), Some(p("b")));
        assert_eq!(t.path_of(11), Some(p("a")));
        assert_eq!(t.child(ROOT, &n("a")), Some(11));
    }

    #[test]
    fn server_side_rename_discovered_through_lookup() {
        let mut t = NodeTable::new();
        t.insert_lookup(ROOT, n("a"), 10, FileKind::Regular);
        t.insert_lookup(ROOT, n("b"), 10, FileKind::Regular);
        assert_eq!(t.path_of(10), Some(p("b")));
        assert_eq!(
            t.insert_lookup(ROOT, n("a"), 12, FileKind::Regular),
            Some(0),
            "the old name now belongs to another inode"
        );
        assert_eq!(t.get(10).unwrap().aliases, vec![(ROOT, n("b"))]);
        assert!(!t.get(10).unwrap().unlinked);
        t.insert_lookup(ROOT, n("b"), 13, FileKind::Regular);
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
            t.insert_lookup(ROOT, n(&format!("f{i}")), 100 + i, FileKind::Regular);
        }
        assert_eq!(t.entries(10).len(), 10);
        assert_eq!(t.entries(1000).len(), 50);
    }
}
