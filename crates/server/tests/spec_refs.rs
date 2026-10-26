//! Every code reference in the session model (`spec/session.qnt` and its instances, and `spec/README.md`) names something the workspace still declares, so a rename or removal in the code fails here rather than leaving the model pointing at nothing. It reads the whole workspace and lives with the server's tests only because a test has to live somewhere.
//!
//! In the model files every backticked name is either the model's own (an identifier its code uses) or code, and code must resolve:
//!
//! - a file path ending in `.rs`, `.md`, `.qnt` or `.sh`: the file exists, and a bare file name is the only file of that name;
//! - `Type::item`: a method of an `impl` or `trait` of that name, or a field or variant of its declaration;
//! - `module::item`: an item that `module.rs` declares;
//! - any other identifier: an item (`fn`, method, `const`, `static`, type, `mod`, `macro_rules!`), field or variant of that name somewhere; parameters and local bindings do not count.
//!
//! Text that is no identifier or path (an expression, a pattern with `*`) is the model's and is skipped. In `spec/README.md`, which also names invariants and test columns in prose, only paths and `owner::item` are checked. The files whose module doc carries [`MARKER`] must be the ones the references resolve into.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};

/// Names from the standard library the model mentions.
const STD_NAMES: &[&str] = &["Arc", "Err"];

/// What marks a file as modelled; `scripts/spec/drift.sh` looks for the same text.
const MARKER: &str = "modelled in `spec/session.qnt`";

/// What one file declares.
#[derive(Default)]
struct Declared {
    /// Items: functions and methods, constants and statics, types, modules, `macro_rules!` macros; and fields and variants.
    names: BTreeSet<String>,
    types: BTreeSet<String>,
    /// (type, member): the methods and constants of its `impl` and `trait` blocks, the fields and variants of its declaration.
    members: BTreeSet<(String, String)>,
}

impl Declared {
    fn parse(text: &str) -> Result<Declared, syn::Error> {
        let file = syn::parse_file(text)?;
        let mut declared = Declared::default();
        declared.visit_file(&file);
        Ok(declared)
    }

    fn member(&mut self, owner: &str, name: String) {
        self.members.insert((owner.to_owned(), name.clone()));
        self.names.insert(name);
    }

    fn fields(&mut self, owner: &str, fields: &syn::Fields) {
        for field in fields {
            if let Some(ident) = &field.ident {
                self.member(owner, ident.to_string());
            }
        }
    }
}

impl<'ast> Visit<'ast> for Declared {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.names.insert(item.sig.ident.to_string());
        visit::visit_item_fn(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if let syn::Type::Path(path) = &*item.self_ty {
            if let Some(owner) = path.path.segments.last().map(|s| s.ident.to_string()) {
                for impl_item in &item.items {
                    match impl_item {
                        syn::ImplItem::Fn(f) => self.member(&owner, f.sig.ident.to_string()),
                        syn::ImplItem::Const(c) => self.member(&owner, c.ident.to_string()),
                        _ => {}
                    }
                }
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_trait(&mut self, item: &'ast syn::ItemTrait) {
        let owner = item.ident.to_string();
        self.types.insert(owner.clone());
        self.names.insert(owner.clone());
        for trait_item in &item.items {
            match trait_item {
                syn::TraitItem::Fn(f) => self.member(&owner, f.sig.ident.to_string()),
                syn::TraitItem::Const(c) => self.member(&owner, c.ident.to_string()),
                _ => {}
            }
        }
        visit::visit_item_trait(self, item);
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        let owner = item.ident.to_string();
        self.types.insert(owner.clone());
        self.names.insert(owner.clone());
        self.fields(&owner, &item.fields);
        visit::visit_item_struct(self, item);
    }

    fn visit_item_enum(&mut self, item: &'ast syn::ItemEnum) {
        let owner = item.ident.to_string();
        self.types.insert(owner.clone());
        self.names.insert(owner.clone());
        for variant in &item.variants {
            self.member(&owner, variant.ident.to_string());
        }
        visit::visit_item_enum(self, item);
    }

    fn visit_item_union(&mut self, item: &'ast syn::ItemUnion) {
        let owner = item.ident.to_string();
        self.types.insert(owner.clone());
        self.names.insert(owner.clone());
        for field in &item.fields.named {
            if let Some(ident) = &field.ident {
                self.member(&owner, ident.to_string());
            }
        }
        visit::visit_item_union(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        self.types.insert(item.ident.to_string());
        self.names.insert(item.ident.to_string());
        visit::visit_item_type(self, item);
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        self.names.insert(item.ident.to_string());
        visit::visit_item_const(self, item);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        self.names.insert(item.ident.to_string());
        visit::visit_item_static(self, item);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        self.names.insert(item.ident.to_string());
        visit::visit_item_mod(self, item);
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if let Some(ident) = &item.ident {
            self.names.insert(ident.to_string());
        }
        visit::visit_item_macro(self, item);
    }
}

/// Every declaration of the workspace's sources, by file.
struct Index {
    files: Vec<(PathBuf, Declared)>,
    /// Every file of the repository a path reference may name.
    paths: BTreeSet<PathBuf>,
}

impl Index {
    fn new(sources: Vec<(PathBuf, String)>, paths: BTreeSet<PathBuf>) -> Index {
        let files = sources
            .into_iter()
            .map(|(path, text)| {
                let declared = Declared::parse(&text)
                    .unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()));
                (path, declared)
            })
            .collect();
        Index { files, paths }
    }

    /// The files `reference` resolves into, or why it resolves into none.
    fn resolve(&self, reference: &str) -> Result<Vec<PathBuf>, String> {
        let found = |f: &dyn Fn(&Declared) -> bool| -> Vec<PathBuf> {
            self.files
                .iter()
                .filter(|(_, d)| f(d))
                .map(|(p, _)| p.clone())
                .collect()
        };
        if is_path(reference) {
            let named: Vec<PathBuf> = if reference.contains('/') {
                self.paths
                    .iter()
                    .filter(|p| *p == Path::new(reference))
                    .cloned()
                    .collect()
            } else {
                self.paths
                    .iter()
                    .filter(|p| p.file_name().is_some_and(|n| n == reference))
                    .cloned()
                    .collect()
            };
            return match named.len() {
                0 => Err("no such file".into()),
                1 => Ok(named),
                n => Err(format!("{n} files of that name; give the path")),
            };
        }
        if let Some((owner, item)) = reference.split_once("::") {
            if owner.starts_with(|c: char| c.is_ascii_lowercase()) {
                let module = format!("{owner}.rs");
                let files: Vec<PathBuf> = self
                    .files
                    .iter()
                    .filter(|(path, d)| {
                        let name = path.file_name().and_then(|n| n.to_str());
                        let is_module = name == Some(module.as_str())
                            || (name == Some("mod.rs")
                                && path
                                    .parent()
                                    .and_then(|p| p.file_name())
                                    .is_some_and(|p| p == owner));
                        is_module && d.names.contains(item)
                    })
                    .map(|(p, _)| p.clone())
                    .collect();
                return if files.is_empty() {
                    Err(format!("no module `{owner}` declaring `{item}`"))
                } else {
                    Ok(files)
                };
            }
            if found(&|d| d.types.contains(owner)).is_empty() {
                return Err(format!("no type `{owner}`"));
            }
            let member = (owner.to_owned(), item.to_owned());
            let files = found(&|d| d.members.contains(&member));
            return if files.is_empty() {
                Err(format!(
                    "`{owner}` has no method, field or variant `{item}`"
                ))
            } else {
                Ok(files)
            };
        }
        let files = found(&|d| d.names.contains(reference));
        if files.is_empty() {
            Err("nothing declares that name".into())
        } else {
            Ok(files)
        }
    }
}

fn is_path(reference: &str) -> bool {
    [".rs", ".md", ".qnt", ".sh"]
        .iter()
        .any(|ext| reference.ends_with(ext))
        && reference
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./".contains(c))
}

fn is_ident(word: &str) -> bool {
    word.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The identifiers the model's own code uses, comments left out: its types, variants, fields, variables, actions and parameters.
fn model_names(spec: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in spec.lines() {
        let code = line.split("//").next().unwrap_or_default();
        for word in code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
            if is_ident(word) {
                names.insert(word.to_owned());
            }
        }
    }
    names
}

/// The references to code in one document, with their line numbers. With the model's names, every backticked identifier or path not among them counts; without, as for prose, only paths and `owner::item`.
fn references(text: &str, model: Option<&BTreeSet<String>>) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        for (k, quoted) in line.split('`').enumerate() {
            if k % 2 == 0 || quoted.is_empty() {
                continue;
            }
            // `Arc<SessionState>` names two things.
            let parts: Vec<&str> = if quoted.contains('<') && !quoted.contains(' ') {
                quoted
                    .split(['<', '>', ','])
                    .filter(|p| !p.is_empty())
                    .collect()
            } else {
                vec![quoted]
            };
            for part in parts {
                let scoped = part
                    .split_once("::")
                    .is_some_and(|(a, b)| is_ident(a) && is_ident(b));
                let counts = is_path(part)
                    || scoped
                    || model.is_some_and(|model| {
                        is_ident(part) && !model.contains(part) && !STD_NAMES.contains(&part)
                    });
                if counts {
                    out.push((n + 1, part.to_owned()));
                }
            }
        }
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .path();
        let skipped = path
            .file_name()
            .is_some_and(|n| n == "target" || n == "node_modules" || n == ".git");
        if path.is_dir() {
            if !skipped {
                walk(&path, out);
            }
        } else {
            out.push(path);
        }
    }
}

#[test]
fn every_code_reference_of_the_model_resolves() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    for dir in ["crates", "spec", "docs", "scripts"] {
        walk(&root.join(dir), &mut files);
    }
    files.extend(["README.md", "CHANGELOG.md"].map(|f| root.join(f)));
    let relative = |p: &Path| p.strip_prefix(&root).unwrap().to_path_buf();
    let paths: BTreeSet<PathBuf> = files.iter().map(|p| relative(p)).collect();
    let sources: Vec<(PathBuf, String)> = files
        .iter()
        .filter(|p| p.starts_with(root.join("crates")) && p.extension().is_some_and(|e| e == "rs"))
        .map(|p| (relative(p), std::fs::read_to_string(p).unwrap()))
        .collect();
    let marked: BTreeSet<PathBuf> = sources
        .iter()
        .filter(|(_, text)| {
            text.lines()
                .any(|l| l.starts_with("//!") && l.contains(MARKER))
        })
        .map(|(p, _)| p.clone())
        .collect();
    let index = Index::new(sources, paths);

    let mut models = Vec::new();
    for path in &files {
        if path.starts_with(root.join("spec")) && path.extension().is_some_and(|e| e == "qnt") {
            models.push(relative(path));
        }
    }
    let model: BTreeSet<String> = models
        .iter()
        .flat_map(|m| model_names(&std::fs::read_to_string(root.join(m)).unwrap()))
        .collect();
    let mut documents: Vec<(PathBuf, Option<&BTreeSet<String>>)> =
        models.into_iter().map(|m| (m, Some(&model))).collect();
    documents.push((PathBuf::from("spec/README.md"), None));

    let mut dangling = Vec::new();
    // Each source file a reference resolves into, and whether some reference resolves into it alone.
    let mut resolved: BTreeMap<PathBuf, bool> = BTreeMap::new();
    let mut checked = 0;
    for (document, model) in documents {
        let text = std::fs::read_to_string(root.join(&document)).unwrap();
        for (line, reference) in references(&text, model) {
            checked += 1;
            match index.resolve(&reference) {
                Ok(into) => {
                    let alone = into.len() == 1;
                    for file in into.into_iter().filter(|f| {
                        f.extension().is_some_and(|e| e == "rs")
                            && f.components().any(|c| c.as_os_str() == "src")
                    }) {
                        *resolved.entry(file).or_default() |= alone;
                    }
                }
                Err(why) => dangling.push(format!(
                    "{}:{line}: `{reference}`: {why}",
                    document.display()
                )),
            }
        }
    }
    assert!(
        checked > 50,
        "only {checked} references found; is the extraction broken?"
    );
    assert!(
        dangling.is_empty(),
        "references to code that is not there:\n{}",
        dangling.join("\n")
    );

    let unmarked: Vec<_> = resolved
        .iter()
        .filter(|(file, alone)| **alone && !marked.contains(*file))
        .map(|(f, _)| f.display().to_string())
        .collect();
    assert!(unmarked.is_empty(), "the model refers to these files, whose module doc does not say they are {MARKER}: {unmarked:?}");
    let unreferenced: Vec<_> = marked
        .iter()
        .filter(|f| !resolved.contains_key(*f))
        .map(|f| f.display().to_string())
        .collect();
    assert!(unreferenced.is_empty(), "these files say they are {MARKER}, but the model refers to nothing in them: {unreferenced:?}");
}

mod resolver {
    use super::*;

    fn index(sources: &[(&str, &str)]) -> Index {
        Index::new(
            sources
                .iter()
                .map(|(p, t)| (PathBuf::from(p), (*t).to_owned()))
                .collect(),
            sources.iter().map(|(p, _)| PathBuf::from(p)).collect(),
        )
    }

    #[test]
    fn a_method_resolves_on_its_own_type_only() {
        let index = index(&[(
            "a.rs",
            "struct A; struct B; impl A { fn begin(&self) { fn nested() {} } } impl B {}",
        )]);
        assert!(index.resolve("A::begin").is_ok());
        assert!(index.resolve("B::begin").is_err());
        assert!(index.resolve("A::finish").is_err(), "renamed or removed");
        assert!(index.resolve("C::begin").is_err());
        assert!(
            index.resolve("A::nested").is_err(),
            "a function inside a method is no method"
        );
    }

    #[test]
    fn a_trait_method_resolves_on_the_type_it_is_implemented_for() {
        let index = index(&[("a.rs", "struct Guard<'a>(&'a u8); struct Other; impl<'a> Drop for Guard<'a> where 'a: 'a { fn drop(&mut self) {} } trait Visit { fn visit(&self); }")]);
        assert!(index.resolve("Guard::drop").is_ok());
        assert!(index.resolve("Visit::visit").is_ok());
        let without = index_of("struct Guard; struct Other; impl Guard { fn new() -> Guard { Guard } } impl Drop for Other { fn drop(&mut self) {} }");
        assert!(
            without.resolve("Guard::drop").is_err(),
            "another type's drop does not count"
        );
    }

    fn index_of(source: &str) -> Index {
        index(&[("a.rs", source)])
    }

    #[test]
    fn fields_and_variants_resolve_on_their_declaration() {
        let index = index_of("pub struct Attached<F: Fn() -> u8> where F: Copy { pub generation: u64, cancels: F } enum Reserved<'a> { Slot(&'a u8), #[allow(dead_code)] Held { handle: u8 }, }");
        assert!(index.resolve("Attached::cancels").is_ok());
        assert!(index.resolve("Reserved::Held").is_ok());
        assert!(index.resolve("Reserved::Slot").is_ok());
        assert!(
            index.resolve("Reserved::Kept").is_err(),
            "a removed variant"
        );
        assert!(index.resolve("Attached::epoch").is_err());
    }

    #[test]
    fn literals_and_comments_hide_nothing_and_add_nothing() {
        let source = r##"
            struct A;
            impl A {
                fn x(&self) { let v = ['\'', '{']; let s = "}"; let r = r#"}"#; let l: &'static str = "fn ghost() {}"; }
                // fn commented() {}
                fn y<'a>(&'a self) {}
            }
        "##;
        let index = index_of(source);
        assert!(index.resolve("A::y").is_ok());
        assert!(index.resolve("A::ghost").is_err());
        assert!(index.resolve("A::commented").is_err());
    }

    #[test]
    fn a_module_item_resolves_in_its_file() {
        let index = index(&[
            ("src/client.rs", "pub(crate) async fn exchange() {}"),
            (
                "src/conn.rs",
                "fn run() { let s = Config { exchange: 1 }; }",
            ),
        ]);
        assert!(index.resolve("client::exchange").is_ok());
        assert!(
            index.resolve("conn::exchange").is_err(),
            "a field named in a literal declares nothing"
        );
    }

    #[test]
    fn a_bare_file_name_must_be_the_only_one() {
        let index = index(&[
            ("a/src/handles.rs", ""),
            ("b/src/handles.rs", ""),
            ("b/src/conn.rs", ""),
        ]);
        assert!(index.resolve("conn.rs").is_ok());
        assert!(index.resolve("b/src/handles.rs").is_ok());
        assert!(index.resolve("handles.rs").is_err());
        assert!(index.resolve("server.rs").is_err());
    }

    #[test]
    fn bare_names_resolve_to_items_fields_and_variants_only() {
        let index = index_of("struct Config { op_timeout: u64 } fn retry_safe() {} enum E { NotSent } fn f(give_up: u8) { let mut min_generation = 1; }");
        for name in ["op_timeout", "retry_safe", "NotSent", "Config", "f"] {
            assert!(index.resolve(name).is_ok(), "{name}");
        }
        for name in ["give_up", "min_generation", "ConnManager"] {
            assert!(index.resolve(name).is_err(), "{name}");
        }
    }

    #[test]
    fn the_model_checks_every_name_that_is_not_its_own() {
        let spec = "  type Phase = Absent | Held\n  action begin(r: int): bool = true\n  /// `Held` in `SessionState::drain`, `begin`, `r`, `retry_safe`, `Arc<SessionState>`, `DetachOnDrop`, `x.rs`, `cancels`, `R + 1`, `seen*`.\n";
        let model = model_names(spec);
        let found: Vec<String> = references(spec, Some(&model))
            .into_iter()
            .map(|(_, r)| r)
            .collect();
        assert_eq!(
            found,
            [
                "SessionState::drain",
                "retry_safe",
                "SessionState",
                "DetachOnDrop",
                "x.rs",
                "cancels"
            ]
        );
        let prose: Vec<String> = references(spec, None).into_iter().map(|(_, r)| r).collect();
        assert_eq!(prose, ["SessionState::drain", "x.rs"]);
    }
}
