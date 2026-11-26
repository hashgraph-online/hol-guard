//! Docs are read after code, and still read when time allows.
use super::*;

#[test]
fn docs_are_prose_and_code_is_not() {
    for name in [
        "README.md",
        "CHANGELOG.MD",
        "notes.rst",
        "guide.txt",
        "x.adoc",
    ] {
        assert!(prose_file(name), "{name}");
    }
    for name in ["parser.py", "pyproject.toml", "app.tsx", "Makefile"] {
        assert!(!prose_file(name), "{name}");
    }
}

#[test]
fn docs_read_last_are_still_found() {
    let dir = tempfile::tempdir().unwrap();
    let root = plain(fs::canonicalize(dir.path()).unwrap());
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::create_dir_all(root.join("src/pkg")).unwrap();
    fs::write(
        root.join("src/pkg/_parser.py"),
        "class NestedDict:\n    def get_or_create_nest(self):\n        pass\n",
    )
    .unwrap();
    fs::write(root.join("CHANGELOG.md"), "Fixed NestedDict.\n").unwrap();
    let terms: Vec<String> = ["nesteddict", "getorcreatenest"]
        .map(str::to_owned)
        .to_vec();
    let found = candidates(&root, &terms, &[], &[], WALK_BUDGET);
    for file in ["src/pkg/_parser.py", "CHANGELOG.md"] {
        assert!(found.contains(&file.to_owned()), "{file} in {found:?}");
    }
}
