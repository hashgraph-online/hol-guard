//! Parity tests for [`super`], pinned by
//! `testdata/inventory_path_parity.json`
//! (`scripts/ci/generate_inventory_path_parity.py`).
//!
//! The pure-path corpus is recorded for both `PurePosixPath` and
//! `PureWindowsPath` from one host, so each platform checks the flavour its
//! `pathlib.Path` would use. The filesystem corpus needs a materialized tree
//! and is recorded by whichever platform ran the generator; the fixture names
//! that platform and [`tree_parity_is_posix_only`] is an ignored, failing test
//! on Windows while no Windows corpus exists, so a Windows run reports the gap
//! by name instead of compiling it out or reporting a pass.

use serde_json::Value;

use super::*;

const PARITY: &str = include_str!("../testdata/inventory_path_parity.json");

fn document() -> Value {
    serde_json::from_str(PARITY).expect("parity fixture parses")
}

fn cases<'a>(document: &'a Value, name: &str) -> &'a [Value] {
    document[name].as_array().expect(name).as_slice()
}

fn text<'a>(case: &'a Value, key: &str) -> &'a str {
    case[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a string"))
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|entry| entry.as_str().expect("string").to_owned())
        .collect()
}

/// The flavour `pathlib.Path` resolves to on this platform.
const PURE_SECTION: &str = if cfg!(windows) {
    "pure_windows"
} else {
    "pure_posix"
};

const RELATIVE_SECTION: &str = if cfg!(windows) {
    "relative_to_windows"
} else {
    "relative_to_posix"
};

#[test]
fn pure_paths_match_cpython() {
    let document = document();
    for case in cases(&document, PURE_SECTION) {
        let raw = text(case, "path");
        let path = PyNativePath::new(raw);
        assert_eq!(path.name(), text(case, "name"), "name of {raw:?}");
        assert_eq!(
            path.is_absolute(),
            case["is_absolute"].as_bool().expect("is_absolute"),
            "is_absolute of {raw:?}",
        );
        assert_eq!(path.parts(), strings(&case["parts"]), "parts of {raw:?}");
    }
}

#[test]
fn relative_to_matches_cpython() {
    let document = document();
    for case in cases(&document, RELATIVE_SECTION) {
        let raw = text(case, "path");
        let base = text(case, "base");
        let relative = PyNativePath::new(raw).relative_to(&PyNativePath::new(base));
        let expected = if case["parts"].is_null() {
            None
        } else {
            Some(strings(&case["parts"]))
        };
        assert_eq!(relative, expected, "{raw:?} relative to {base:?}");
    }
}

/// Windows has no recorded filesystem corpus yet: `Path.resolve()` and the
/// symlink cases below would have to be generated on Windows. Until they are,
/// the native path parsing above is the only Windows coverage.
///
/// Asserting that the fixture says `posix` would pass, which is how a missing
/// corpus reads as a green parity check. Failing under `#[ignore]` keeps the
/// gap named in every Windows run's ignored list without turning an absent
/// corpus into a red build; removing the attribute is what the Windows corpus
/// landing looks like.
#[cfg(windows)]
#[test]
#[ignore = "no Windows tree corpus: regenerate testdata/inventory_path_parity.json on Windows, then enable the tree module there"]
fn tree_parity_is_posix_only() {
    panic!(
        "no Windows filesystem parity corpus: fixture platform is {:?}",
        document()["tree"]["platform"].as_str(),
    );
}

/// `ntpath.splitroot` reads the second *character* for the colon, so a drive
/// letter needs no ASCII first byte. Reading byte 1 instead sees a UTF-8
/// continuation byte here, finds no drive, and calls the path relative —
/// which `redact_known_path` answers by returning the value unchanged, so the
/// whole private path would be exported on Windows.
#[test]
fn a_non_ascii_drive_letter_is_still_a_drive() {
    assert_eq!(
        split_root("\u{e9}:\\Users\\alice\\secret"),
        (
            "\u{e9}:".to_owned(),
            "\\".to_owned(),
            "Users\\alice\\secret".to_owned(),
        ),
    );
}

/// The same drive without the separator after it: a drive and no root, which
/// is what makes `PureWindowsPath('\u{e9}:Users')` relative.
#[test]
fn a_non_ascii_drive_without_a_root_keeps_its_tail() {
    assert_eq!(
        split_root("\u{e9}:Users"),
        ("\u{e9}:".to_owned(), String::new(), "Users".to_owned()),
    );
}

#[cfg(unix)]
mod tree {
    use std::fs;
    use std::os::unix::fs as unix_fs;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::inventory_path_redaction::{
        redact_command_value, redact_known_path, redact_local_path,
    };

    /// The tree the generator built, rebuilt under a private root.
    fn materialize(root: &Path, tree: &Value) {
        for entry in tree["dirs"].as_array().expect("dirs") {
            fs::create_dir_all(root.join(entry.as_str().expect("dir"))).expect("create dir");
        }
        for entry in tree["files"].as_array().expect("files") {
            fs::write(root.join(entry.as_str().expect("file")), "x\n").expect("write file");
        }
        for entry in tree["links"].as_array().expect("links") {
            unix_fs::symlink(text(entry, "target"), root.join(text(entry, "link")))
                .expect("create symlink");
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        root: String,
        home: PathBuf,
        workspace: PathBuf,
        cwd: PathBuf,
        tree: Value,
    }

    impl Fixture {
        fn new() -> Self {
            let document = document();
            let tree = document["tree"].clone();
            assert_eq!(
                tree["platform"].as_str(),
                Some("posix"),
                "regenerate the fixture on this platform",
            );
            let dir = tempfile::tempdir().expect("temp root");
            // macOS hands out `/var/folders/...`, a symlink to `/private/var`;
            // the generator resolved its own root for the same reason.
            let root = fs::canonicalize(dir.path()).expect("canonical root");
            materialize(&root, &tree);
            let root = root.to_string_lossy().into_owned();
            let home = PathBuf::from(
                tree["home_dir"]
                    .as_str()
                    .expect("home")
                    .replace("{root}", &root),
            );
            let workspace = PathBuf::from(
                tree["workspace_dir"]
                    .as_str()
                    .expect("workspace")
                    .replace("{root}", &root),
            );
            let cwd = PathBuf::from(tree["cwd"].as_str().expect("cwd").replace("{root}", &root));
            Self {
                _dir: dir,
                root,
                home,
                workspace,
                cwd,
                tree,
            }
        }

        fn place(&self, template: &str) -> String {
            template.replace("{root}", &self.root)
        }

        /// The generator wrote its own root back out as `{root}`.
        fn unplace(&self, value: &str) -> String {
            value.replace(&self.root, "{root}")
        }

        fn section(&self, name: &str) -> Vec<Value> {
            self.tree[name].as_array().expect(name).clone()
        }
    }

    #[test]
    fn local_paths_match_cpython() {
        let fixture = Fixture::new();
        for case in fixture.section("local_paths") {
            let raw = text(&case, "path");
            let home = case["home_dir"]
                .as_str()
                .map(|home| PathBuf::from(fixture.place(home)));
            let actual = redact_local_path(&fixture.place(raw), home.as_deref(), &fixture.cwd);
            assert_eq!(
                fixture.unplace(&actual),
                text(&case, "expected"),
                "redact_local_path({raw:?}, home={:?})",
                case["home_dir"],
            );
        }
    }

    #[test]
    fn known_paths_match_cpython() {
        let fixture = Fixture::new();
        for case in fixture.section("known_paths") {
            let raw = text(&case, "value");
            let workspace = case["workspace_dir"]
                .as_str()
                .map(|workspace| PathBuf::from(fixture.place(workspace)));
            let actual = redact_known_path(
                &fixture.place(raw),
                &fixture.home,
                workspace.as_deref(),
                &fixture.cwd,
            );
            assert_eq!(
                fixture.unplace(&actual),
                text(&case, "expected"),
                "redact_known_path({raw:?}, workspace={:?})",
                case["workspace_dir"],
            );
        }
    }

    #[test]
    fn command_values_match_cpython() {
        let fixture = Fixture::new();
        for case in fixture.section("commands") {
            let raw = text(&case, "value");
            let actual = redact_command_value(
                &fixture.place(raw),
                &fixture.home,
                Some(fixture.workspace.as_path()),
                &fixture.cwd,
            );
            assert_eq!(
                fixture.unplace(&actual),
                text(&case, "expected"),
                "redact_command_value({raw:?})",
            );
        }
    }

    /// The home boundary holds when the workspace sits inside it, which is the
    /// ordinary shape on a developer machine: `_redact_known_path` prefers
    /// `{home}` and never reaches the workspace branch.
    #[test]
    fn home_prefix_wins_over_a_nested_workspace() {
        let fixture = Fixture::new();
        let nested = fixture.home.join("project");
        let actual = redact_known_path(
            &fixture.place("{root}/home/project/app.py"),
            &fixture.home,
            Some(nested.as_path()),
            &fixture.cwd,
        );
        assert_eq!(actual, "{home}/project/app.py");
    }

    /// A `//`-rooted candidate is the one shape where this port deliberately
    /// diverges: the shared POSIX resolver does not model that root, so the
    /// path takes the bare-name fallback instead of CPython's `{home}/` form.
    /// The fallback is the safe direction, and this pins it there: what must
    /// never happen is the private prefix reaching the output.
    #[test]
    fn double_slash_root_falls_back_to_the_bare_name() {
        let fixture = Fixture::new();
        let doubled = format!("/{}", fixture.place("{root}/home/project/app.py"));
        let actual = redact_local_path(&doubled, Some(fixture.home.as_path()), &fixture.cwd);
        assert_eq!(actual, "app.py");
        assert!(!actual.contains(&fixture.place("{root}")));
    }
}
