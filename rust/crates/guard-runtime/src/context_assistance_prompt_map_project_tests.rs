//! The map from a typed prompt, through the walk and Guard's own read of a
//! project on disk.
use super::tests::CORE;
use super::*;
use crate::context_assistance_prompt_files::{plain, walk};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const ON: &str = "[context_assistance]\nenabled=true\nruntime_id='selected'\n\
[context_assistance.features]\nagent_context=true\n\
[context_assistance.sources]\nworkspace_documents=true\nsource_set_id='selected-workspaces'\n";

/// A Guard home with `config`, and a project holding `list`.
fn project(config: &str, list: &[(&str, &str)]) -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), config).unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = plain(std::fs::canonicalize(project.path()).unwrap());
    for (path, text) in list {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
    (home, project, root)
}

fn prompt_map(home: &Path, root: &Path, prompt: &str) -> Option<String> {
    changes_map(home, root, prompt, false)
}

/// The map as the hook builds it, for a prompt about this session's changes
/// when `about_changes`.
fn changes_map(home: &Path, root: &Path, prompt: &str, about_changes: bool) -> Option<String> {
    let terms = crate::context_assistance_prompt_words::marked_terms(prompt);
    let words: Vec<String> = terms.iter().map(|(term, _)| term.clone()).collect();
    let quoted = crate::context_assistance_prompt_files::phrases(prompt);
    let found = walk(
        root,
        &words,
        &quoted,
        &named(prompt),
        Duration::from_secs(5),
    );
    let until = Instant::now() + Duration::from_secs(5);
    let map = mapped(
        home,
        root,
        "codex",
        &found,
        &terms,
        &quoted,
        prompt,
        about_changes,
        until,
    );
    map.map(|rendered| rendered.text)
}

/// From a typed prompt to the map, through the walk and Guard's own read: a
/// file holding a private key is never read or named, and a workspace that
/// has not allowed project context gets nothing.
#[test]
fn a_prompt_maps_to_allowed_project_code_only() {
    let armour = |edge: &str| format!("-----{edge} RSA {}-----", "PRIVATE KEY");
    let key = format!(
        "def case_sensitive_key():\n    return '''{}\nMIIEowIBAAKCAQEA1c7b0q2xQ0keykeykeykeykey\n{}'''\n",
        armour("BEGIN"),
        armour("END")
    );
    let list = [
        ("src/core.py", CORE),
        ("src/signing.py", key.as_str()),
        (
            "tests/test_core.py",
            "def test_choice():\n    Choice(['a'], case_sensitive=False)\n",
        ),
    ];
    let prompt = "Make `Choice` honour `case_sensitive` when converting values";
    let (home, _project, root) = project(ON, &list);
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(text.contains("\nsrc/core.py:"), "{text}");
    assert!(!text.contains("```"), "{text}");
    assert!(
        text.contains("tests/test_core.py: 1 related tests, last test_choice 1-2"),
        "{text}"
    );
    assert!(!text.contains("signing.py"), "{text}");
    let (home, _project, root) = project("", &list);
    assert_eq!(prompt_map(home.path(), &root, prompt), None);
}

/// A changelog at the project root is read through Guard's own check and
/// named on the map with its newest section; it was left out before, since
/// `.rst` counted as source only inside a docs folder. A review of the
/// session's changes keeps it and drops the uses of its plain words.
#[test]
fn a_root_changelog_reaches_the_map() {
    let changes = "Changes\n=======\n\nUnreleased\n----------\n\n- Fix thing.\n";
    let list = [
        ("src/core.py", CORE),
        ("CHANGES.rst", changes),
        ("docs/changes.rst", ".. include:: ../CHANGES.rst\n"),
    ];
    let prompt = "Make `Choice` honour `case_sensitive` and describe it in CHANGES.rst";
    let (home, _project, root) = project(ON, &list);
    let text = prompt_map(home.path(), &root, prompt).unwrap();
    assert!(
        text.contains("\nCHANGES.rst:4-7 newest section: Unreleased"),
        "{text}"
    );
    let review = "Review every change against the original code and make sure \
CHANGES.rst describes everything.";
    let text = changes_map(home.path(), &root, review, true).unwrap();
    assert!(text.contains("\nCHANGES.rst:4-7"), "{text}");
    assert!(!text.contains("'original'"), "{text}");
}

/// Prompts from varied tasks reach the definition they mean: a method named as
/// code is a named definition, and a rename lists every call to it, single
/// lines included; a file the prompt names wins over another defining the same
/// name, even when it is named like a test file; and the file's folders are not
/// searched for as words.
#[test]
fn everyday_prompts_reach_the_definition_they_mean() {
    let compiler =
        "class CodeGenerator:\n    def _import_common(self, node):\n        return node\n\n    \
def visit_Import(self, node):\n        self._import_common(node)\n        return node\n\n    \
def visit_FromImport(self, node):\n        self._import_common(node)\n        return node\n";
    let list = [
        ("src/pkg/compiler.py", compiler),
        (
            "src/pkg/termui.py",
            "def getchar(echo=False):\n    return _getchar(echo)\n",
        ),
        (
            "src/pkg/_termui_impl.py",
            "def getchar(echo):\n    return echo\n",
        ),
        (
            "src/pkg/tests.py",
            "def test_undefined(value):\n    return value is None\n",
        ),
    ];
    let (home, _project, root) = project(ON, &list);
    let map = |prompt: &str| prompt_map(home.path(), &root, prompt).unwrap();
    let text =
        map("Rename the private helper `_import_common` to `_import_common_impl` everywhere.");
    assert!(
        text.contains("\nsrc/pkg/compiler.py:2-3 def _import_common(self, node):"),
        "{text}"
    );
    assert!(
        text.contains("CodeGenerator.visit_Import (lines 6)"),
        "{text}"
    );
    assert!(
        text.contains("CodeGenerator.visit_FromImport (lines 10)"),
        "{text}"
    );
    let text = map("Tests fail: `getchar` in src/pkg/termui.py raises NotImplementedError.");
    assert!(
        text.contains("\nsrc/pkg/termui.py:1-2 def getchar"),
        "{text}"
    );
    assert!(!text.contains("_termui_impl.py:1-2"), "{text}");
    let text = map("Add a usage example to the docstring of `test_undefined` in src/pkg/tests.py.");
    assert!(
        text.contains("\nsrc/pkg/tests.py:1-2 def test_undefined(value):"),
        "{text}"
    );
    assert!(!text.contains("'src'") && !text.contains("'pkg'"), "{text}");
}
