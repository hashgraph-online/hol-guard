//! The names a change gives for finding the tests that use what it touched.
use super::super::Hunk;
use super::{add_tests, names, Changed};
use std::fs;
use std::time::Duration;

const GROUP: &str = "class Group:
    def __init__(self, commands):
        self.commands = commands

    def split_value(self, rv):
        return (rv or \"\").split()
";

/// Each changed definition is named once, as it is written;
/// `__init__`, which every class has, by its class; a changed test or doc
/// names nothing.
#[test]
fn a_change_is_named_by_its_definition_or_its_class() {
    let hunk = |path: &str, start, body: &str| Hunk {
        path: path.into(),
        start,
        body: body.into(),
    };
    let changed = vec![
        hunk("src/group.py", 3, "+        self.commands = commands\n"),
        hunk("src/group.py", 6, "+        return (rv or \"\").split()\n"),
        hunk("src/group.py", 6, "+        return (rv or \"\").split()\n"),
        hunk("tests/test_group.py", 2, "+    assert True\n"),
        hunk("README.md", 1, "+# Title\n"),
    ];
    let texts = vec![
        ("README.md".to_owned(), "# Title\n\nbody\n".to_owned()),
        ("src/group.py".to_owned(), GROUP.to_owned()),
        (
            "tests/test_group.py".to_owned(),
            "def test_split():\n    assert True\n".to_owned(),
        ),
    ];
    assert_eq!(names(&changed, &texts), ["group", "split_value"]);
}

/// One change running across two definitions names both, not only the one
/// it starts in.
#[test]
fn a_change_across_two_definitions_names_both() {
    let text = "def first(a):\n    return a + 10\n\n\ndef second(b):\n    return b + 20\n";
    let changed = vec![Hunk {
        path: "src/pair.py".into(),
        start: 2,
        body: "-    return a + 1\n-\n-\n-def second(b):\n-    return b + 2\n\
+    return a + 10\n+\n+\n+def second(b):\n+    return b + 20\n"
            .into(),
    }];
    let texts = vec![("src/pair.py".to_owned(), text.to_owned())];
    assert_eq!(names(&changed, &texts), ["first", "second"]);
}

/// A test that calls a changed definition by a name with an underscore,
/// `split_value`, is found and shown, though the prompt's words spell it
/// `splitvalue`.
#[test]
fn a_test_calling_a_name_with_an_underscore_is_shown() {
    let guard_home = tempfile::tempdir().unwrap();
    fs::write(
        guard_home.path().join("config.toml"),
        "[context_assistance]\nenabled=true\nruntime_id='selected'\n\
[context_assistance.features]\nagent_context=true\n\
[context_assistance.sources]\nworkspace_documents=true\nsource_set_id='selected-workspaces'\n",
    )
    .unwrap();
    let repo = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(repo.path()).unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("tests")).unwrap();
    fs::write(root.join("src/group.py"), GROUP).unwrap();
    let test = "from src.group import Group\n\n\ndef test_words():\n    \
assert Group([]).split_value(\"a b\") == [\"a\", \"b\"]\n";
    fs::write(root.join("tests/test_group.py"), test).unwrap();
    let changed = vec![Hunk {
        path: "src/group.py".into(),
        start: 6,
        body: "+        return (rv or \"\").split()\n".into(),
    }];
    let texts = vec![("src/group.py".to_owned(), GROUP.to_owned())];
    let changed = Changed {
        text: String::new(),
        names: names(&changed, &texts),
    };
    let mut response = serde_json::json!({ "hookSpecificOutput": {} });
    let at = (guard_home.path(), root.as_path(), "codex", None);
    add_tests(
        &mut response,
        at,
        Some(changed),
        &[],
        Duration::from_secs(5),
        || true,
    );
    let text = response["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains("tests/test_group.py: 1 related tests")
            && text.contains("def test_words():\n    assert Group([]).split_value("),
        "{text}"
    );
}
