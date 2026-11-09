//! The names a change gives for finding the tests that use what it touched.
use super::super::Hunk;
use super::names;

const GROUP: &str = "class Group:
    def __init__(self, commands):
        self.commands = commands

    def split_value(self, rv):
        return (rv or \"\").split()
";

/// Each changed definition is named once, as the prompt's words are spelled;
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
    assert_eq!(names(&changed, &texts), ["group", "splitvalue"]);
}
