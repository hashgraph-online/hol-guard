use super::super::project_tests::{project, prompt_map, ON};

/// A module Guard's secret check keeps out whole, for a line that reads like
/// a credential assigned in code, with the definition a prompt asks about
/// further down.
fn lexer() -> String {
    let held = concat!("to", "ken = self.stream.current");
    format!(
        "class TokenStreamIterator:\n    def __next__(self):\n        {held}\n        \
return self\n\n\ndef get_lexer(environment):\n    \"\"\"Return a lexer.\"\"\"\n    \
return Lexer(environment)\n"
    )
}

/// The map gives the lines of a named definition in a file Guard keeps out
/// for what it holds, and none of the file's text, so the agent opens those
/// lines instead of searching the project for it. Before, the map had
/// nothing for it.
#[test]
fn a_named_definition_in_a_withheld_file_is_placed_by_its_lines() {
    let text = lexer();
    let list = [
        ("src/lexer.py", text.as_str()),
        ("src/utils.py", "def helper():\n    return 1\n"),
    ];
    let (home, _project, root) = project(ON, &list);
    let map = prompt_map(home.path(), &root, "Where is `get_lexer` defined?").unwrap();
    assert!(map.contains("src/lexer.py:7-9 get_lexer"), "{map}");
    assert!(map.contains("keeps out of this context"), "{map}");
    assert!(!map.contains("stream.current"), "{map}");
    assert!(!map.contains("Return a lexer"), "{map}");
    let (home, _project, root) = project("", &list);
    let off = prompt_map(home.path(), &root, "Where is `get_lexer` defined?");
    assert_eq!(off, None);
}

/// A file the checks refuse by its path, such as `.env` or one under
/// `secrets/`, is never read, even to place a definition.
#[test]
fn a_file_refused_by_its_path_is_not_placed() {
    let text = lexer();
    let list = [
        ("secrets/lexer.py", text.as_str()),
        ("src/utils.py", "def helper():\n    return 1\n"),
    ];
    let (home, _project, root) = project(ON, &list);
    let map = prompt_map(home.path(), &root, "Where is `get_lexer` defined?");
    assert!(
        map.as_ref().is_none_or(|map| !map.contains("lexer.py")),
        "{map:?}"
    );
}
