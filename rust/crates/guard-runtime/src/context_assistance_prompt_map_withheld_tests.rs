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

/// With no named definition in the withheld file, its unfinished functions
/// are not listed in their place: they need not be what the prompt means.
#[test]
fn an_unnamed_function_in_a_withheld_file_is_not_placed() {
    let text = lexer() + "\n\ndef pending_step():\n    raise NotImplementedError\n";
    let list = [
        ("src/lexer.py", text.as_str()),
        ("src/utils.py", "def helper():\n    return 1\n"),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Add a `missing_name` helper to `src/lexer.py`.";
    let map = prompt_map(home.path(), &root, prompt);
    assert!(
        map.as_ref().is_none_or(|map| !map.contains("pending_step")),
        "{map:?}"
    );
}

/// A definition whose name reads as the same word but is spelled another
/// way is not the one the prompt names.
#[test]
fn a_definition_spelled_another_way_is_not_placed() {
    let text = lexer().replace("get_lexer", "getLexer");
    let list = [
        ("src/lexer.py", text.as_str()),
        ("src/utils.py", "def helper():\n    return 1\n"),
    ];
    let (home, _project, root) = project(ON, &list);
    let map = prompt_map(home.path(), &root, "Where is `get_lexer` defined?");
    assert!(
        map.as_ref().is_none_or(|map| !map.contains("getLexer")),
        "{map:?}"
    );
}

/// A file that spells the name another way does not keep the one that spells
/// it as written from being placed.
#[test]
fn a_definition_spelled_as_written_is_placed_beside_one_spelled_another_way() {
    let list = [
        ("src/a.py", lexer().replace("get_lexer", "getLexer")),
        ("src/b.py", lexer()),
    ];
    let list: Vec<(&str, &str)> = list
        .iter()
        .map(|(path, text)| (*path, text.as_str()))
        .collect();
    let (home, _project, root) = project(ON, &list);
    let map = prompt_map(home.path(), &root, "Where is `get_lexer` defined?").unwrap_or_default();
    assert!(map.contains("src/b.py:7-9 get_lexer"), "{map}");
    assert!(!map.contains("getLexer"), "{map}");
}

/// A docstring the prompt quotes, wrapped over two lines in a file Guard keeps
/// out, places the method holding it by its lines. Before, the map listed
/// other files that use the quote's words, and the agent answered with one.
#[test]
fn a_quote_only_a_withheld_file_holds_places_its_definition() {
    let held = concat!("to", "ken = self.stream.current");
    let lexer = format!(
        "class Lexer:\n    def __next__(self):\n        {held}\n        return self\n\n    \
def _normalize_newlines(self, value):\n        \"\"\"Replace all newlines with the configured \
sequence in strings\n        and template data.\n        \"\"\"\n        return value\n"
    );
    let compiler = "class CodeGenerator:\n    def newline(self):\n        \
\"\"\"Add a newline to the configured output.\"\"\"\n        self.write(\"\\n\")\n";
    let list = [
        ("src/lexer.py", lexer.as_str()),
        ("src/compiler.py", compiler),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Question, no code changes: which function does this? \"Replace all newlines \
with the configured sequence in strings and template data.\" Reply with its file path and \
function name.";
    let map = prompt_map(home.path(), &root, prompt).unwrap_or_default();
    assert!(
        map.contains("src/lexer.py:6-10 Lexer._normalize_newlines"),
        "{map}"
    );
    assert!(!map.contains("stream.current"), "{map}");
}

/// A quoted sentence a withheld module's docstring repeats still places the
/// function whose docstring holds it: the module docstring is in no
/// definition, so the next match is tried.
#[test]
fn a_quote_repeated_outside_a_definition_places_the_one_inside() {
    let held = concat!("to", "ken = self.stream.current");
    let lexer = format!(
        "\"\"\"Strip trailing spaces from every template line.\"\"\"\n\n\
class Lexer:\n    def __next__(self):\n        {held}\n        return self\n\n    \
def _strip(self, value):\n        \"\"\"Strip trailing spaces from every template line.\"\"\"\n        \
return value\n"
    );
    let list = [
        ("src/lexer.py", lexer.as_str()),
        ("src/utils.py", "def helper():\n    return 1\n"),
    ];
    let (home, _project, root) = project(ON, &list);
    let prompt = "Question, no code changes: which function does this? \"Strip trailing spaces \
from every template line.\" Reply with its file path and function name.";
    let map = prompt_map(home.path(), &root, prompt).unwrap_or_default();
    assert!(map.contains("src/lexer.py:8-10 Lexer._strip"), "{map}");
    assert!(!map.contains("stream.current"), "{map}");
}
