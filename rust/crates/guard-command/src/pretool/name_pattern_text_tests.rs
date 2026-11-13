use crate::pretool::search_pattern_text::command_sensitive;

fn sensitive(command: &str) -> bool {
    let model = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .expect("the command parses");
    command_sensitive(&model, command, None)
}

/// A `find` name test and a `pytest -k` expression only choose among names
/// the command already walks or collects. A credential word there selects
/// tests or prints file names; it opens nothing.
#[test]
fn a_name_pattern_is_not_a_sensitive_target() {
    for command in [
        "pytest -k password -v",
        "pytest tests/test_options.py -k password -v",
        "python -m pytest tests/ -k password -v",
        "python3 -m pytest -k \"password and not slow\"",
        "find examples -name \"*password*\" -o -name \"*prompt*\" | head -10",
        "find . -iname '*secret*'",
        "find src -path '*credentials*' -type f | wc -l",
        "find . -name '*token*' | grep -v node_modules | head -n 20",
    ] {
        assert!(!sensitive(command), "{command} still reads as sensitive");
    }
}

/// The pattern is set aside only while nothing can open what it selects.
/// Names handed to a program that reads them, a `find` action, shell text
/// inside the pattern, and a credential path outside it all keep the screen.
#[test]
fn a_pattern_that_can_reach_a_file_keeps_its_screen() {
    for command in [
        "find . -name \"*password*\" | xargs cat",
        "find . -name \"*password*\" -exec cat {} \\;",
        "find . -name '*secret*' -fprint out.txt",
        "find . -name '*secret*' | head -5 | xargs cat",
        "find . -name '*secret*' | tail -f",
        "pytest -k password .env",
        "pytest -k password -- -k secret",
        "cat .env | head",
    ] {
        assert!(sensitive(command), "{command} lost a signal to the mask");
    }
}
