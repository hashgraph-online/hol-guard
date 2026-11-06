use super::*;

fn has(command: &str, spelling: &str) -> bool {
    spellings(command).iter().any(|text| text == spelling)
}

#[test]
fn spacing_and_separators_read_as_the_command() {
    for command in [
        "  npm publish",
        "npm  publish",
        "npm publish ;",
        "npm publish &",
    ] {
        assert!(has(command, "npm publish"), "{command}");
    }
}

#[test]
fn each_step_of_a_line_is_listed() {
    for command in [
        "npm test && npm publish",
        "npm test; npm publish",
        "npm test || npm publish",
        "npm test | npm publish",
        "(npm publish)",
        "{ npm publish; }",
        "if true; then npm publish; fi",
        "npm publish > publish.log",
        "npm publish >publish.log 2>&1",
        "npm publish < /dev/null",
    ] {
        assert!(has(command, "npm publish"), "{command}");
    }
}

#[test]
fn prefixes_and_paths_read_as_the_program() {
    for command in [
        "CI=1 npm publish",
        "env CI=1 npm publish",
        "/usr/local/bin/npm publish",
        "bash -c 'npm publish'",
        "sh -lc \"npm publish\"",
        "bash -c '(npm publish)'",
    ] {
        assert!(has(command, "npm publish"), "{command}");
    }
}

#[test]
fn quoted_words_keep_their_quotes() {
    assert!(has(
        "git  commit -m 'two words'",
        "git commit -m 'two words'"
    ));
    assert!(has(
        "git  commit -m 'two words'",
        "git commit -m \"two words\""
    ));
}

#[test]
fn text_a_step_only_prints_is_not_a_step() {
    for command in [
        "echo npm publish",
        "echo \"x; npm publish\"",
        "echo '(npm publish)'",
        "git commit -m 'npm publish'",
        "cat <<EOF\nnpm publish\nEOF",
    ] {
        assert!(!has(command, "npm publish"), "{command}");
    }
}

#[test]
fn the_command_itself_is_not_listed() {
    assert!(spellings("npm publish").is_empty());
}

#[test]
fn a_long_line_lists_a_bounded_number() {
    let line = vec!["npm test"; 400].join(" && ");
    assert!(spellings(&line).len() <= MAX_SPELLINGS);
    assert!(spellings(&"x".repeat(MAX_COMMAND_BYTES + 1)).is_empty());
}
