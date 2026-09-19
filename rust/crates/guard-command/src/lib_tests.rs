use super::*;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: default_dialect(),
        transport: default_transport(),
        extraction_provenance: default_provenance(),
    }
}

#[test]
fn parses_simple_command_without_execution() {
    let parsed = parse_command(&request("git status --short")).unwrap();
    assert_eq!(parsed.confidence, "exact");
    assert_eq!(parsed.segments.len(), 1);
    assert_eq!(parsed.segments[0].executable.as_deref(), Some("git"));
    assert_eq!(parsed.segments[0].arguments, ["status", "--short"]);
    assert_eq!(parsed.segments[0].span.start, 0);
    assert_eq!(parsed.segments[0].span.end, 18);
}

#[test]
fn preserves_quotes_environment_and_path_override() {
    let parsed = parse_command(&request("FOO=bar PATH=/tmp tool --name 'two words'")).unwrap();
    let segment = &parsed.segments[0];
    assert_eq!(segment.environment_names, ["FOO", "PATH"]);
    assert_eq!(segment.executable.as_deref(), Some("tool"));
    assert_eq!(segment.arguments, ["--name", "two words"]);
    assert!(segment.path_overridden);
    assert!(parsed.path_overridden);
}

#[test]
fn matches_python_shlex_escape_and_whitespace_semantics() {
    let parsed = parse_command(&request(
        "printf \"%s\" \"a\\q\" \"a\\$b\" \"a\\\"b\" \"a\\\\b\" x\u{00a0}y",
    ))
    .unwrap();
    assert_eq!(parsed.confidence, "exact");
    assert_eq!(
        parsed.segments[0].tokens,
        [
            "printf",
            "%s",
            "a\\q",
            "a\\$b",
            "a\"b",
            "a\\b",
            "x\u{00a0}y"
        ]
    );
}

#[test]
fn splits_pipeline_but_not_quoted_pipe() {
    let parsed = parse_command(&request("printf 'a|b' | grep b")).unwrap();
    assert_eq!(parsed.segments.len(), 2);
    assert_eq!(parsed.segments[0].tokens, ["printf", "a|b"]);
    assert_eq!(parsed.segments[0].pipeline_index, 0);
    assert_eq!(parsed.segments[1].tokens, ["grep", "b"]);
    assert_eq!(parsed.segments[1].pipeline_index, 1);
}

#[test]
fn marks_complex_shell_forms_uncertain_without_partial_segments() {
    for command in [
        "echo $(uname)",
        "cat <<EOF",
        "echo hello > out.txt",
        "sleep 1 &",
        "sudo rm -rf /tmp/example",
        "sh -c 'rm -rf /tmp/example'",
        "eval 'rm -rf /tmp/example'",
        "if true; then echo yes; fi",
        "[[ -f Cargo.toml ]]",
        "echo $'non-posix quote'",
        "xargs rm -rf",
        "find . -exec rm {} ;",
    ] {
        let parsed = parse_command(&request(command)).unwrap();
        assert_eq!(parsed.confidence, "uncertain", "{command}");
        assert!(parsed.segments.is_empty(), "{command}");
        assert!(parsed.uncertainty_reason.is_some(), "{command}");
    }
}

#[test]
fn rejects_oversized_commands_without_partial_exact_parse() {
    let parsed = parse_command(&request(&"x".repeat(MAX_COMMAND_BYTES + 1))).unwrap();
    assert_eq!(parsed.confidence, "uncertain");
    assert_eq!(
        parsed.uncertainty_reason.as_deref(),
        Some("command_byte_limit_exceeded")
    );
    assert!(parsed.segments.is_empty());
}
