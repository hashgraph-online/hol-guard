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

#[cfg(unix)]
#[test]
fn parses_only_literal_stderr_null_sink_without_changing_quoted_arguments() {
    let parsed = parse_command(&request("ls -la src 2>/dev/null; echo done")).unwrap();
    assert_eq!(parsed.confidence, "exact");
    assert_eq!(parsed.segments[0].arguments, ["-la", "src"]);
    assert_eq!(parsed.segments[0].text, "ls -la src 2>/dev/null");
    let quoted = parse_command(&request("echo '2>/dev/null'")).unwrap();
    assert_eq!(quoted.segments[0].arguments, ["2>/dev/null"]);
    for command in [
        "ls 2>/dev/null.env",
        "ls 2>/dev/null/other",
        "ls 12>/dev/null",
        "ls 2>>/dev/null",
        "ls >/dev/null",
        "ls 2> .env",
        "ls src2>/dev/null",
        "cat foo\\ 2>/dev/null",
        "cat foo\\\n2>/dev/null",
        "cat foo\\ 2>&1",
    ] {
        assert_ne!(
            parse_command(&request(command)).unwrap().confidence,
            "exact",
            "{command}"
        );
    }
}

#[test]
fn one_trailing_terminator_ends_the_command() {
    for command in ["ls;", "ls ;  ", "ls\n", "ls src; ls tests;"] {
        let parsed = parse_command(&request(command)).unwrap();
        assert_eq!(parsed.confidence, "exact", "{command:?}");
        assert!(
            parsed
                .segments
                .iter()
                .all(|segment| !segment.text.is_empty()),
            "{command:?}"
        );
    }
    assert_eq!(parse_command(&request("ls;")).unwrap().segments.len(), 1);
    // These are POSIX parser results. A Windows host retries input POSIX
    // cannot prove as PowerShell, where an empty statement (`ls; ;`) is valid.
    crate::powershell_reads::with_posix_powershell_host(|| {
        for command in [";", "ls; ;", "ls;;", "ls &&", "ls ||", "ls |"] {
            assert_ne!(
                parse_command(&request(command)).unwrap().confidence,
                "exact",
                "{command:?}"
            );
        }
    });
}

#[test]
fn redirect_boundary_respects_backslash_profile() {
    let escaped: Vec<char> = "foo\\ 2>&1".chars().collect();
    assert!(!starts_at_shell_token_boundary(&escaped, 5, false));
    assert!(starts_at_shell_token_boundary(&escaped, 5, true));
    let paired: Vec<char> = "foo\\\\ 2>&1".chars().collect();
    assert!(starts_at_shell_token_boundary(&paired, 6, false));
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
fn unquoted_backslash_preservation_keeps_quoted_escapes() {
    let tokens = shell_tokens(r#"printf "%s" "a\q" "a\$b" "a\"b" "a\\b""#, true).unwrap();
    assert_eq!(tokens, ["printf", "%s", "a\\q", "a\\$b", "a\"b", "a\\b"]);
    let path = shell_tokens(r"cmd /c echo C:\Work\file.txt", true).unwrap();
    assert_eq!(path, ["cmd", "/c", "echo", r"C:\Work\file.txt"]);
    let segments = split_execution_segments(r"dir C:\Work\", true).unwrap();
    assert_eq!(segments.len(), 1);
    let trailing = shell_tokens(r"dir C:\Work\", true).unwrap();
    assert_eq!(trailing, ["dir", r"C:\Work\"]);
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
fn parses_frozen_contained_routine_forms_without_general_shell_expansion() {
    let stderr_pipeline = parse_command(&request(
        "cd workspace/service && bun run typecheck 2>&1 | head -40",
    ))
    .unwrap();
    assert_eq!(
        stderr_pipeline.confidence, "exact",
        "{:?}",
        stderr_pipeline.uncertainty_reason
    );
    assert_eq!(stderr_pipeline.segments.len(), 3);
    assert_eq!(
        stderr_pipeline.segments[1].arguments,
        ["run", "typecheck", "2>&1"]
    );
    assert_eq!(stderr_pipeline.segments[2].tokens, ["head", "-40"]);

    let compile_check = parse_command(&request(
        "cd workspace/service && find src -name '*.py' -exec python -m py_compile {} +",
    ))
    .unwrap();
    assert_eq!(compile_check.confidence, "exact");
    assert_eq!(compile_check.segments.len(), 2);
    assert_eq!(
        compile_check.segments[1].arguments,
        [
            "src",
            "-name",
            "*.py",
            "-exec",
            "python",
            "-m",
            "py_compile",
            "{}",
            "+"
        ]
    );
}

#[test]
fn marks_complex_shell_forms_uncertain_without_partial_segments() {
    for command in [
        "echo $(uname)",
        "cat <<EOF",
        "echo hello > out.txt",
        "sleep 1 &",
        "sudo -s rm -rf /tmp/example",
        "eval 'rm -rf /tmp/example'",
        "if true; then echo yes; fi",
        // A closed `[[ ... ]]` pair is not here: the parse surface reads it as
        // the `[` test it asks. An unclosed one is some other shape.
        "[[ -f Cargo.toml",
        // `[[ ]]` evaluates an arithmetic operand and resolves a bare name
        // through the value it holds, so `X='a[$(id)]'` runs `id` where the
        // `[` this would otherwise rewrite to compares two words and stops.
        "[[ $X -eq 0 ]]",
        "[[ 1 -gt $LIMIT ]]",
        "echo $\"locale translation\"",
        "xargs rm -rf",
        "find . -exec rm {} ;",
    ] {
        let parsed = parse_command(&request(command)).unwrap();
        assert_eq!(parsed.confidence, "uncertain", "{command}");
        assert!(parsed.segments.is_empty(), "{command}");
        assert!(parsed.uncertainty_reason.is_some(), "{command}");
    }
}

/// Quote removal leaves `'[[' -f Cargo.toml ']]'` with the same words a bare
/// `[[ ... ]]` carries, but that text runs a command named `[[`, whose
/// operands the shell splits and globs. Only the bare reserved words are read
/// as the `[ ... ]` test they ask; the quoted spelling keeps the review every
/// other shell keyword gets.
#[test]
fn reads_only_bare_double_brackets_as_the_test_they_ask() {
    let bare = parse_command(&request("[[ -f Cargo.toml ]]")).unwrap();
    assert_eq!(bare.confidence, "exact");
    assert_eq!(bare.segments[0].executable.as_deref(), Some("["));
    assert_eq!(bare.segments[0].text, "[ -f Cargo.toml ]");

    for command in [
        "'[[' -f Cargo.toml ']]'",
        "\"[[\" -f Cargo.toml \"]]\"",
        "[['' -f Cargo.toml ]]",
        "[[ -f Cargo.toml '']]",
    ] {
        let quoted = parse_command(&request(command)).unwrap();
        assert_eq!(quoted.confidence, "uncertain", "{command}");
        assert_eq!(
            quoted.uncertainty_reason.as_deref(),
            Some("compound_shell_not_yet_supported"),
            "{command}"
        );
        assert!(quoted.segments.is_empty(), "{command}");
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
