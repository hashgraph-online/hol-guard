use serde_json::{json, Map, Value};

use super::*;

fn payload(value: Value) -> Map<String, Value> {
    value.as_object().expect("object payload").clone()
}

fn preview(value: Value) -> Option<String> {
    build_invocation_preview_from_payload(&payload(value), None)
}

#[test]
fn an_explicit_command_key_is_the_checked_text() {
    assert_eq!(
        preview(json!({"command": "  ls -la  "})).as_deref(),
        Some("ls -la")
    );
}

#[test]
fn a_tool_input_command_outranks_a_loose_payload_key() {
    let rendered = preview(json!({
        "tool_name": "Bash",
        "tool_input": {"command": "echo checked"},
        "command": "echo loose",
    }));
    assert_eq!(rendered.as_deref(), Some("echo checked"));
}

#[test]
fn an_empty_tool_input_falls_through_to_the_named_call() {
    let rendered = preview(json!({
        "tool_name": "Bash",
        "tool_input": {},
        "toolCalls": [
            {"name": "Read", "args": {"command": "echo other"}},
            {"name": "Bash", "args": {"command": "echo named"}},
        ],
    }));
    assert_eq!(rendered.as_deref(), Some("echo named"));
}

#[test]
fn an_unnamed_call_list_uses_its_first_usable_entry() {
    let rendered = preview(json!({
        "toolCalls": [
            "not a call",
            {"name": "   "},
            {"name": "Bash", "args": {"command": "echo first"}},
            {"name": "Read", "args": {"command": "echo second"}},
        ],
    }));
    assert_eq!(rendered.as_deref(), Some("echo first"));
}

#[test]
fn a_heredoc_body_never_survives() {
    let rendered = preview(json!({"command": "cat <<'EOF'\nprivate body\nEOF"}));
    assert_eq!(rendered.as_deref(), Some("cat <<'EOF'\n…\nEOF"));
}

#[test]
fn a_comment_tail_is_dropped_while_a_quoted_hash_stays() {
    let rendered = preview(json!({"command": "echo hi # drop this\necho 'a # b'"}));
    assert_eq!(rendered.as_deref(), Some("echo hi\necho 'a # b'"));
}

#[test]
fn a_secret_assignment_a_url_and_an_address_are_redacted() {
    let rendered = preview(json!({
        "command": "export API_TOKEN=abc123 && curl https://example.com -d person@example.com",
    }));
    assert_eq!(
        rendered.as_deref(),
        Some("export [redacted] && curl [redacted] -d [redacted]")
    );
}

#[test]
fn an_absolute_path_is_redacted_and_a_bare_name_is_kept() {
    let rendered = preview(json!({"command": "cat /etc/hosts && cat notes.txt"}));
    assert_eq!(rendered.as_deref(), Some("cat [redacted] && cat notes.txt"));
}

#[test]
fn a_windows_path_is_redacted() {
    let rendered = preview(json!({"command": "type C:\\Users\\example\\notes.txt"}));
    assert_eq!(rendered.as_deref(), Some("type [redacted]"));
}

#[test]
fn a_home_directory_prefix_never_reaches_the_preview() {
    let rendered =
        build_invocation_preview(Some("ls /Users/example/notes"), Some("/Users/example/"));
    assert_eq!(rendered.as_deref(), Some("ls [redacted]"));
}

#[test]
fn a_payload_without_a_command_carries_no_preview() {
    assert_eq!(
        preview(json!({"tool_name": "Read", "tool_input": {"path": "notes.txt"}})),
        None
    );
    assert_eq!(preview(json!({"command": "   "})), None);
    assert_eq!(build_invocation_preview(None, None), None);
}

#[test]
fn a_preview_longer_than_its_bound_is_truncated() {
    let rendered = build_invocation_preview(Some(&"a".repeat(5_000)), None).expect("preview");
    assert_eq!(rendered.chars().count(), INVOCATION_PREVIEW_MAX_CHARS);
    assert!(rendered.ends_with('…'));
    assert_eq!(
        rendered
            .chars()
            .filter(|character| *character == 'a')
            .count(),
        INVOCATION_PREVIEW_MAX_CHARS - 1
    );
}

#[test]
fn an_mcp_tool_call_is_data_rather_than_shell_source() {
    let rendered = preview(json!({
        "tool_name": "mcp__linear__search",
        "tool_input": {"query": "rm -rf /tmp/example"},
    }));
    assert_eq!(rendered, None);
}

#[test]
fn a_scrub_pass_that_cannot_finish_yields_no_preview() {
    // `rewrite` is the only place a scrub can fail: `fancy_regex` gives up on a
    // pattern that backtracks past its bound, where Python's `re.sub` would
    // have substituted. Returning the input there would store the raw command.
    //
    // The pattern needs a backreference. `fancy_regex` hands any subexpression
    // without a backreference or lookaround to the linear `regex` crate, which
    // never backtracks and so can never fail this way, so a nested quantifier
    // on its own never reaches the bound. A bound of zero fails on the first
    // backtrack, which keeps the test off how long a runaway pattern takes.
    let pattern = fancy_regex::RegexBuilder::new(r"(?:(a|a)\1)+c")
        .backtrack_limit(0)
        .build()
        .expect("pattern");
    let runaway = "a".repeat(8);
    assert!(
        pattern
            .captures_iter(&runaway)
            .any(|captures| captures.is_err()),
        "expected the backtrack bound to be reached"
    );
    assert_eq!(
        rewrite(&pattern, &runaway, &[], |_| REDACTED.to_owned()),
        None
    );
}

fn plain(command: &str) -> String {
    build_invocation_preview(Some(command), None).expect("preview")
}

#[test]
fn a_token_in_a_comment_tail_never_reaches_the_preview() {
    let rendered = plain("git push origin release/2.2 --force # ghp_0123456789FORBIDDEN");
    assert!(rendered.contains("git push origin release/2.2 --force"));
    assert!(!rendered.contains("ghp_0123456789FORBIDDEN"));
}

#[test]
fn a_comment_after_any_shell_operator_is_dropped() {
    assert_eq!(
        plain("printf \"# visible\" # private-note\ngit status"),
        "printf \"# visible\"\ngit status"
    );
    let private = plain("rm -rf ./stale-lab-dir # guard-private-command-sentinel");
    assert!(private.starts_with("rm -rf"));
    assert!(!private.contains("guard-private-command-sentinel"));
    for operator in [";", "&&", "||", "|", "&", ")", "("] {
        let rendered = plain(&format!("echo ok{operator}# private-note\ngit status"));
        assert!(!rendered.contains("private-note"), "{operator}");
    }
    assert!(!plain("echo ok \\\n# private-note\ngit status").contains("private-note"));
}

#[test]
fn a_colon_delimited_credential_is_redacted() {
    let rendered = plain(
        "tool --meta 'password: hunter2' --meta 'authorization: abc123' --meta 'access_key: xyz789'",
    );
    for secret in ["hunter2", "abc123", "xyz789"] {
        assert!(!rendered.contains(secret), "{secret}");
    }
    assert_eq!(rendered.matches("[redacted]").count(), 3);
}

#[test]
fn an_authorization_scheme_credential_is_redacted() {
    let rendered = plain(
        "tool --header 'Authorization: Bearer live-jwt-token' --header 'Authorization: Basic live-basic-token'",
    );
    assert!(!rendered.contains("live-jwt-token"));
    assert!(!rendered.contains("live-basic-token"));
    assert!(rendered.matches("[redacted]").count() + rendered.matches("*****").count() >= 2);
}

#[test]
fn spaced_heredocs_remotes_quoted_secrets_and_quoted_paths_are_scrubbed() {
    let heredoc = plain("git push origin main << EOF\nHEREDOC_PRIVATE\nEOF");
    assert!(heredoc.contains("git push origin main"));
    assert!(!heredoc.contains("HEREDOC_PRIVATE"));
    let quoted = plain("AWS_SECRET_ACCESS_KEY='alpha beta' git status");
    assert!(quoted.contains("git status"));
    assert!(!quoted.contains("alpha beta"));
    let remote = plain("git push ssh://internal.example/path");
    assert!(remote.contains("git push"));
    assert!(!remote.contains("ssh://internal.example/path"));
    for (command, private) in [
        ("cat /etc/passwd", "/etc/passwd"),
        ("type C:\\Secrets\\token.txt", "C:\\Secrets\\token.txt"),
        ("type C:/Secrets/token.txt", "C:/Secrets/token.txt"),
        (
            "type \"C:/Docs/alice/My Documents/token.txt\"",
            "My Documents",
        ),
        (
            "type 'C:\\Docs\\alice\\My Documents\\token.txt'",
            "Documents\\token.txt",
        ),
        ("cat \"/var/secret dir/token.txt\"", "secret dir/token.txt"),
        (
            "git push origin main << 'end.json'\nHEREDOC_PRIVATE\nend.json",
            "HEREDOC_PRIVATE",
        ),
    ] {
        assert!(!plain(command).contains(private), "{command}");
    }
}

#[test]
fn a_native_tool_input_and_a_codex_call_list_are_read() {
    assert_eq!(
        preview(json!({
            "toolUseId": "call_test_0123456789abcdef",
            "toolInput": {"command": "echo example"},
        }))
        .as_deref(),
        Some("echo example")
    );
    assert_eq!(
        preview(json!({"toolCalls": [{"name": "Bash", "args": {"command": "git status"}}]}))
            .as_deref(),
        Some("git status")
    );
}
