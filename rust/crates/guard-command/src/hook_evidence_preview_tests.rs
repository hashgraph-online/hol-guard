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
    // The bound is set explicitly rather than left at its default, so the test
    // does not depend on how long a runaway pattern takes to exhaust it.
    let pattern = fancy_regex::RegexBuilder::new(r"(?=(a+)+b)")
        .backtrack_limit(1)
        .build()
        .expect("pattern");
    let runaway = "a".repeat(32);
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
