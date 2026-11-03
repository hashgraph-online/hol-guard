use serde_json::{json, Value};

use super::{dispatch, python_json_list};
use crate::runner_authority_op::ERR_INVALID;

const NAME: &str = "hol-guard::test";

fn replace(text: &str, command: &[&str]) -> Value {
    dispatch(&json!({"text": text, "name": NAME, "command": command})).expect("answer")
}

fn replaced(text: &str, command: &[&str]) -> String {
    replace(text, command)["text"]
        .as_str()
        .expect("replaced text")
        .to_owned()
}

fn refused(text: &str) -> String {
    let answer = replace(text, &["x"]);
    assert_eq!(answer["text"], Value::Null, "{text}");
    answer["reason"].as_str().expect("reason").to_owned()
}

fn config(command: &str) -> String {
    format!(
        "{{\n  \"mcp\": {{\n    \"test\": {{\"command\": [\"python3\"]}},\n    \"{NAME}\": {{\n      \"type\": \"local\",\n      \"command\": {command},\n      \"enabled\": true\n    }}\n  }}\n}}\n"
    )
}

#[test]
fn only_the_named_launchers_command_changes() {
    let text = format!(
        "// user configuration\n{}",
        config("[\"/old/hol-guard\", \"opencode-mcp-proxy\"]")
    );
    let result = replaced(&text, &["/new/hol-guard", "opencode-mcp-proxy"]);
    assert_eq!(
        result,
        format!(
            "// user configuration\n{}",
            config("[\"/new/hol-guard\", \"opencode-mcp-proxy\"]")
        )
    );
    // The other server's `command` is left alone.
    assert!(result.contains("\"test\": {\"command\": [\"python3\"]}"));
}

#[test]
fn comments_inside_the_old_array_are_kept_as_notes() {
    let old = "[\"/old/hol-guard\", // launcher note\n  /* pinned */ \"opencode-mcp-proxy\",]";
    let result = replaced(&config(old), &["/new/hol-guard"]);
    assert_eq!(
        result,
        config("// launcher note\n/* pinned */\n[\"/new/hol-guard\"]")
    );
    // A comment marker inside a string is text, not a comment.
    let result = replaced(&config("[\"http://x/*y*/\"]"), &["z"]);
    assert_eq!(result, config("[\"z\"]"));
}

#[test]
fn offsets_count_characters_not_bytes() {
    let text = format!(
        "/* café ✓ — ünïcode */\n{}",
        config("[\"/old/é\"] /* ✓ after */")
    );
    let result = replaced(&text, &["/new"]);
    assert_eq!(
        result,
        format!(
            "/* café ✓ — ünïcode */\n{}",
            config("[\"/new\"] /* ✓ after */")
        )
    );
}

#[test]
fn the_new_array_is_spelled_as_python_json_dumps_spells_it() {
    assert_eq!(python_json_list(&[]), "[]");
    assert_eq!(
        python_json_list(&["a b", "é", "😀", "q\"\\\n\r\t\u{8}\u{c}\u{1}\u{7f}~"]),
        r#"["a b", "é", "😀", "q\"\\\n\r\t\b\f\u0001\u007f~"]"#
    );
}

#[test]
fn a_missing_repeated_or_malformed_member_is_refused() {
    assert_eq!(
        refused("{\"mcp\": {}}"),
        "OpenCode launcher member is missing or ambiguous"
    );
    let repeated = format!("{{\"mcp\": {{\"{NAME}\": {{\"command\": [], \"command\": []}}}}}}");
    assert_eq!(
        refused(&repeated),
        "OpenCode launcher member is missing or ambiguous"
    );
    assert_eq!(
        refused("{\"mcp\": []}"),
        "OpenCode launcher refresh expected an object"
    );
    assert_eq!(refused("{\"mcp\" {}}"), "Invalid OpenCode object member");
    assert_eq!(
        refused("{\"mcp\": {} \"x\": 1}"),
        "Invalid OpenCode object separator"
    );
    for text in ["", "{", "{\"mcp\": {\"a\": tru}}", "/* open", "{1: 2}"] {
        assert!(!refused(text).is_empty(), "{text}");
    }
}

#[test]
fn a_malformed_request_is_refused() {
    for request in [
        json!({"name": NAME, "command": []}),
        json!({"text": "{}", "command": []}),
        json!({"text": "{}", "name": NAME}),
        json!({"text": "{}", "name": NAME, "command": [1]}),
        json!({"text": "{}", "name": NAME, "command": vec!["x"; 4097]}),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID));
    }
}
