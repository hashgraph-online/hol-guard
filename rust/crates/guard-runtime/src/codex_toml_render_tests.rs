use serde_json::{json, Value};

use super::{dispatch, same, HookVal};
use crate::pyjson;

fn render(payload: &str, tokens: Value, original: Option<&str>) -> String {
    let answer = dispatch(&json!({ "payload": payload, "tokens": tokens, "original": original }));
    answer.unwrap()["text"].as_str().unwrap().to_owned()
}

fn plain(payload: &str) -> String {
    render(payload, json!({}), None)
}

/// Whether `text` reads back as exactly the JSON `payload`.
fn means(text: &str, payload: &str) -> bool {
    let document = text.parse::<toml_edit::DocumentMut>().unwrap();
    let expected = HookVal::from_py(&pyjson::parse(payload).unwrap());
    same(&HookVal::from_document(document.as_table()), &expected)
}

#[test]
fn the_plain_renderer_writes_what_python_wrote() {
    let payload = r#"{"model": "fixture", "n": 1, "f": 1e16, "g": 0.1, "b": true, "none": null,
        "uni": "café \"q\"",
        "mcp_servers": {"a b": {"args": ["x", 2, null], "env": {"K": "v", "N": null}, "empty": {},
            "inner": {"deep": {}}}, "plain": {"command": "node"}},
        "list": [{"a": 1}], "when": "T-0", "day": "T-1", "big": "T-2"}"#;
    let tokens = json!({
        "T-0": {"type": "datetime", "value": "2024-01-02T03:04:05+00:00"},
        "T-1": {"type": "date", "value": "2024-01-02"},
        "T-2": {"__int__": "1180591620717411303424"},
    });
    let expected = "model = \"fixture\"\nn = 1\nf = 1e+16\ng = 0.1\nb = true\n\
        uni = \"caf\\u00e9 \\\"q\\\"\"\nlist = [{ a = 1 }]\nwhen = \"2024-01-02 03:04:05+00:00\"\n\
        day = \"2024-01-02\"\nbig = 1180591620717411303424\n[mcp_servers]\n\n\
        [mcp_servers.\"a b\"]\nargs = [\"x\", 2, \"None\"]\n\n[mcp_servers.\"a b\".env]\nK = \"v\"\n\n\n\
        [mcp_servers.\"a b\".empty]\n\n[mcp_servers.\"a b\".inner]\n\n[mcp_servers.\"a b\".inner.deep]\n\n\
        [mcp_servers.plain]\ncommand = \"node\"\n";
    assert_eq!(render(payload, tokens, None), expected);
    assert_eq!(plain("{}"), "");
    assert_eq!(plain(r#"{"a": {}}"#), "[a]\n");
    assert_eq!(plain(r#"{"a": {"b": {}}}"#), "[a]\n\n[a.b]\n");
}

const HAND_WRITTEN: &str = "\
# Which model Codex talks to. Keep this at the top.
model = \"fixture\"
model_reasoning_effort = 'medium'   # single quotes on purpose

# Everything below is mine.
[mcp_servers.fixture]
command = \"node\"
args = [\"fixture.js\"]        # trailing comment
env = { FIXTURE = \"1\" }

[tui]
# A comment with no key after it.
";

#[test]
fn an_edit_keeps_the_comments_and_the_spelling_around_it() {
    let payload =
        r#"{"model": "fixture", "model_reasoning_effort": "medium", "approval_policy": "never"}"#;
    let rendered = render(payload, json!({}), Some(HAND_WRITTEN));
    assert!(rendered.contains("# Which model Codex talks to. Keep this at the top."));
    assert!(rendered.contains("model_reasoning_effort = 'medium'   # single quotes on purpose"));
    assert!(rendered.contains("approval_policy = \"never\""));
    assert!(means(&rendered, payload), "{rendered}");
}

#[test]
fn the_rendered_file_means_exactly_the_payload() {
    let payload = r#"{"model": "replacement", "mcp_servers": {"fixture": {"command": "node",
        "args": ["fixture.js", "--guard"], "env": {"FIXTURE": "2", "MORE": "x"}}},
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command"}]}]},
        "profiles": {"a": {"model": "m"}}, "empty": [], "dicts": {"inline": [{"x": 1}]}}"#;
    let rendered = render(payload, json!({}), Some(HAND_WRITTEN));
    assert!(means(&rendered, payload), "{rendered}");
    assert!(rendered.contains("# Everything below is mine."));
    assert!(rendered.contains("# Which model Codex talks to."));
    assert!(rendered.contains("[[hooks.PreToolUse]]"), "{rendered}");
    assert!(
        !rendered.contains("[tui]"),
        "a key the payload dropped is removed"
    );
}

#[test]
fn a_file_or_value_the_edit_cannot_keep_falls_back_to_the_plain_renderer() {
    let payload = r#"{"model": "fixture"}"#;
    assert_eq!(
        render(payload, json!({}), Some("model = = =\n")),
        plain(payload)
    );
    assert_eq!(render(payload, json!({}), Some("")), plain(payload));
    let wide = r#"{"model": "fixture", "big": "T-0"}"#;
    let tokens = json!({"T-0": {"__int__": "1180591620717411303424"}});
    let nan = json!({"T-0": {"type": "float", "value": "nan"}});
    assert_eq!(
        render(wide, tokens.clone(), Some(HAND_WRITTEN)),
        render(wide, tokens, None)
    );
    assert_eq!(
        render(wide, nan.clone(), Some(HAND_WRITTEN)),
        render(wide, nan, None)
    );
    let listed_null = r#"{"model": ["x", null]}"#;
    assert_eq!(
        render(listed_null, json!({}), Some(HAND_WRITTEN)),
        plain(listed_null)
    );
}

const WITH_USER_HOOKS: &str = "\
model = \"fixture\"

[features]
hooks = 1   # the user wrote an integer here

[[hooks.PreToolUse]]
# My own hook. Hands off.
matcher = \"Bash\"

  [[hooks.PreToolUse.hooks]]
  type = \"command\"
  command = \"echo mine\"   # keep this spelling
";

#[test]
fn an_integer_standing_in_for_a_boolean_is_corrected() {
    let payload = r#"{"model": "fixture", "features": {"hooks": true}}"#;
    let rendered = render(payload, json!({}), Some(WITH_USER_HOOKS));
    assert!(means(&rendered, payload), "{rendered}");
    assert!(rendered.contains("hooks = true"));
}

#[test]
fn an_added_hook_group_leaves_the_users_group_as_written() {
    let payload = r#"{"model": "fixture", "features": {"hooks": true}, "hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]},
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "guard-hook"}]}]}}"#;
    let rendered = render(payload, json!({}), Some(WITH_USER_HOOKS));
    assert!(means(&rendered, payload), "{rendered}");
    assert!(rendered.contains("# My own hook. Hands off."));
    assert!(rendered.contains("command = \"echo mine\"   # keep this spelling"));
}

const GUARD_GROUP_FIRST: &str = "\
[[hooks.PreToolUse]]
# Guard group.
matcher = \"Bash\"

  [[hooks.PreToolUse.hooks]]
  type = \"command\"
  command = \"guard-hook\"

[[hooks.PreToolUse]]
# My own hook. Hands off.
matcher = \"Bash\"

  [[hooks.PreToolUse.hooks]]
  type = \"command\"
  command = \"echo mine\"   # keep this spelling
";

#[test]
fn reordering_hook_groups_does_not_move_the_users_comments() {
    let payload = r#"{"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]},
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "guard-hook"}]}]}}"#;
    let rendered = render(payload, json!({}), Some(GUARD_GROUP_FIRST));
    assert!(means(&rendered, payload), "{rendered}");
    let at = |needle: &str| rendered.find(needle).unwrap();
    assert!(at("# My own hook. Hands off.") < at("command = \"echo mine\"   # keep this spelling"));
    assert!(at("command = \"echo mine\"") < at("# Guard group."));
    assert!(at("# Guard group.") < at("command = \"guard-hook\""));

    let changed = r#"{"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]},
        {"matcher": "Edit", "hooks": [{"type": "command", "command": "guard-hook-2"}]}]}}"#;
    let rendered = render(changed, json!({}), Some(GUARD_GROUP_FIRST));
    assert!(means(&rendered, changed), "{rendered}");
    assert!(rendered.contains("command = \"echo mine\"   # keep this spelling"));
}

#[test]
fn an_inline_array_keeps_matched_elements_and_edits_the_rest() {
    let original = "servers = [{ name = \"a\", port = 1 }, \"plain\"]   # mine\n";
    let payload = r#"{"servers": ["plain", {"name": "a", "port": 2}, [1]]}"#;
    let rendered = render(payload, json!({}), Some(original));
    assert!(means(&rendered, payload), "{rendered}");
    assert!(rendered.contains("# mine"));
}

#[test]
fn malformed_requests_are_refused() {
    for args in [
        json!({"payload": "{}", "tokens": {}}),
        json!({"payload": "{}", "tokens": {}, "original": 1}),
        json!({"payload": "[]", "tokens": {}, "original": null}),
        json!({"payload": "{", "tokens": {}, "original": null}),
        json!({"payload": "{\"a\": \"T\"}", "tokens": {"T": {"type": "set", "value": "x"}}, "original": null}),
        json!({"payload": "{}", "tokens": [], "original": null}),
        json!({"payload": "{}", "tokens": {}, "original": null, "more": 1}),
    ] {
        assert!(dispatch(&args).is_err(), "{args}");
    }
}
