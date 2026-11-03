//! The Devin `config.json` and Muse `settings.json` rewrites, with the texts
//! `DevinHarnessAdapter` and `MuseHarnessAdapter` wrote through
//! `json.dumps(indent=2)` and their refusal messages.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const DEVIN_COMMAND: &str = "HOL_GUARD_MANAGED_DEVIN=1 guard-hook";
const MUSE_COMMAND: &str = "HOL_GUARD_MANAGED_MUSE=1 guard-hook";
const DEVIN_PATH: &str = "/home/user/.config/devin/config.json";
const MUSE_PATH: &str = "/home/user/.config/muse/settings.json";
const TOOLS: &str =
    "^(exec|read|write|edit|apply_patch|notebook_read|notebook_edit|grep|glob|webfetch|mcp_call_tool|mcp__.*)$";
const DEVIN_PARSE: &str = "Devin config at ~/.config/devin/config.json could not be parsed as a \
     JSON object; Guard will not rewrite it. Fix the file, then rerun hol-guard install devin.";
const MUSE_PARSE: &str = "Muse settings at ~/.config/muse/settings.json could not be parsed as a \
     JSON object; Guard will not rewrite it. Fix the file, then rerun hol-guard install muse.";

/// `json.dumps(indent=2)` of a fresh Devin install, `{tools}` standing for
/// the tool matcher.
const DEVIN_FRESH: &str = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "HOL_GUARD_MANAGED_DEVIN=1 guard-hook",
            "timeout": 65
          }
        ],
        "matcher": "{tools}"
      }
    ],
    "PermissionRequest": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "HOL_GUARD_MANAGED_DEVIN=1 guard-hook",
            "timeout": 30
          }
        ],
        "matcher": "{tools}"
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "HOL_GUARD_MANAGED_DEVIN=1 guard-hook",
            "timeout": 30
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "HOL_GUARD_MANAGED_DEVIN=1 guard-hook",
            "timeout": 65
          }
        ],
        "matcher": "{tools}"
      }
    ]
  }
}
"#;

fn encoded(content: Option<&str>) -> Value {
    json!(content.map(|text| STANDARD.encode(text)))
}

fn install_request(harness: &str, content: Value, timing: Value) -> Value {
    let (key, path, command) = match harness {
        "muse" => ("bridge_seconds", MUSE_PATH, MUSE_COMMAND),
        _ => ("wait_seconds", DEVIN_PATH, DEVIN_COMMAND),
    };
    let mut request = json!({
        "op": "install",
        "harness": harness,
        "content": content,
        "config_path": path,
        "command": command,
    });
    request[key] = timing;
    request
}

fn install(harness: &str, content: Option<&str>) -> Value {
    dispatch(&install_request(harness, encoded(content), json!(60))).expect("install answers")
}

fn installed(harness: &str, content: Option<&str>) -> String {
    let answer = install(harness, content);
    assert_eq!(answer.as_object().map(|map| map.len()), Some(3), "{answer}");
    answer["text"].as_str().expect("text").to_owned()
}

fn refusal(harness: &str, content: &[u8]) -> String {
    let request = install_request(harness, json!(STANDARD.encode(content)), json!(60));
    let answer = dispatch(&request).expect("install answers");
    assert_eq!(answer.as_object().map(|map| map.len()), Some(1), "{answer}");
    answer["refusal"].as_str().expect("refusal").to_owned()
}

fn uninstall(harness: &str, content: Value, present: bool) -> Value {
    let request =
        json!({ "op": "uninstall", "harness": harness, "content": content, "present": present });
    dispatch(&request).expect("uninstall answers")
}

fn parsed(text: &str) -> Value {
    serde_json::from_str(text).expect("rendered JSON")
}

#[test]
fn devin_fresh_install_renders_python_bytes() {
    let answer = install("devin", None);
    assert_eq!(answer["text"], DEVIN_FRESH.replace("{tools}", TOOLS));
    assert_eq!(
        answer["state"],
        format!("{{\n  \"managed_config_path\": \"{DEVIN_PATH}\"\n}}\n")
    );
    assert_eq!(
        answer["notes"],
        json!([
            "Guard hook entries added to ~/.config/devin/config.json under the hooks section",
            "User permissions, read_config_from, MCP servers, and any pre-existing hooks were preserved",
        ])
    );
    // An empty file plans like no file.
    assert_eq!(installed("devin", Some(" \n")), answer["text"]);
}

#[test]
fn muse_fresh_install_adds_schema_version_and_status() {
    let answer = install("muse", None);
    let text = answer["text"].as_str().expect("text");
    assert!(text.starts_with("{\n  \"schema_version\": 1,\n  \"hooks\": {\n    \"PreToolUse\": ["));
    let after = parsed(text);
    let hooks = &after["hooks"];
    assert_eq!(hooks.as_object().map(|events| events.len()), Some(6));
    let handler = &hooks["PreToolUse"][0]["hooks"][0];
    assert_eq!(handler["timeout"], 65);
    assert_eq!(
        handler["statusMessage"],
        "HOL Guard is checking this action"
    );
    assert_eq!(hooks["Stop"][0]["hooks"][0]["timeout"], 30);
    assert!(hooks["PreToolUse"][0].get("matcher").is_none());
    assert_eq!(
        answer["state"],
        format!("{{\n  \"managed_settings_path\": \"{MUSE_PATH}\"\n}}\n")
    );
    assert_eq!(answer["notes"].as_array().map(Vec::len), Some(3));
    // A schema_version the user set is kept in place; a missing one goes last.
    let kept = installed("muse", Some(r#"{"hooks": {}, "schema_version": 2}"#));
    assert!(
        kept.contains("  },\n  \"schema_version\": 2\n}\n"),
        "{kept}"
    );
    let added = installed("muse", Some(r#"{"model": "m", "hooks": null}"#));
    assert!(
        added.starts_with("{\n  \"model\": \"m\",\n  \"hooks\": {"),
        "{added}"
    );
    assert!(
        added.ends_with("  },\n  \"schema_version\": 1\n}\n"),
        "{added}"
    );
}

#[test]
fn install_keeps_user_values_and_order_and_is_idempotent() {
    let before = json!({
        "z": 1,
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": TOOLS,
                    "hooks": [
                        { "type": "command", "command": "HOL_GUARD_MANAGED_DEVIN old", "timeout": 1 },
                        { "type": "command", "command": "lint" },
                    ],
                },
                { "matcher": "user", "hooks": [{ "command": "mine" }] },
            ],
            "Custom": [1],
            "PostToolUse": "not a list",
        },
        "a": "b",
    });
    // serde_json sorts keys; write the user's order by hand.
    let text = format!(
        "{{\"z\": 1, \"hooks\": {{\"PreToolUse\": {}, \"Custom\": [1], \"PostToolUse\": \"not a list\"}}, \"a\": \"b\"}}",
        before["hooks"]["PreToolUse"]
    );
    let first = installed("devin", Some(text.as_str()));
    let order = [
        "\"z\"",
        "\"hooks\"",
        "\"PreToolUse\"",
        "\"Custom\"",
        "\"PostToolUse\"",
        "\"PermissionRequest\"",
        "\"a\"",
    ];
    let positions: Vec<usize> = order
        .iter()
        .map(|key| first.find(key).expect(key))
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "{first}"
    );
    let after = parsed(&first);
    // The old Guard handler is replaced in the user's own group, after lint.
    let group = &after["hooks"]["PreToolUse"][0];
    assert_eq!(group["matcher"], TOOLS);
    assert_eq!(group["hooks"][0]["command"], "lint");
    assert_eq!(group["hooks"][1]["command"], DEVIN_COMMAND);
    assert_eq!(group["hooks"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        after["hooks"]["PreToolUse"][1],
        before["hooks"]["PreToolUse"][1]
    );
    assert_eq!(after["hooks"]["Custom"], json!([1]));
    // Devin replaces a non-list managed event with Guard's group.
    assert_eq!(
        after["hooks"]["PostToolUse"][0]["hooks"][0]["command"],
        DEVIN_COMMAND
    );
    assert_eq!(installed("devin", Some(first.as_str())), first);
}

#[test]
fn install_escapes_non_ascii_and_keeps_numbers() {
    let text = installed(
        "muse",
        Some("{\"x\": \"caf\u{e9} \u{2615}\", \"n\": NaN, \"i\": 1e400, \"b\": 12345678901234567890123, \"f\": 1.50}"),
    );
    assert!(text.starts_with(
        "{\n  \"x\": \"caf\\u00e9 \\u2615\",\n  \"n\": NaN,\n  \"i\": Infinity,\n  \"b\": 12345678901234567890123,\n  \"f\": 1.5,\n"
    ), "{text}");
}

#[test]
fn install_refuses_a_lone_surrogate_it_cannot_write_back() {
    let request = install_request("muse", encoded(Some(r#"{"a": "\ud800"}"#)), json!(60));
    assert_eq!(dispatch(&request), Err(ERR_INVALID));
    let request = install_request("devin", encoded(Some(r#"{"a": "\udc00"}"#)), json!(60));
    assert_eq!(dispatch(&request), Err(ERR_INVALID));
}

#[test]
fn devin_install_refusals_keep_python_messages() {
    let commented = "Devin config at ~/.config/devin/config.json contains comments or trailing \
         commas; Guard will not rewrite it. Remove the comments or move them to another file, \
         then rerun hol-guard install devin.";
    assert_eq!(refusal("devin", b"{\"a\": 1 // note\n}"), commented);
    assert_eq!(refusal("devin", b"{\"a\": 1,}"), commented);
    assert_eq!(refusal("devin", b"nope"), DEVIN_PARSE);
    assert_eq!(refusal("devin", b"[1]"), DEVIN_PARSE);
    assert_eq!(
        refusal("devin", b"{\"a\": \"\xff\"}"),
        "Devin config could not be parsed as a JSON object; Guard will not rewrite it."
    );
    assert_eq!(
        refusal("devin", b"{\"hooks\": []}"),
        "Devin config has a non-object hooks value; Guard will not rewrite it."
    );
}

#[test]
fn muse_install_refusals_keep_python_messages() {
    assert_eq!(refusal("muse", b"nope"), MUSE_PARSE);
    assert_eq!(refusal("muse", b""), MUSE_PARSE);
    assert_eq!(refusal("muse", b"{\"a\": 1 // note\n}"), MUSE_PARSE);
    assert_eq!(refusal("muse", b"\xff"), MUSE_PARSE);
    assert_eq!(
        refusal("muse", b"[1]"),
        "Muse settings must be a JSON object before installation."
    );
    assert_eq!(
        refusal("muse", b"{\"hooks\": \"x\"}"),
        "Muse settings have a non-object hooks value; Guard will not rewrite it."
    );
    assert_eq!(
        refusal("muse", "{\"hooks\": {\"Stop\": null, \"\u{c9}v\u{e9}nement\": {}}}".as_bytes()),
        "Muse settings have a non-list hooks.\u{c9}v\u{e9}nement value; Guard will not rewrite it. \
         Fix the file, then rerun hol-guard install muse."
    );
}

#[test]
fn uninstall_prunes_guard_handlers_and_drops_empty_hooks() {
    let installed_text = installed("devin", Some(r#"{"keep": true, "hooks": {"Custom": [1]}}"#));
    let answer = uninstall("devin", encoded(Some(installed_text.as_str())), true);
    assert_eq!(
        answer["text"],
        "{\n  \"keep\": true,\n  \"hooks\": {\n    \"Custom\": [\n      1\n    ]\n  }\n}\n"
    );
    assert_eq!(
        answer["notes"],
        json!([
            "Guard-managed hook entries removed from ~/.config/devin/config.json",
            "User permissions, read_config_from, MCP servers, and any pre-existing hooks were preserved",
        ])
    );
    let fresh = installed("muse", Some(r#"{"model": "m"}"#));
    let answer = uninstall("muse", encoded(Some(fresh.as_str())), true);
    assert_eq!(
        answer["text"],
        "{\n  \"model\": \"m\",\n  \"schema_version\": 1\n}\n"
    );
    // A dict hooks value always rewrites, normalizing the text.
    let answer = uninstall("muse", encoded(Some(r#"{"f": 1.50, "hooks": {}}"#)), true);
    assert_eq!(answer["text"], "{\n  \"f\": 1.5\n}\n");
}

#[test]
fn uninstall_leaves_files_it_will_not_rewrite() {
    let unparsed = json!(["Devin config could not be parsed; Guard left the file untouched."]);
    let answer = uninstall("devin", encoded(Some("nope")), true);
    assert_eq!(answer, json!({ "text": null, "notes": unparsed }));
    // Present but unreadable.
    assert_eq!(uninstall("devin", Value::Null, true)["notes"], unparsed);
    assert_eq!(
        uninstall("devin", json!(STANDARD.encode(b"\xff")), true)["notes"],
        unparsed
    );
    let answer = uninstall("devin", encoded(Some("{\"hooks\": {}} // note")), true);
    assert_eq!(answer["text"], Value::Null);
    assert_eq!(
        answer["notes"],
        json!([
            "Devin config is JSONC (comments or trailing commas); Guard left its managed hook \
             entries in place rather than rewriting the file. Remove the entries under the hooks \
             key manually."
        ])
    );
    let muse_unparsed =
        json!(["Muse settings could not be parsed; Guard left the file untouched."]);
    assert_eq!(
        uninstall("muse", encoded(Some("nope")), true)["notes"],
        muse_unparsed
    );
    let removed = json!([
        "Guard-managed hook entries removed from ~/.config/muse/settings.json",
        "User model, skills, MCP servers, and any pre-existing hooks were preserved",
    ]);
    for content in ["[1]", r#"{"hooks": 3}"#] {
        let answer = uninstall("muse", encoded(Some(content)), true);
        assert_eq!(answer, json!({ "text": null, "notes": removed }));
    }
    let answer = uninstall("muse", Value::Null, false);
    assert_eq!(answer, json!({ "text": null, "notes": removed }));
}

#[test]
fn malformed_requests_are_refused() {
    let base = install_request("devin", Value::Null, json!(60));
    let mut cases = Vec::new();
    for (key, value) in [
        ("harness", json!("claude")),
        ("op", json!("prune")),
        ("content", json!("not base64!")),
        ("content", json!(3)),
        ("command", json!(null)),
        ("config_path", json!(1)),
        ("wait_seconds", json!("60")),
        ("wait_seconds", json!(1.5)),
    ] {
        let mut request = base.clone();
        request[key] = value;
        cases.push(request);
    }
    let mut extra = base.clone();
    extra["bridge_seconds"] = json!(60);
    cases.push(extra);
    let mut missing = base.clone();
    missing.as_object_mut().expect("request").remove("command");
    cases.push(missing);
    cases.push(json!([]));
    // Muse's deadline overflows past i64.
    cases.push(install_request("muse", Value::Null, json!(u64::MAX)));
    cases.push(json!({ "op": "uninstall", "harness": "muse", "content": null, "present": "yes" }));
    cases.push(json!({ "op": "uninstall", "harness": "muse", "content": encoded(Some("{}")), "present": false }));
    cases.push(json!({ "op": "uninstall", "harness": "muse", "content": null }));
    for request in cases {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
    // Devin clamps its approval wait instead.
    let request = install_request("devin", Value::Null, json!(u64::MAX));
    let text = dispatch(&request).expect("clamped")["text"].clone();
    assert_eq!(
        parsed(text.as_str().expect("text"))["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"],
        605
    );
}
