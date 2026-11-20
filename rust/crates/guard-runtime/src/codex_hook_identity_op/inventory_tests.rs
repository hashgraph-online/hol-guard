use super::super::{evaluate_request, refusal};
use guard_contracts::{CodexHookIdentityRequestV1, CODEX_HOOK_IDENTITY_REQUEST_SCHEMA};
use serde_json::{json, Value};

fn request(entries: Vec<Value>, tokens: Value) -> CodexHookIdentityRequestV1 {
    serde_json::from_value(json!({
        "schema": CODEX_HOOK_IDENTITY_REQUEST_SCHEMA,
        "request_id": "test",
        "scalar_tokens": tokens,
        "entries": entries,
    }))
    .expect("request parses")
}

fn answers(request: &CodexHookIdentityRequestV1) -> Vec<Value> {
    assert_eq!(refusal(request), None);
    evaluate_request(request)["identities"]
        .as_array()
        .expect("identities is a list")
        .clone()
}

fn inventory(events: Value) -> Value {
    json!({
        "kind": "inventory",
        "source_scope": "user",
        "source_hooks_enabled": true,
        "event_name": "",
        "source_format": "toml",
        "events": events,
    })
}

fn group() -> Value {
    json!({
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "echo hello  world", "timeout": 1.5}],
    })
}

#[test]
fn a_record_carries_the_identity_a_handler_question_derives() {
    let handler = json!({
        "kind": "handler",
        "source_scope": "user",
        "source_hooks_enabled": true,
        "event_name": "PreToolUse",
        "group": group(),
        "handler": group()["hooks"][0].clone(),
    });
    let request = request(
        vec![handler, inventory(json!([["PreToolUse", [group()]]]))],
        json!({}),
    );
    let answers = answers(&request);
    let record = &answers[1]["records"][0];
    assert_eq!(record["canonical_identity"], answers[0]["digest"]);
    assert_eq!(record["command_argv"], json!(["echo", "hello", "world"]));
    assert_eq!(record["matcher"], json!("Bash"));
    assert_eq!(record["timeout"], json!(1.5));
    assert_eq!(record["ownership"], json!("unmanaged"));
    assert_eq!(record["active"], json!(true));
    assert_eq!(answers[1]["issues"], json!([]));
}

#[test]
fn ownership_follows_the_first_authority_that_binds_the_handler() {
    let binding = json!({
        "event": "PreToolUse",
        "group": {"matcher": "Bash"},
        "handler": {"type": "command", "command": "echo hello  world", "timeout": 1.5},
    });
    let mut self_bound = inventory(json!([["PreToolUse", [group()]]]));
    self_bound["self_bindings"] = json!([binding]);
    let mut both = self_bound.clone();
    both["authenticated_bindings"] = json!([binding]);
    let answers = answers(&request(vec![self_bound, both], json!({})));
    assert_eq!(
        answers[0]["records"][0]["ownership"],
        json!("self_install_binding")
    );
    assert_eq!(
        answers[1]["records"][0]["ownership"],
        json!("authenticated_manifest")
    );
}

#[test]
fn events_keep_the_order_the_source_wrote_them_in() {
    let events = json!([
        ["Stop", ["not a group"]],
        ["PreToolUse", [group()]],
        ["AfterAgent", "not a list"],
    ]);
    let answers = answers(&request(vec![inventory(events)], json!({})));
    let issues = answers[0]["issues"].as_array().unwrap();
    let events: Vec<&Value> = issues.iter().map(|issue| &issue["event_name"]).collect();
    assert_eq!(events, [&json!("Stop"), &json!("AfterAgent")]);
    assert_eq!(issues[0]["group_index"], json!(0));
    assert_eq!(issues[1]["group_index"], Value::Null);
    assert_eq!(answers[0]["records"][0]["event_name"], json!("PreToolUse"));
}

#[test]
fn hooks_that_are_not_a_table_are_one_issue() {
    let mut entry = inventory(Value::Null);
    entry.as_object_mut().unwrap().remove("events");
    let answers = answers(&request(vec![entry], json!({})));
    assert_eq!(answers[0]["records"], json!([]));
    assert_eq!(
        answers[0]["issues"][0]["reason_code"],
        json!("codex_hook_inventory_unsupported_event_shape")
    );
}

#[test]
fn tokens_stand_for_the_scalars_json_cannot_carry() {
    let tokens = json!({
        "t-0": {"__int__": "123456789012345678901234567890"},
        "t-1": {"type": "datetime", "value": "1979-05-27T07:32:00+00:00"},
    });
    let handler = json!({"type": "command", "command": "run", "timeout": "t-0", "since": "t-1"});
    let group = json!({"hooks": [handler]});
    let question = json!({
        "kind": "handler",
        "source_scope": "user",
        "source_hooks_enabled": true,
        "event_name": "Stop",
        "group": group,
        "handler": handler,
    });
    let answers = answers(&request(
        vec![question, inventory(json!([["Stop", [group]]]))],
        tokens,
    ));
    let record = &answers[1]["records"][0];
    assert_eq!(record["canonical_identity"], answers[0]["digest"]);
    assert_eq!(
        record["timeout"].to_string(),
        "123456789012345678901234567890"
    );
}

#[test]
fn an_entry_naming_an_unknown_token_or_format_is_refused() {
    let unknown = request(
        vec![inventory(json!([["Stop", [{"hooks": ["t-0"]}]]]))],
        json!({"t-0": {"type": "bytes", "value": "b''"}}),
    );
    assert_eq!(
        refusal(&unknown),
        Some("native_codex_hook_identity_entry_invalid")
    );
    let mut formatless = inventory(json!([]));
    formatless["source_format"] = json!("yaml");
    assert_eq!(
        refusal(&request(vec![formatless], json!({}))),
        Some("native_codex_hook_identity_entry_invalid")
    );
}

#[test]
fn a_binding_token_claims_the_handler_holding_the_same_scalar() {
    let tokens = json!({
        "t-0": {"type": "date", "value": "2026-10-23"},
        "t-1": {"type": "date", "value": "2026-10-23"},
        "t-2": {"type": "date", "value": "2026-10-24"},
        "t-3": {"type": "float", "value": "inf"},
        "t-4": {"type": "float", "value": "inf"},
    });
    let handler = |since: &str, ratio: &str| json!({"type": "command", "command": "guard-hook", "since": since, "ratio": ratio});
    let entry = |binding_since: &str| {
        let mut entry = inventory(json!([[
            "PreToolUse",
            [{"matcher": "Bash", "hooks": [handler("t-0", "t-3")]}],
        ]]));
        entry["self_bindings"] = json!([{
            "event": "PreToolUse",
            "group": {"matcher": "Bash"},
            "handler": handler(binding_since, "t-4"),
        }]);
        entry
    };
    let answers = answers(&request(vec![entry("t-1"), entry("t-2")], tokens));
    assert_eq!(
        answers[0]["records"][0]["ownership"],
        json!("self_install_binding")
    );
    assert_eq!(answers[1]["records"][0]["ownership"], json!("unmanaged"));
}

fn is_text(value: &Value) -> bool {
    value.as_str().is_some()
}

fn is_text_or_null(value: &Value) -> bool {
    value.is_null() || is_text(value)
}

fn is_count_or_null(value: &Value) -> bool {
    value.is_null() || value.is_u64()
}

fn is_text_list(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(is_text))
}

/// The shape a caller reads an answer by. The bridge builds its records from
/// these fields without re-checking their types, so the types are held here.
#[test]
fn every_record_and_issue_has_the_fields_and_types_a_caller_reads() {
    let source = inventory(json!([
        ["PreToolUse", [group()]],
        [
            "PostToolUse",
            [{"matcher": null, "hooks": [{"type": "command", "command": "echo"}, "not a handler"]}]
        ],
        ["Stop", "not a list of groups"],
    ]));
    let answers = answers(&request(vec![source], json!({})));
    let records = answers[0]["records"].as_array().expect("records is a list");
    assert!(records.len() >= 2);
    for record in records {
        let record = record.as_object().expect("a record is an object");
        let mut keys: Vec<&str> = record.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "active",
                "canonical_identity",
                "command",
                "command_argv",
                "environment_keys",
                "event_name",
                "executable",
                "group_index",
                "handler_index",
                "handler_type",
                "matcher",
                "ownership",
                "timeout",
            ]
        );
        assert!(is_text(&record["event_name"]));
        assert!(record["group_index"].is_u64() && record["handler_index"].is_u64());
        assert!(is_text_or_null(&record["matcher"]));
        assert!(is_text_or_null(&record["handler_type"]));
        assert!(is_text_or_null(&record["command"]));
        assert!(record["command_argv"].is_null() || is_text_list(&record["command_argv"]));
        assert!(record["timeout"].is_null() || record["timeout"].is_number());
        assert!(is_text_list(&record["environment_keys"]));
        assert!(record["active"].is_boolean() && record["executable"].is_boolean());
        assert!(matches!(
            record["ownership"].as_str(),
            Some(
                "authenticated_manifest"
                    | "exact_legacy_adoption"
                    | "self_install_binding"
                    | "unmanaged"
            )
        ));
        assert!(record["canonical_identity"]
            .as_str()
            .is_some_and(|identity| !identity.is_empty()));
    }
    let issues = answers[0]["issues"].as_array().expect("issues is a list");
    assert!(!issues.is_empty());
    for issue in issues {
        let issue = issue.as_object().expect("an issue is an object");
        let mut keys: Vec<&str> = issue.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "event_name",
                "group_index",
                "handler_index",
                "message",
                "reason_code"
            ]
        );
        assert!(is_text(&issue["reason_code"]) && is_text(&issue["message"]));
        assert!(is_text_or_null(&issue["event_name"]));
        assert!(is_count_or_null(&issue["group_index"]));
        assert!(is_count_or_null(&issue["handler_index"]));
    }
}
