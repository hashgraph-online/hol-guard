//! Replays the verdicts the original Python `cursor_native_hook_state` gave
//! over real planted files, and pins the argument refusals.

use serde_json::{json, Value};

use super::cursor_hook_state::dispatch;
use super::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/cursor/cursor_hook_state_vectors.json");

fn cases() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(document["schema"], "guard-cursor-hook-state-vectors.v1");
    document["cases"].as_array().expect("cases").clone()
}

/// The verdict the Python shim builds from an answer.
fn applied(answer: &Value, identity: &Value) -> Value {
    if let Some(label) = answer.get("raise") {
        assert_eq!(answer.as_object().expect("answer").len(), 1);
        return json!({ "raise": label });
    }
    let status = answer["integrity_status"].as_str().expect("status");
    if status == "valid" {
        assert!(answer["reason"].is_null());
        return json!({
            "protection_active": true,
            "integrity_status": "valid",
            "reason": null,
            "guard_cli_identity": identity,
        });
    }
    json!({
        "protection_active": false,
        "integrity_status": status,
        "reason": answer["reason"],
    })
}

#[test]
fn every_recorded_verdict_replays() {
    let cases = cases();
    assert_eq!(cases.len(), 58);
    for case in cases {
        let answer = dispatch(&case["args"]).expect("verdict");
        assert_eq!(
            applied(&answer, &case["args"]["identity"]),
            case["verdict"],
            "{}",
            case["name"]
        );
    }
}

fn healthy() -> Value {
    cases()
        .into_iter()
        .find(|case| case["name"] == "healthy install")
        .expect("healthy case")["args"]
        .clone()
}

fn reason(args: &Value) -> Value {
    dispatch(args).expect("verdict")["reason"].clone()
}

#[test]
fn python_only_json_reads_as_unparseable() {
    let mut args = healthy();
    args["state_text"] = json!("{\"guard_cli_identity\": NaN}");
    assert_eq!(reason(&args), "guard_cursor_hook_state_missing");
    let mut args = healthy();
    args["hooks_text"] = json!("{\"hooks\": {}, \"x\": Infinity}");
    assert_eq!(reason(&args), "guard_cursor_hook_registration_missing");
}

#[test]
fn every_unknown_event_disables_the_file() {
    let base = healthy();
    for (event, unsupported) in [
        ("beforeWriteFile", true),
        ("beforeEditFile", true),
        ("BeforeShellExecution", true),
        ("stop", false),
        ("workspaceOpen", false),
        ("postToolUseFailure", false),
    ] {
        let mut args = base.clone();
        let mut hooks: Value =
            serde_json::from_str(args["hooks_text"].as_str().expect("hooks")).expect("hooks json");
        hooks["hooks"][event] = json!([]);
        args["hooks_text"] = json!(hooks.to_string());
        let expected = if unsupported {
            json!("guard_cursor_hook_unsupported_event")
        } else {
            Value::Null
        };
        assert_eq!(reason(&args), expected, "{event}");
    }
}

#[test]
fn numbers_compare_as_python_values() {
    let base = healthy();
    for (spelled, equal) in [
        (json!(1), true),
        (json!(1.0), true),
        (json!(true), true),
        (serde_json::from_str::<Value>("1e0").expect("number"), true),
        (
            serde_json::from_str::<Value>("100e-2").expect("number"),
            true,
        ),
        (json!(-0.0), false),
        (json!(1.000_000_1), false),
        (json!(false), false),
        (json!("1"), false),
        (json!([1]), false),
    ] {
        let mut identity = base["identity"].clone();
        identity["schema_version"] = spelled.clone();
        let mut args = base.clone();
        let mut state: Value =
            serde_json::from_str(args["state_text"].as_str().expect("state")).expect("state json");
        state["guard_cli_identity"] = identity;
        args["state_text"] = json!(state.to_string());
        let expected = if equal {
            Value::Null
        } else {
            json!("guard_cursor_cli_identity_mismatch")
        };
        assert_eq!(reason(&args), expected, "{spelled}");
    }
}

#[test]
fn large_integers_compare_exactly() {
    let base = healthy();
    for (identity, state, equal) in [
        ("9007199254740993", "9007199254740992.0", false),
        ("9007199254740992", "9007199254740992.0", true),
        (
            "123456789012345678901234567890",
            "123456789012345678901234567890",
            true,
        ),
        ("1", "1e400", false),
    ] {
        let mut args = base.clone();
        args["identity"] = serde_json::from_str(identity).expect("identity");
        args["state_text"] = json!(format!(
            "{{\"guard_cli_identity\": {state}, \"hook_script_sha256\": 0}}"
        ));
        let expected = if equal {
            "guard_cursor_hook_script_identity_stale"
        } else {
            "guard_cursor_cli_identity_mismatch"
        };
        assert_eq!(reason(&args), expected, "{identity} {state}");
    }
}

#[test]
fn malformed_arguments_are_refused() {
    let base = healthy();
    let mut refusals: Vec<Value> = Vec::new();
    for key in [
        "source",
        "identity",
        "state_text",
        "scripts",
        "hooks_text",
        "entries",
    ] {
        let mut args = base.clone();
        args.as_object_mut().expect("args").remove(key);
        refusals.push(args);
    }
    let mut extra = base.clone();
    extra["op"] = json!("state");
    refusals.push(extra);
    for (key, value) in [
        ("source", json!(null)),
        ("state_text", json!(false)),
        ("state_text", json!(7)),
        ("scripts", json!([null])),
        ("scripts", json!([null, null, null])),
        ("scripts", json!([{"regular": true}, null])),
        ("scripts", json!([{"regular": 1, "text": ""}, null])),
        (
            "scripts",
            json!([{"regular": true, "text": "", "x": 1}, null]),
        ),
        ("scripts", json!([true, null])),
        ("hooks_text", json!(true)),
        ("hooks_text", json!({})),
        ("entries", json!([])),
    ] {
        let mut args = base.clone();
        args[key] = value;
        refusals.push(args);
    }
    let mut missing_event = base.clone();
    missing_event["entries"]
        .as_object_mut()
        .expect("entries")
        .remove("preToolUse");
    refusals.push(missing_event);
    for (event, value) in [("preToolUse", json!(null)), ("stop", json!({}))] {
        let mut args = base.clone();
        args["entries"][event] = value;
        refusals.push(args);
    }
    refusals.push(json!([]));
    for args in refusals {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
