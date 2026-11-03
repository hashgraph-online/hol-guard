//! Transport binding, typed rejection, and size checks for `HookAdapter`.

use guard_contracts::HOOK_ADAPTER_REQUEST_SCHEMA;
use serde_json::{json, Value};

fn resident(request: Value) -> Result<Value, String> {
    crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

fn envelope(schema: &str, query: Value) -> Value {
    json!({
        "operation": "hook_adapter",
        "request": {"schema": schema, "request_id": "req-adapter", "query": query},
    })
}

fn host() -> Value {
    json!({"tilde_home": "/home/u", "default_home": "/home/u", "cwd": "/work"})
}

#[test]
fn binds_the_request_and_answers_command_detail() {
    let reply = resident(envelope(
        HOOK_ADAPTER_REQUEST_SCHEMA,
        json!({"kind": "command_detail", "text": "echo hi", "home_dir": null, "host": host()}),
    ))
    .unwrap();
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["code"], "ok");
    assert_eq!(reply["schema"], "guard-hook-adapter-result.v1");
    assert_eq!(reply["request_id"], "req-adapter");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(reply["payload"]["text"], "echo hi");
}

#[test]
fn rejects_wrong_schema_and_unknown_fields() {
    let query = json!({"kind": "apply_patch_paths", "tool_input": ["d"]});
    assert_eq!(
        resident(envelope("bogus", query.clone())).unwrap_err(),
        "native_hook_adapter_schema_mismatch"
    );
    let surprise = json!({"kind": "apply_patch_paths", "tool_input": ["d"], "surprise": true});
    assert!(resident(envelope(HOOK_ADAPTER_REQUEST_SCHEMA, surprise)).is_err());
}

#[test]
fn unsupported_harness_is_a_typed_rejection() {
    let reply = resident(envelope(
        HOOK_ADAPTER_REQUEST_SCHEMA,
        json!({
            "kind": "action_envelope",
            "harness": "no-such",
            "event_name": "PreToolUse",
            "payload": ["d"],
            "workspace": null,
            "home_dir": null,
            "devin_project_dir": null,
            "path_env": null,
            "host": host(),
        }),
    ))
    .unwrap();
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], "native_hook_adapter_unsupported_harness");
    assert_eq!(reply["payload"], json!({"harness": "no-such"}));
}

#[test]
fn malformed_wire_values_fail_closed() {
    let reply = resident(envelope(
        HOOK_ADAPTER_REQUEST_SCHEMA,
        json!({"kind": "prepare_payload", "harness": "codex", "payload": ["d", "key"], "devin_project_dir": null}),
    ))
    .unwrap();
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["payload"], Value::Null);
    assert!(reply["code"]
        .as_str()
        .unwrap()
        .starts_with("native_hook_adapter_"));
}

#[test]
fn preparation_keeps_payload_key_order() {
    let reply = resident(envelope(
        HOOK_ADAPTER_REQUEST_SCHEMA,
        json!({
            "kind": "prepare_payload",
            "harness": "codex",
            "payload": ["d", "zeta", 1, "alpha", 2],
            "devin_project_dir": null,
        }),
    ))
    .unwrap();
    assert_eq!(reply["status"], "ok");
    let keys: Vec<&str> = reply["payload"]
        .as_array()
        .unwrap()
        .iter()
        .skip(1)
        .step_by(2)
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(keys, ["zeta", "alpha"]);
}

#[test]
fn oversized_answers_become_a_typed_error() {
    let huge = "a".repeat(1_100_000);
    let command = format!("echo {huge}");
    let reply = resident(envelope(
        HOOK_ADAPTER_REQUEST_SCHEMA,
        json!({"kind": "command_detail", "text": command, "home_dir": null, "host": host()}),
    ));
    // The wire parser caps strings at 1 MiB, so either layer must refuse.
    assert!(reply.is_err() || reply.unwrap()["status"] == "error");
}

#[test]
fn byte_exact_oversize_echoes_travel_as_digest_references() {
    let big = "q".repeat(70_000);
    let reply = resident(envelope(
        HOOK_ADAPTER_REQUEST_SCHEMA,
        json!({
            "kind": "prepare_payload",
            "harness": "codex",
            "payload": ["d", "blob", big, "small", "kept"],
            "devin_project_dir": null,
        }),
    ))
    .unwrap();
    assert_eq!(reply["status"], "ok");
    let body = reply["payload"].as_array().unwrap();
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(big.as_bytes()));
    assert_eq!(body[2], json!(["r", digest]));
    assert_eq!(body[4], "kept");
}

#[test]
fn many_small_strings_over_the_response_cap_fail_closed() {
    let mut payload = vec![json!("d")];
    for index in 0..40 {
        payload.push(json!(format!("k{index}")));
        payload.push(json!(format!("{index:02}{}", "z".repeat(60_000))));
    }
    let reply = resident(envelope(
        HOOK_ADAPTER_REQUEST_SCHEMA,
        json!({
            "kind": "prepare_payload",
            "harness": "codex",
            "payload": payload,
            "devin_project_dir": null,
        }),
    ))
    .unwrap();
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], "native_hook_adapter_response_too_large");
}

#[test]
fn chunked_strings_are_rejoined_and_malformed_chunks_fail_closed() {
    let prepare = |payload: Value| {
        resident(envelope(
            HOOK_ADAPTER_REQUEST_SCHEMA,
            json!({"kind": "prepare_payload", "harness": "codex", "payload": payload, "devin_project_dir": null}),
        ))
        .unwrap()
    };
    let joined = prepare(json!(["d", "blob", ["c", "ab", "", "cd"]]));
    assert_eq!(joined["status"], "ok");
    assert_eq!(joined["payload"], json!(["d", "blob", "abcd"]));
    let part = "p".repeat(300_000);
    let long = prepare(json!(["d", "blob", ["c", part, part, part, part]]));
    assert_eq!(long["status"], "ok");
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(
        part.repeat(4).as_bytes(),
    ));
    assert_eq!(long["payload"], json!(["d", "blob", ["r", digest]]));
    for bad in [json!(["c", 1]), json!(["c", ["l"]])] {
        let reply = prepare(json!(["d", "blob", bad]));
        assert_eq!(reply["status"], "error");
        assert_eq!(reply["code"], "native_hook_adapter_wire_invalid");
    }
}

#[test]
fn command_text_echoes_of_oversize_commands_travel_as_references() {
    let command = format!("echo {}", "a".repeat(200_000));
    let reply = resident(envelope(
        HOOK_ADAPTER_REQUEST_SCHEMA,
        json!({
            "kind": "command_text",
            "tool_name": "Bash",
            "tool_input": ["d", "command", command],
        }),
    ))
    .unwrap();
    assert_eq!(reply["status"], "ok");
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(command.as_bytes()));
    assert_eq!(reply["payload"]["text"], json!(["r", digest]));
    let short = resident(envelope(
        HOOK_ADAPTER_REQUEST_SCHEMA,
        json!({"kind": "command_text", "tool_name": "Bash", "tool_input": ["d", "command", "echo hi"]}),
    ))
    .unwrap();
    assert_eq!(short["payload"]["text"], "echo hi");
}
