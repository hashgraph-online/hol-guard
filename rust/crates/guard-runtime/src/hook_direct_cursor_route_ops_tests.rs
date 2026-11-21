use serde_json::{json, Value};

use super::{probe_response, route_name};

fn route_of(payload: Value) -> &'static str {
    route_name(payload.as_object().expect("object"))
}

const ALLOW: fn() -> Value = || json!({"policy_action": "allow"});

fn shell(extra: Value) -> Value {
    let mut payload = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Shell",
        "tool_input": {"command": "pytest -q"},
    });
    for (key, value) in extra.as_object().unwrap() {
        payload[key] = value.clone();
    }
    payload
}

#[cfg(unix)]
#[test]
fn native_route_requests_the_binding_only_for_a_scoped_probe() {
    use crate::policy_store::policy_store_direct_lane::tests::fixture;

    let fixture = fixture("cursor-route-answer");
    let mut params = json!({
        "payload": shell(json!({"cursor_route_probe": true})),
        "guard_home": fixture.root,
        "home_dir": fixture.root,
        "workspace": fixture.root,
        "sink_command": ["guard"],
        "native_sink": true,
    });
    let review = |params: &Value| {
        super::answer(
            params.as_object().unwrap(),
            "hook-render-cursor",
            Some(&fixture.store),
        )
        .map(Value::Object)
    };
    assert_eq!(
        review(&params).unwrap(),
        json!({"value": ALLOW(), "needs_binding": true})
    );
    params["snapshot"] = json!({"generation": 1});
    params["probe_budget_ms"] = json!(500);
    assert_eq!(
        review(&params).unwrap(),
        json!({"value": ALLOW(), "needs_binding": false})
    );
    params["payload"] = shell(json!({}));
    assert_eq!(
        review(&params).unwrap(),
        json!({"value": null, "needs_binding": false})
    );
    params["guard_home"] = json!(fixture.root.join("another-home"));
    assert_eq!(review(&params), Err("native_hook_render_invalid"));
}

#[cfg(unix)]
#[test]
fn native_probe_reviews_the_admitted_policy_and_observes_watch() {
    use crate::policy_store::policy_store_direct_lane::tests::{fixture, push};

    let fixture = fixture("cursor-probe-binding");
    push(&fixture, None).unwrap();
    let envelope: guard_contracts::GuardHookEnvelopeV2 = crate::strict_json::from_value(json!({
        "schema": guard_contracts::GUARD_HOOK_ENVELOPE_V2_SCHEMA,
        "request_id": "cursor-probe",
        "harness": "cursor",
        "event": "PreToolUse",
        "raw_payload": shell(json!({
            "cursor_route_probe": true,
            "cwd": fixture.root,
            "tool_input": {"command": "pytest -q", "cwd": fixture.root},
        })),
        "policy_generation": fixture.snapshot.generation,
        "policy_snapshot": {
            "generation": fixture.snapshot.generation,
            "policy_digest": fixture.snapshot.policy_digest,
            "runtime_identity": fixture.snapshot.runtime_identity,
        },
        "deadline_budget_ms": 1000,
        "source": {"cwd": fixture.root, "home_dir": fixture.root, "guard_home": fixture.root},
        "containment_sink": {"sink_command": ["guard"], "native_sink": true},
    }))
    .unwrap();
    let watched = json!({"cursor": "watch"});
    assert!(
        crate::edge::evaluate_cursor_probe(envelope.clone(), &fixture.store, Some(&watched))
            .unwrap()
            .is_none()
    );
    let bytes = crate::edge::evaluate_cursor_probe(envelope, &fixture.store, None)
        .unwrap()
        .expect("an enforcing probe goes to the native edge");
    let edge: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(edge["schema"], "guard-hook-edge-result.v2");
    assert_eq!(edge["harness"], "cursor");
}

#[cfg(not(windows))]
#[test]
fn only_cursors_own_shell_pretooluse_is_a_probe() {
    assert_eq!(
        route_of(shell(json!({"cursor_route_probe": true}))),
        "probe"
    );
    // A Shell call another hook sends for Cursor keeps its ordinary review.
    assert_eq!(route_of(shell(json!({}))), "review");
    assert_eq!(
        route_of(shell(json!({"cursor_route_probe": "true"}))),
        "review"
    );
    assert_eq!(
        route_of(shell(json!({
            "cursor_route_probe": true,
            "cursor_source_hook_event": "beforeShellExecution",
        }))),
        "review"
    );
    assert_eq!(
        route_of(shell(
            json!({"cursor_route_probe": true, "tool_name": "Write"})
        )),
        "review"
    );
    assert_eq!(
        route_of(shell(
            json!({"cursor_route_probe": true, "hook_event_name": "PostToolUse"})
        )),
        "review"
    );
}

#[cfg(not(windows))]
#[test]
fn a_before_shell_call_naming_the_sink_is_a_sink() {
    let named = |command: &str, source: &str| {
        shell(json!({
            "cursor_source_hook_event": source,
            "tool_input": {"command": command},
        }))
    };
    assert_eq!(
        route_of(named(
            "guard execute-contained-test --harness cursor",
            "beforeShellExecution"
        )),
        "sink"
    );
    assert_eq!(
        route_of(named(
            "/opt/hol/runtime contained-workspace-sink",
            "beforeShellExecution"
        )),
        "sink"
    );
    assert_eq!(
        route_of(named("pytest -q", "beforeShellExecution")),
        "review"
    );
    assert_eq!(
        route_of(named("guard execute-contained-test", "preToolUse")),
        "review"
    );
}

#[cfg(not(windows))]
#[test]
fn a_receipt_only_call_is_reviewed_as_usual() {
    let probe = shell(json!({
        "cursor_route_probe": true,
        "guard_containment_receipt_only": true,
    }));
    assert_eq!(route_of(probe), "review");
    let null = shell(json!({
        "cursor_route_probe": true,
        "guard_containment_receipt_only": null,
    }));
    assert_eq!(route_of(null), "probe");
}

#[cfg(windows)]
#[test]
fn windows_is_never_routed() {
    assert_eq!(
        route_of(shell(json!({"cursor_route_probe": true}))),
        "review"
    );
}

#[test]
fn a_probe_the_edge_did_not_answer_is_a_plain_allow() {
    assert_eq!(probe_response(None), ALLOW());
    assert_eq!(probe_response(Some(&Value::Null)), ALLOW());
}

#[test]
fn a_probe_the_edge_does_not_route_to_the_sink_is_a_plain_allow() {
    for route in ["none", "grant"] {
        let edge = json!({
            "containment_route": route,
            "containment_rewrite": "routed",
            "harness_response": {"policy_action": "allow", "reason_code": "native_contained_execution_routed"},
        });
        assert_eq!(probe_response(Some(&edge)), ALLOW());
    }
    assert_eq!(probe_response(Some(&json!({}))), ALLOW());
}

#[test]
fn a_routed_probe_answer_is_the_edges_own() {
    let routed = json!({
        "policy_action": "allow",
        "reason_code": "native_contained_execution_routed",
        "hookSpecificOutput": {"updatedInput": {"command": "guard execute-contained-test", "cwd": "/w"}},
    });
    let edge = json!({
        "containment_route": "sink",
        "containment_rewrite": "routed",
        "harness_response": routed,
    });
    assert_eq!(probe_response(Some(&edge)), routed);
}

#[test]
fn a_probe_the_edge_keeps_is_its_plain_allow() {
    let edge = json!({
        "containment_route": "sink",
        "containment_rewrite": "kept",
        "harness_response": {"policy_action": "allow"},
    });
    assert_eq!(probe_response(Some(&edge)), ALLOW());
}

#[test]
fn an_edge_answer_that_is_not_a_probe_answer_is_a_plain_allow() {
    let blocked = json!({
        "policy_action": "block",
        "decision": "deny",
        "reason_code": "native_contained_execution_required",
    });
    for (mark, response) in [
        ("kept", blocked.clone()),
        ("routed", json!({"policy_action": "allow"})),
        (
            "routed",
            json!({"policy_action": "block", "reason_code": "native_contained_execution_routed"}),
        ),
        (
            "other",
            json!({"policy_action": "allow", "reason_code": "native_contained_execution_routed"}),
        ),
    ] {
        let edge = json!({
            "containment_route": "sink",
            "containment_rewrite": mark,
            "harness_response": response,
        });
        assert_eq!(probe_response(Some(&edge)), ALLOW());
    }
    // No rewrite mark, or a response that is not an object, is no probe answer.
    for edge in [
        json!({"containment_route": "sink", "harness_response": {"policy_action": "allow"}}),
        json!({"containment_route": "sink", "containment_rewrite": "kept", "harness_response": "allow"}),
    ] {
        assert_eq!(probe_response(Some(&edge)), ALLOW());
    }
}
