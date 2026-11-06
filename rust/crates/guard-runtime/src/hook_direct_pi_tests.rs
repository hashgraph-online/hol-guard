use super::{
    allowed_payload, allowing_lane, deferred, drain, lane, post_tool_payload, prompt_payload,
    run_as, Lane, HOME,
};
use crate::hook_direct::pi::{resolution, source_ref_external_allowed, structured_mediation};
use serde_json::{json, Value};

const VECTORS: &str = include_str!("../testdata/hook_direct_pi/pi_vectors.json");

fn vectors(group: &str) -> Vec<Value> {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let group = vectors[group].as_array().unwrap().clone();
    assert!(!group.is_empty());
    group
}

#[test]
fn the_source_ref_flag_follows_the_recorded_daemon_rule() {
    for vector in vectors("source_ref_external_allowed") {
        let harness = vector["harness"].as_str().unwrap();
        assert_eq!(
            source_ref_external_allowed(harness),
            vector["allowed"].as_bool().unwrap(),
            "{harness:?}"
        );
    }
}

#[test]
fn structured_mediation_follows_the_recorded_daemon_rule() {
    for vector in vectors("structured_mediation") {
        let harness = vector["harness"].as_str().unwrap();
        let event = vector["event"].as_str().unwrap();
        assert_eq!(
            structured_mediation(harness, event),
            vector["mediated"].as_bool().unwrap(),
            "{harness:?} {event}"
        );
    }
}

#[test]
fn a_pi_lifecycle_hook_gets_the_recorded_daemon_constant() {
    let lane = lane("pi-lifecycle", json!({}));
    for vector in vectors("lifecycle") {
        let harness = vector["harness"].as_str().unwrap();
        let event = vector["event"].as_str().unwrap();
        let payload = json!({ "hook_event_name": event, "session_id": "synthetic" });
        let result = run_as(&lane, harness, Some(HOME), payload);
        assert_eq!(result["outcome"], "answer", "{harness} {event}: {result}");
        assert_eq!(
            result["edge"],
            json!({ "harness_response": vector["response"] }),
            "{harness} {event}"
        );
    }
    assert_eq!(drain(&lane, None)["records"], json!([]));
}

#[test]
fn a_pi_tool_hook_is_answered_with_the_daemon_source_flag() {
    for harness in ["pi", "omp"] {
        let lane = allowing_lane(&format!("pi-pre-{harness}"), json!({}));
        // The extension names no event for a tool call, and sends its budget.
        let payload = json!({
            "tool_name": "bash",
            "tool_input": { "command": "pwd" },
            "cwd": lane.workspace,
            "guard_remaining_ms": 4_000,
        });
        let result = run_as(&lane, harness, Some(HOME), payload);
        assert_eq!(result["outcome"], "answer", "{harness}: {result}");
        let edge = &result["edge"];
        assert_eq!(
            edge["receipt"]["source_ref_external_allowed"], true,
            "{harness}"
        );
        let page = drain(&lane, None);
        let record = &page["records"][0];
        assert_eq!(record["harness"], harness);
        assert_eq!(record["event"], "PreToolUse");
        assert_eq!(record["harness_response"], edge["harness_response"]);
        assert_eq!(record["receipt"], edge["receipt"]);
    }
    let codex = allowing_lane("pi-pre-codex", json!({}));
    let result = run_as(&codex, "codex", Some(HOME), allowed_payload(&codex));
    assert_eq!(
        result["edge"]["receipt"]["source_ref_external_allowed"],
        false
    );
}

#[test]
fn a_pi_prompt_is_answered_with_the_daemon_source_flag() {
    for harness in ["pi", "omp"] {
        let lane = lane(&format!("pi-prompt-{harness}"), json!({}));
        let result = run_as(&lane, harness, Some(HOME), prompt_payload(&lane));
        assert_eq!(result["outcome"], "answer", "{harness}: {result}");
        assert_eq!(
            result["edge"]["receipt"]["source_ref_external_allowed"],
            true
        );
        let page = drain(&lane, None);
        assert_eq!(page["records"][0]["harness"], harness);
        assert_eq!(page["records"][0]["event"], "UserPromptSubmit");
    }
}

/// The view the publisher binds for a recorded managed policy.
fn structured_output_view(policy: &str) -> Value {
    vectors("structured_output")
        .into_iter()
        .find(|vector| vector["policy"] == policy)
        .map(|vector| vector["view"].clone())
        .unwrap()
}

#[test]
fn the_resident_resolves_the_bound_view_as_the_daemon_resolves_the_config() {
    let vectors = vectors("structured_output");
    assert!(vectors.iter().any(|vector| vector["view"].is_null()));
    for vector in vectors {
        let harness = vector["harness"].as_str().unwrap();
        let view = &vector["view"];
        let policy = &vector["policy"];
        let Some(resolved) = resolution(harness, (!view.is_null()).then_some(view)) else {
            // An unbound view resolves to nothing, and the hook defers.
            assert!(view.is_null(), "{policy} {harness}");
            continue;
        };
        // `unchanged` records that the daemon returned the edge response as
        // it was, which is exactly where it required no mediation.
        assert_eq!(
            resolved["required"].as_bool() == Some(false),
            vector["unchanged"].as_bool().unwrap(),
            "{policy} {harness}"
        );
    }
    // A view that is not `_config_wire`'s shape is not resolved.
    let mut view = structured_output_view("absent");
    view["extra"] = json!(true);
    assert!(resolution("pi", Some(&view)).is_none());
    let mut view = structured_output_view("absent");
    view.as_object_mut().unwrap().remove("managed_policy");
    assert!(resolution("pi", Some(&view)).is_none());
    assert!(resolution("pi", Some(&Value::Null)).is_none());
    assert!(resolution("pi", Some(&json!([]))).is_none());
    assert!(resolution("pi", None).is_none());
}

#[test]
fn a_pi_post_tool_use_is_answered_when_no_mediation_is_required() {
    for harness in ["pi", "omp"] {
        let config = json!({ "structured_output_config": structured_output_view("absent") });
        let lane = lane(&format!("pi-post-{harness}"), config);
        let result = run_as(&lane, harness, Some(HOME), post_tool_payload(&lane));
        assert_eq!(result["outcome"], "answer", "{harness}: {result}");
        assert_eq!(result["edge"]["event_name"], "PostToolUse", "{harness}");
        // Nothing is required, so the response carries no mediation at all.
        assert_eq!(
            result["edge"]["harness_response"]["structured_content_mediation"],
            Value::Null,
            "{harness}"
        );
        let page = drain(&lane, None);
        let records = page["records"].as_array().unwrap();
        assert_eq!(records.len(), 1, "{harness}");
        assert_eq!(records[0]["harness"], harness);
        assert_eq!(records[0]["event"], "PostToolUse");
        assert_eq!(
            records[0]["harness_response"],
            result["edge"]["harness_response"]
        );
    }
}

/// A Pi `read` of `guide.txt` in the workspace, carrying the extension's
/// source reference to the file the tool returned.
fn source_read_payload(lane: &Lane, content: &str) -> Value {
    let path = format!("{}/guide.txt", lane.workspace);
    std::fs::write(&path, content).unwrap();
    json!({
        "hook_event_name": "PostToolUse",
        "tool_name": "read",
        "tool_input": { "path": path },
        "tool_response": { "content": content },
        "tool_response_summary": { "excerpt_truncated": false },
        "guard_source_ref": {
            "version": 1,
            "path": path,
            "tool_input_path": path,
            "output_sha256": guard_hook_core::sha256_text(content),
            "output_chars": content.chars().count(),
        },
        "cwd": lane.workspace,
    })
}

#[test]
fn a_pi_post_tool_use_source_reference_is_reviewed_by_the_resident() {
    let token = format!("{}{}", ["gh", "p_"].concat(), "b".repeat(30));
    for harness in ["pi", "omp"] {
        // The allowing policy keeps the source scan's own reason; the default
        // fixture's warn floor would turn a clean read into the silent warning.
        let config = json!({ "structured_output_config": structured_output_view("absent") });
        let lane = allowing_lane(&format!("pi-source-{harness}"), config);
        let mut acked: Option<Value> = None;
        for (content, reason) in [
            ("ordinary notes\n".to_owned(), "source_full_scan_allow"),
            (format!("token = '{token}'\n"), "source_secret_match"),
        ] {
            let result = run_as(
                &lane,
                harness,
                Some(HOME),
                source_read_payload(&lane, &content),
            );
            assert_eq!(result["outcome"], "answer", "{harness}: {result}");
            assert_eq!(
                result["edge"]["result"]["reason_code"], reason,
                "{harness}: {result}"
            );
            let page = drain(&lane, acked.as_ref());
            let records = page["records"].as_array().unwrap();
            assert_eq!(records.len(), 1, "{harness} {reason}");
            assert_eq!(
                records[0]["harness_response"],
                result["edge"]["harness_response"]
            );
            acked = Some(page);
        }
        let mut encrypted = post_tool_payload(&lane);
        encrypted["guard_payload_ref"] = json!({ "path": "/tmp/payload.bin" });
        let result = run_as(&lane, harness, Some(HOME), encrypted);
        assert_eq!(deferred(&result), "direct_hook_payload_unsupported");
        let before = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "read",
            "tool_input": { "path": "guide.txt" },
            "guard_source_ref": { "path": "guide.txt" },
            "cwd": lane.workspace,
        });
        let result = run_as(&lane, harness, Some(HOME), before);
        assert_eq!(deferred(&result), "direct_hook_payload_unsupported");
    }
}

#[test]
fn a_pi_post_tool_use_takes_the_daemon_path_without_a_bound_view() {
    let unbound = lane("pi-post-unbound", json!({}));
    let result = run_as(&unbound, "pi", Some(HOME), post_tool_payload(&unbound));
    assert_eq!(deferred(&result), "direct_hook_structured_mediation");
    assert_eq!(drain(&unbound, None)["records"], json!([]));
    // Another harness's `PostToolUse` never resolves the view.
    let codex = lane(
        "pi-post-codex",
        json!({ "structured_output_config": structured_output_view("tampered") }),
    );
    let result = run_as(&codex, "codex", Some(HOME), post_tool_payload(&codex));
    assert_eq!(result["outcome"], "answer", "{result}");
    assert_eq!(
        result["edge"]["harness_response"]["structured_content_mediation"],
        Value::Null
    );
}

#[test]
fn a_pi_post_tool_use_the_managed_policy_covers_is_mediated_by_the_resident() {
    // A `pwd` carries no structured output the resident can prove clean, so
    // every covered policy withholds it rather than forwarding.
    for (label, harness, policy) in [
        ("pi-post-required", "omp", "active_locked_omp"),
        ("pi-post-tampered", "pi", "tampered"),
    ] {
        let config = json!({ "structured_output_config": structured_output_view(policy) });
        let lane = lane(label, config);
        let result = run_as(&lane, harness, Some(HOME), post_tool_payload(&lane));
        assert_eq!(result["outcome"], "answer", "{label}: {result}");
        let mediation = &result["edge"]["harness_response"]["structured_content_mediation"];
        assert_eq!(
            mediation["schema"], "guard-structured-content-mediation.v1",
            "{label}: {result}"
        );
        assert_eq!(mediation["action"], "withhold", "{label}: {result}");
        assert!(
            mediation["reason_code"]
                .as_str()
                .is_some_and(|reason| reason.starts_with("structured_")),
            "{label}: {result}"
        );
        assert_eq!(mediation["content_sha256"], Value::Null, "{label}");
        // The evidence the daemon drains carries the mediated response.
        let page = drain(&lane, None);
        let records = page["records"].as_array().unwrap();
        assert_eq!(records.len(), 1, "{label}");
        assert_eq!(
            records[0]["harness_response"], result["edge"]["harness_response"],
            "{label}"
        );
    }
}
