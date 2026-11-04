use serde_json::{json, Value};

use crate::cloud_sync_privacy::cloud_review_event_display;
use crate::runner_authority_op::ERR_INVALID;

fn row() -> Value {
    json!({
        "request_id": "r1",
        "harness": "codex",
        "policy_action": "allow",
        "command_text": "echo hi",
        "created_at": "2026-11-04T01:00:00+00:00",
    })
}

fn facts() -> Value {
    json!({
        "sequence": 4,
        "event_type": "request_created",
        "claim": null,
        "continuation": {
            "correlationId": "corr-1",
            "capability": "native_resume",
            "hookAttached": true,
            "opaqueTargetId": "target-1",
            "waitDeadline": null,
            "offeredAt": "not sent",
        },
        "now": "2026-11-04T02:00:00+00:00",
        "columns": {
            "updated_at": null,
            "guard_version": "3.60.0",
            "first_seen_guard_version": "",
            "last_seen_guard_version": 7,
        },
    })
}

fn assemble(item: Value, facts: Value) -> Result<Value, &'static str> {
    let answer = cloud_review_event_display(&json!({
        "item": item,
        "redaction_level": "none",
        "event": facts,
    }))?;
    let fields = answer.as_object().expect("answer");
    assert_eq!(fields.len(), 1);
    Ok(answer["event"].clone())
}

#[test]
fn the_event_carries_the_display_answer_and_the_row_facts() {
    let display = cloud_review_event_display(&json!({"item": row(), "redaction_level": "none"}))
        .expect("display");
    let event = assemble(row(), facts()).expect("event");
    for (field, key) in [
        ("displayProvenance", "display_provenance"),
        ("displayCommand", "display_command"),
        ("displaySummary", "display_summary"),
        ("rawCommand", "raw_command"),
        ("redactedCommand", "redacted_command"),
        ("requestPayload", "payload"),
    ] {
        assert_eq!(event[field], display[key], "{field}");
    }
    assert_eq!(event["rawCommand"], "echo hi");
    assert_eq!(
        event,
        json!({
            "localRequestId": "r1",
            "correlationId": "corr-1",
            "localEventSequence": 4,
            "eventType": "request_created",
            "harnessId": "codex",
            "requestKind": "codex",
            "displayProvenance": display["display_provenance"],
            "displayCommand": display["display_command"],
            "displaySummary": display["display_summary"],
            "rawCommand": "echo hi",
            "redactedCommand": null,
            "reviewClaim": null,
            "requestPayload": display["payload"],
            "continuationCapability": "native_resume",
            "continuationHookAttached": true,
            "continuationOpaqueTargetId": "target-1",
            "continuationWaitDeadline": null,
            "riskCategory": null,
            "policyAction": "allow",
            "recommendedScope": null,
            "localCreatedAt": "2026-11-04T01:00:00+00:00",
            "localUpdatedAt": "2026-11-04T01:00:00+00:00",
            "localLastSeenAt": "2026-11-04T01:00:00+00:00",
            "guardVersion": "3.60.0",
            "firstSeenGuardVersion": null,
            "lastSeenGuardVersion": "7",
            "localEmittedAt": "2026-11-04T02:00:00+00:00",
            "sentAt": "2026-11-04T02:00:00+00:00",
        })
    );
}

#[test]
fn falsy_columns_fall_back_the_way_python_did() {
    let mut facts = facts();
    facts["claim"] = json!({"claimId": "c-1"});
    facts["columns"]["updated_at"] = json!("2026-11-04T03:00:00+00:00");
    let item = json!({
        "request_id": "r2",
        "review_kind": "approval",
        "policy_action": "allow",
        "created_at": "",
        "risk_category": 0,
        "recommended_scope": true,
    });
    let event = assemble(item, facts.clone()).expect("event");
    assert_eq!(event["harnessId"], "guard-review");
    assert_eq!(event["requestKind"], "approval");
    assert_eq!(event["localCreatedAt"], "2026-11-04T02:00:00+00:00");
    assert_eq!(event["localLastSeenAt"], "2026-11-04T02:00:00+00:00");
    assert_eq!(event["localUpdatedAt"], "2026-11-04T03:00:00+00:00");
    assert_eq!(event["riskCategory"], Value::Null);
    assert_eq!(event["recommendedScope"], "True");
    assert_eq!(event["reviewClaim"], json!({"claimId": "c-1"}));

    let bare =
        assemble(json!({"request_id": "r3", "policy_action": "allow"}), facts).expect("event");
    assert_eq!(bare["requestKind"], "guard-review");
}

#[test]
fn malformed_event_facts_are_refused() {
    let mut cases = Vec::new();
    for (path, value) in [
        ("sequence", json!("4")),
        ("sequence", json!(true)),
        ("sequence", json!(1.5)),
        ("event_type", json!("")),
        ("now", Value::Null),
        ("claim", json!("claim")),
        ("continuation", json!([])),
        ("columns", json!({"updated_at": null})),
    ] {
        let mut facts = facts();
        facts[path] = value;
        cases.push((row(), facts));
    }
    let mut missing = facts();
    let offer = missing["continuation"].as_object_mut().expect("offer");
    offer.remove("waitDeadline");
    cases.push((row(), missing));
    let mut extra = facts();
    extra["extra"] = json!(1);
    cases.push((row(), extra));
    let mut listed = row();
    listed["harness"] = json!(["codex"]);
    cases.push((listed, facts()));
    cases.push((row(), json!([])));
    for (item, facts) in cases {
        assert_eq!(assemble(item, facts.clone()), Err(ERR_INVALID), "{facts}");
    }
}
