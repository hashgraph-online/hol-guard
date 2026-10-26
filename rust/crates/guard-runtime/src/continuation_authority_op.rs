//! Fused continuation evidence projection; no transport or delivery lease ownership.
use super::runner_authority_op::{KindResult, ERR_INVALID};
use serde_json::{json, Value};

fn text(value: &Value) -> Option<&str> {
    value
        .as_str()
        .map(super::guard_store_json::py_strip)
        .filter(|s| !s.is_empty())
}
fn status(value: &str) -> &str {
    match value {
        "waiting" => "pending",
        "resumed" => "sent",
        "already_resumed" => "already_sent",
        "blocked_not_resumed" => "blocked",
        other => other,
    }
}
fn digest(value: &Value) -> Result<String, &'static str> {
    let mut bytes = Vec::new();
    super::context_digest_json::write_canonical_json(value, &mut bytes)?;
    Ok(guard_policy_snapshot::digest_bytes(&bytes))
}
fn offer_hash(offer: &Value, identity: bool) -> Result<String, &'static str> {
    let mut value = json!({"capability":offer["capability"], "contractVersion":offer["contract_version"],
        "harness":offer["harness"], "hookAttached":offer["original_hook_attached"], "target":offer["opaque_target_id"]});
    value[if identity { "deadline" } else { "waitDeadline" }] = offer["wait_deadline"].clone();
    if !identity {
        value["correlationId"] = offer["correlation_id"].clone();
    }
    digest(&value)
}
fn message(value: &str) -> Value {
    match value {
        "waiting" => json!("Decision saved. Codex is still waiting for this browser decision, so HOL Guard will let the original Codex action continue without starting a second headless run."),
        "manual_retry_required" => json!("Decision recorded for the original request. HOL Guard could not find the original Codex chat to resume. Return to that chat and retry; a new tool call may require fresh approval."),
        "failed" => json!("Decision recorded for the original request. HOL Guard could not send a continuation to the original Codex chat. Return to that chat and retry; a new tool call may require fresh approval."),
        "blocked_not_resumed" => json!("Decision saved. HOL Guard blocked this Codex request and will not resume or retry it. Do not retry that action in Codex. Ask for a safe alternative instead."),
        _ => Value::Null,
    }
}
pub(crate) fn evaluate(args: &Value) -> KindResult {
    match args["call"].as_str().ok_or(ERR_INVALID)? {
        "project" => project(args),
        "snapshot" => Ok(json!({"snapshot": snapshot(&args["value"])})),
        "coordinate" => coordinate(args),
        "finalize" => finalize(args),
        "offer" => offer(args),
        "replay" => replay(args),
        "identity" => Ok(
            json!({"offer_hash":offer_hash(&args["offer"],false)?,"identity_hash":offer_hash(&args["offer"],true)?}),
        ),
        "status" => Ok(json!({"status":status(args["value"].as_str().ok_or(ERR_INVALID)?)})),
        "store_claim" | "store_finalize" => crate::continuation_store::evaluate(args),
        "store_finalize_projected" => {
            let projection = finalize(args)?;
            let mut request = projection["finalization"].clone();
            for key in ["guard_home", "store_path", "busy_timeout_ms"] {
                request[key] = args[key].clone();
            }
            request["call"] = json!("store_finalize");
            request["metadata_nonfinite"] = args["operation_metadata_nonfinite"].clone();
            crate::continuation_store::evaluate(&request)
        }
        "claim_check" => Ok(crate::continuation_store::claim_check(args)),
        "attempt" => Ok(
            json!({"attempt_count":args["prior"]["attempt_count"].as_i64().and_then(|v|v.checked_add(1)).unwrap_or(1)}),
        ),
        _ => Err(ERR_INVALID),
    }
}
fn replay(args: &Value) -> KindResult {
    let value = &args["prior"];
    let offer = &args["offer"];
    if value["continuation_offer_hash"] != offer_hash(offer, false)?
        || value["continuation_action"] != args["action"]
    {
        return Ok(json!({"result":Value::Null}));
    }
    let Some(state) = text(&value["continuation_status"]).filter(|s| {
        matches!(
            *s,
            "resumed"
                | "already_resumed"
                | "manual_retry_required"
                | "blocked_not_resumed"
                | "unsupported"
                | "failed"
                | "waiting"
        )
    }) else {
        return Ok(json!({"result":Value::Null}));
    };
    let completed = text(&value["continuation_completed_at"])
        .filter(|value| has_time_zone(value))
        .and_then(guard_contracts::canonical_utc_timestamp)
        // Python `isoformat()` spelling: whole seconds drop the fraction.
        .and_then(|value| crate::guard_store_json::add_seconds_isoformat(&value, 0));
    let evidence = value["continuation_evidence"]
        .as_array()
        .and_then(|values| values.iter().find(|v| v.is_object()))
        .and_then(|v| text(&v["evidenceId"]));
    let (Some(completed), Some(evidence)) = (completed, evidence) else {
        return Ok(json!({"result":Value::Null}));
    };
    let reason = text(&value["continuation_reason"])
        .unwrap_or(state)
        .chars()
        .take(128)
        .collect::<String>();
    Ok(
        json!({"result":{"correlation_id":offer["correlation_id"],"capability":offer["capability"],"status":state,"reason":reason,"completed_at":completed,"evidence_id":evidence}}),
    )
}

pub(crate) fn has_time_zone(value: &str) -> bool {
    crate::guard_store_json::add_seconds_isoformat(value, 0).is_some_and(|value| {
        value
            .split_once('T')
            .or_else(|| value.split_once(' '))
            .is_some_and(|(_, time)| {
                time.contains('+') || time.contains('-') || time.ends_with('Z')
            })
    })
}
fn offer(args: &Value) -> KindResult {
    let harness = args["harness"]
        .as_str()
        .map(super::guard_store_json::py_strip)
        .ok_or(ERR_INVALID)?
        .to_lowercase();
    let deadline = &args["wait_deadline"];
    let attached = args["original_hook_attached"] == true;
    // Mirror the old short-circuit: the deadline is only compared for an attached Codex hook.
    let live = harness == "codex"
        && attached
        && !deadline.is_null()
        && guard_contracts::utc_timestamp_micros(deadline.as_str().ok_or(ERR_INVALID)?)
            .ok_or(ERR_INVALID)?
            > guard_contracts::utc_timestamp_micros(args["now"].as_str().ok_or(ERR_INVALID)?)
                .ok_or(ERR_INVALID)?;
    let capability = if harness == "codex" && live {
        "suspended-response"
    } else if harness == "codex"
        && args["headless"] != true
        && args["session_target_verified"] == true
    {
        "session-resume"
    } else if matches!(
        harness.as_str(),
        "codex" | "pi" | "omp" | "oh-my-pi" | "grok" | "openclaw" | "hermes"
    ) {
        "retry-only"
    } else {
        "unsupported"
    };
    Ok(
        json!({"offer":{"correlation_id":args["correlation_id"], "harness":harness, "capability":capability,
        "original_hook_attached":capability == "suspended-response", "wait_deadline":if capability == "suspended-response" {deadline.clone()} else {Value::Null},
        "opaque_target_id":if capability == "session-resume" {args["opaque_target_id"].clone()} else {Value::Null},
        "contract_version":"guard.harness-continuation.v2"}}),
    )
}
fn finalize(args: &Value) -> KindResult {
    let projection = project(args)?;
    let offer = &args["offer"];
    let result = &args["result"];
    let prior = &args["prior"];
    let operation = &args["operation"];
    let state = text(&result["status"]).ok_or(ERR_INVALID)?;
    let action = text(&args["action"]).ok_or(ERR_INVALID)?;
    let capability = text(&offer["capability"]).ok_or(ERR_INVALID)?;
    let supported = matches!(capability, "suspended-response" | "session-resume");
    let existing = prior["attempt_count"].as_i64();
    let attempts =
        if offer["harness"] == "codex" && capability == "session-resume" && existing.is_some() {
            existing.ok_or(ERR_INVALID)?
        } else {
            existing.and_then(|v| v.checked_add(1)).unwrap_or(1)
        };
    let metadata = &operation["metadata"];
    let session = [
        "codex_thread_id",
        "thread_id",
        "threadId",
        "conversation_id",
        "conversationId",
        "session_id",
        "sessionId",
    ]
    .iter()
    .find_map(|key| text(&metadata[*key]))
    .or_else(|| text(&operation["session_id"]));
    Ok(
        json!({"finalization":{"request_id":args["request_id"], "offer_hash":projection["offer_hash"], "action":action,
        "claim_id":args["claim_id"], "evidence_id":result["evidence_id"], "terminal":state != "waiting",
        "resume_seed":{"operation_id":text(&operation["operation_id"]), "harness":offer["harness"], "strategy":projection["strategy"], "supported":supported,"thread_id":session},
        "resume_update":{"resolution_action":if action == "allow_once" {"allow"} else {"block"},
            "strategy":projection["strategy"],"supported":supported,"status":projection["persisted_status"],"reason":result["reason"],
            "message":Value::Null,"last_error":if state == "failed" {result["reason"].clone()} else {Value::Null},"attempt_count":attempts,
            "last_attempt_at":args["now"],"sent_at":if matches!(state,"resumed"|"already_resumed") {args["now"].clone()} else {Value::Null},
            "continuation_contract_version":"guard.harness-continuation.v2", "continuation_capability":capability,"continuation_status":state,
            "continuation_reason":result["reason"], "continuation_evidence":[{"correlationId":offer["correlation_id"],"evidenceId":result["evidence_id"],"status":state}],
            "continuation_offer_hash":projection["offer_hash"], "continuation_action":action,"continuation_completed_at":result["completed_at"],
            "continuation_cancelled_at":if result["reason"] == "continuation_cancelled" {args["now"].clone()} else {Value::Null}},
        "operation_update":projection["operation_update"],"events":projection["events"],"now":args["now"],"approval_decision":args["approval_decision"]}}),
    )
}
fn make_result(offer: &Value, state: &str, reason: &str, args: &Value) -> Value {
    json!({"correlation_id":offer["correlation_id"],"capability":offer["capability"],"status":state,
        "reason":reason.chars().take(128).collect::<String>(),"completed_at":args["now"],"evidence_id":args["evidence_id"]})
}
fn coordinate(args: &Value) -> KindResult {
    let offer = &args["offer"];
    let capability = text(&offer["capability"]).ok_or(ERR_INVALID)?;
    let terminal = if args["action"] == "block" {
        Some(("blocked_not_resumed", "decision_blocked"))
    } else if args["cancelled"] == true {
        Some(("failed", "continuation_cancelled"))
    } else if capability == "unsupported" {
        Some(("unsupported", "harness_unsupported"))
    } else if capability == "retry-only" {
        Some(("manual_retry_required", "manual_retry_required"))
    } else if !offer["wait_deadline"].is_null()
        && guard_contracts::utc_timestamp_micros(
            offer["wait_deadline"].as_str().ok_or(ERR_INVALID)?,
        )
        .ok_or(ERR_INVALID)?
            <= guard_contracts::utc_timestamp_micros(args["now"].as_str().ok_or(ERR_INVALID)?)
                .ok_or(ERR_INVALID)?
    {
        Some(("manual_retry_required", "wait_window_expired"))
    } else {
        None
    };
    Ok(
        json!({"identity_hash":offer_hash(offer,true)?, "result":terminal.map(|(s,r)|make_result(offer,s,r,args))}),
    )
}
fn correlation(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("gcr_") else {
        return false;
    };
    suffix.len() == 36
        && suffix.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn snapshot(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return Value::Null;
    };
    if object.len() != 5
        || ![
            "capability",
            "correlationId",
            "hookAttached",
            "opaqueTargetId",
            "waitDeadline",
        ]
        .iter()
        .all(|k| object.contains_key(*k))
    {
        return Value::Null;
    }
    let (Some(id), Some(capability), Some(attached)) = (
        text(&value["correlationId"]),
        text(&value["capability"]),
        value["hookAttached"].as_bool(),
    ) else {
        return Value::Null;
    };
    let target = &value["opaqueTargetId"];
    let deadline = &value["waitDeadline"];
    if !correlation(id)
        || (!target.is_null() && text(target).is_none())
        || (!deadline.is_null() && text(deadline).is_none())
    {
        return Value::Null;
    }
    if capability == "suspended-response" {
        if !attached || deadline.is_null() || !target.is_null() {
            return Value::Null;
        }
    } else if attached || !deadline.is_null() {
        return Value::Null;
    }
    if capability == "session-resume" {
        if target.is_null() {
            return Value::Null;
        }
    } else if !target.is_null()
        || !matches!(
            capability,
            "suspended-response" | "retry-only" | "unsupported"
        )
    {
        return Value::Null;
    }
    json!({"correlationId":id,"capability":capability,"hookAttached":attached,"opaqueTargetId":target,"waitDeadline":deadline})
}
fn project(args: &Value) -> KindResult {
    let offer = &args["offer"];
    let result = &args["result"];
    let harness = offer["harness"].as_str().ok_or(ERR_INVALID)?;
    let capability = offer["capability"].as_str().ok_or(ERR_INVALID)?;
    let state = result["status"].as_str().ok_or(ERR_INVALID)?;
    let action = args["action"].as_str().ok_or(ERR_INVALID)?;
    let codex = harness == "codex";
    let public = if codex && matches!(state, "manual_retry_required" | "blocked_not_resumed") {
        "skipped"
    } else {
        status(state)
    };
    let reason = if codex && state == "blocked_not_resumed" {
        json!("blocked_not_resumed")
    } else if codex && state == "waiting" {
        json!("live_hook_waiting")
    } else {
        result["reason"].clone()
    };
    let strategy = if state == "blocked_not_resumed" {
        "manual-only"
    } else {
        match capability {
            "suspended-response" => "codex-live-hook",
            "session-resume" => "codex-app-server-thread",
            _ => "manual-only",
        }
    };
    let detail = json!({"capability":capability, "completedAt":result["completed_at"],
        "correlationId":offer["correlation_id"], "evidenceId":result["evidence_id"], "harness":harness,
        "message":if codex {message(state)} else {Value::Null}, "reason":reason, "status":public,
        "strategy":strategy, "supported":state != "blocked_not_resumed" && matches!(capability,"suspended-response"|"session-resume")});
    let mut payload = json!({"correlationId":offer["correlation_id"], "continuationCapability":capability,
        "continuationCompletedAt":result["completed_at"], "continuationEvidenceId":result["evidence_id"],
        "continuationReason":result["reason"], "continuationStatus":state});
    payload[if codex {
        "codexResume"
    } else {
        "harnessResume"
    }] = detail;
    let replayed = payload.clone();
    if state == "manual_retry_required" {
        payload["localManualRetryNotification"] = json!(true);
    }
    let operation = &args["operation"];
    let operation_id = text(&operation["operation_id"]);
    let mut events = vec![
        json!(["review.continuation.attempt", {"action":action, "capability":capability,
        "correlationId":offer["correlation_id"], "evidence_id":result["evidence_id"], "harness":harness,
        "request_id":args["request_id"], "status":state}]),
    ];
    if state != "waiting" {
        events.push(
            json!(["review.continuation.terminal", {"correlationId":offer["correlation_id"],
        "evidence_id":result["evidence_id"], "request_id":args["request_id"], "status":state}]),
        );
    }
    if !codex {
        events.push(json!(["harness/operation_resume", {"action":if action == "allow_once" {"allow"} else {"block"},
        "correlationId":offer["correlation_id"], "harness":harness, "operation_id":operation_id, "request_id":args["request_id"], "status":status(state)}]));
    }
    if state == "manual_retry_required" {
        events.push(json!(["review.continuation.manual_retry_required", {
        "correlationId":offer["correlation_id"], "evidence_id":result["evidence_id"], "harness":harness,
        "request_id":args["request_id"], "reason":result["reason"]}]));
    }
    let update = if let (Some(id), Some(session), Some(kind), Some(operation_harness)) = (
        operation_id,
        text(&operation["session_id"]),
        text(&operation["operation_type"]),
        text(&operation["harness"]),
    ) {
        let mut metadata = operation["metadata"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        metadata.insert("continuation".into(), json!({"action":action, "capability":result["capability"],
            "correlationId":result["correlation_id"], "evidence_id":result["evidence_id"], "reason":result["reason"], "status":state}));
        let ids: Vec<&str> = operation["approval_request_ids"]
            .as_array()
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let operation_state = match state {
            "resumed" | "already_resumed" => "resumed",
            "manual_retry_required" => "manual_retry_required",
            "blocked_not_resumed" => "blocked",
            "failed" => "continuation_failed",
            _ => "waiting_on_approval",
        };
        json!({"operation_id":id, "session_id":session, "harness":operation_harness, "operation_type":kind,
            "status":operation_state, "approval_request_ids":ids, "resume_token":text(&operation["resume_token"]), "metadata":metadata,"now":args["now"]})
    } else {
        Value::Null
    };
    Ok(
        json!({"offer_hash":offer_hash(offer,false)?, "identity_hash":offer_hash(offer,true)?, "payload":payload,
        "replayed_payload":replayed, "strategy":strategy, "persisted_status":public,"operation_update":update,"events":events}),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn pinned_python_projection_vectors() {
        let document: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/continuation_authority_vectors.json"
        ))
        .unwrap();
        for (index, case) in document["cases"].as_array().unwrap().iter().enumerate() {
            assert_eq!(
                super::evaluate(&case["args"]).unwrap(),
                case["expected"],
                "vector {index}"
            );
        }
    }
}
