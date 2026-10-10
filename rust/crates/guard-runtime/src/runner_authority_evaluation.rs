//! Evaluation patches for `RunnerAuthority`: recording a detector result,
//! terminal approval-claim failures and receipt-evidence merging.
//!
//! Every artifact rewrite goes through `rebuild_artifact_authority`, so the
//! serialized decision aliases cannot drift from the authoritative decision.

use guard_command::decisions::{
    build_authoritative_decision, parse_signals, rebuild_artifact_authority,
    AUTHORITATIVE_DECISION_INCONSISTENT,
};
use guard_contracts::{GuardAction, RiskSignalV2};
use serde_json::{json, Map, Value};

use super::runner_authority_detector::{
    args_object, detector_action_and_reason, nonterminal_evidence,
};
use super::runner_authority_op::{KindResult, ERR_INVALID};

const ERR_DECISION: &str = "native_runner_authority_decision_error";
const DETECTOR_RESULT_KEYS: [&str; 4] = [
    "runtime_detector_signals_v2",
    "runtime_detector_telemetry",
    "runtime_detector_composition",
    "runtime_detector_trace_error",
];
const REUSE_SOURCE: &str = "approval_reuse";
const CONTEXT_CHANGED_CODE: &str = "approval_reuse_context_changed_after_claim";

/// Python truthiness for the carried `blocked` field.
fn py_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

fn same_evidence(entry: &Value, source: &Value, reason_code: &Value) -> bool {
    entry.as_object().is_some_and(|entry| {
        entry.get("source") == Some(source) && entry.get("reason_code") == Some(reason_code)
    })
}

/// `_artifact_with_authority_updates`: a malformed decision is preserved and
/// flagged so the final gate fails closed.
fn rebuilt(
    item: Map<String, Value>,
    reason: Option<&str>,
    updates: &Map<String, Value>,
    signals: &[RiskSignalV2],
) -> Value {
    let payload = Value::Object(item.clone());
    match rebuild_artifact_authority(&payload, reason, Some(updates), signals) {
        Ok(next) => Value::Object(next),
        Err(_) => {
            let mut flagged = item;
            flagged.insert(
                "decision_contract_error".to_owned(),
                json!(AUTHORITATIVE_DECISION_INCONSISTENT),
            );
            Value::Object(flagged)
        }
    }
}

/// Per-artifact patches: only the keys a rewrite changed, so the reply never
/// echoes untouched artifact payloads. `index` is the artifact's position in
/// the request; non-object entries are never rewritten.
fn artifact_patches<F>(artifacts: &[Value], rewrite: F) -> Vec<Value>
where
    F: Fn(&Map<String, Value>) -> Option<Value>,
{
    artifacts
        .iter()
        .enumerate()
        .filter_map(|(index, raw)| {
            let original = raw.as_object()?;
            let Value::Object(next) = rewrite(original)? else {
                return None;
            };
            let changed: Map<String, Value> = next
                .into_iter()
                .filter(|(key, value)| original.get(key) != Some(value))
                .collect();
            (!changed.is_empty()).then(|| json!({"index": index, "set": changed}))
        })
        .collect()
}

fn detector_signals(detector: &Map<String, Value>) -> Result<Vec<RiskSignalV2>, ()> {
    match detector.get("runtime_detector_signals_v2") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(raw) => parse_signals(raw).map_err(|_| ()),
    }
}

fn recorded_artifact(
    raw: &Map<String, Value>,
    evidence: Option<&Value>,
    action: Option<GuardAction>,
    reason: Option<&str>,
    signals: &[RiskSignalV2],
) -> Value {
    let mut item = raw.clone();
    let mut scanner_evidence: Vec<Value> = match raw.get("scanner_evidence") {
        Some(Value::Array(entries)) => entries.clone(),
        _ => Vec::new(),
    };
    if let Some(evidence) = evidence {
        let (source, code) = (&evidence["source"], &evidence["reason_code"]);
        if !scanner_evidence
            .iter()
            .any(|entry| same_evidence(entry, source, code))
        {
            scanner_evidence.push(evidence.clone());
        }
    }
    item.insert(
        "scanner_evidence".to_owned(),
        Value::Array(scanner_evidence),
    );
    let mut updates = Map::new();
    if let Some(action) = action {
        let evidence_reason = evidence.and_then(|e| e["reason"].as_str());
        updates.insert("runtime_detector_action".to_owned(), json!(action.as_str()));
        updates.insert(
            "runtime_detector_reason".to_owned(),
            json!(reason
                .or(evidence_reason)
                .unwrap_or("runtime detector authority")),
        );
    }
    let code = evidence
        .filter(|_| {
            action.is_some_and(|a| {
                raw.get("policy_action").and_then(Value::as_str) == Some(a.as_str())
            })
        })
        .and_then(|e| e["reason_code"].as_str());
    rebuilt(item, code, &updates, signals)
}

pub(crate) fn apply_detector_result(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let detector = args
        .get("detector")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let mut set = Map::new();
    for key in DETECTOR_RESULT_KEYS {
        if let Some(value) = detector.get(key) {
            set.insert(key.to_owned(), value.clone());
        }
    }
    let mut blocked = args.get("blocked").is_some_and(py_truthy);
    if let Some(reason) = detector
        .get("blocked_by_detector")
        .and_then(Value::as_str)
        .filter(|reason| !reason.is_empty())
    {
        blocked = true;
        set.insert("blocked".to_owned(), json!(true));
        set.insert("blocked_by_detector".to_owned(), json!(reason));
    }
    let (action, reason) = detector_action_and_reason(detector);
    let Ok(signals) = detector_signals(detector) else {
        set.insert(
            "decision_contract_error".to_owned(),
            json!(AUTHORITATIVE_DECISION_INCONSISTENT),
        );
        return Ok(json!({"set": set}));
    };
    let evidence = nonterminal_evidence(action, reason.as_deref());
    let artifacts = args
        .get("artifacts")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty());
    let Some(artifacts) = artifacts else {
        if let Some(action) = action {
            let authority_reason = reason
                .clone()
                .or_else(|| {
                    evidence
                        .as_ref()
                        .and_then(|e| e["reason"].as_str().map(str::to_owned))
                })
                .unwrap_or_else(|| "runtime detector blocked this launch".to_owned());
            let mut trace = Map::new();
            trace.insert("runtime_detector_action".to_owned(), json!(action.as_str()));
            let decision = build_authoritative_decision(
                action,
                &authority_reason,
                &trace,
                &signals,
                action != GuardAction::Review,
                "runtime-detector-registry",
            )
            .map_err(|_| ERR_DECISION)?;
            let blocking = decision.enforcement.blocking;
            set.insert("run_authoritative_decision".to_owned(), decision.to_value());
            set.insert("blocked".to_owned(), json!(blocked || blocking));
            if blocking {
                set.insert("blocked_by_detector".to_owned(), json!(authority_reason));
            }
        }
        return Ok(json!({"set": set}));
    };
    let patches = artifact_patches(artifacts, |item| {
        Some(recorded_artifact(
            item,
            evidence.as_ref(),
            action,
            reason.as_deref(),
            &signals,
        ))
    });
    set.insert("artifact_patches".to_owned(), Value::Array(patches));
    Ok(json!({"set": set}))
}

/// Mark one artifact's saved-approval reuse rejected and rebuild its authority.
fn rejected_reuse_artifact(
    raw: &Map<String, Value>,
    evidence: &Value,
    reason_code: &str,
    revalidation: &str,
) -> Value {
    let mut item = raw.clone();
    let mut scanner_evidence: Vec<Value> = raw
        .get("scanner_evidence")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| {
                    entry.as_object().is_some_and(|e| {
                        e.get("source").and_then(Value::as_str) != Some(REUSE_SOURCE)
                    })
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    scanner_evidence.push(evidence.clone());
    item.insert(
        "scanner_evidence".to_owned(),
        Value::Array(scanner_evidence),
    );
    item.insert("approval_reuse_status".to_owned(), json!("rejected"));
    item.insert("approval_reuse_reason_code".to_owned(), json!(reason_code));
    let mut reuse = raw
        .get("approval_reuse")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    reuse.insert(
        "action".to_owned(),
        raw.get("policy_action").cloned().unwrap_or(Value::Null),
    );
    reuse.insert("status".to_owned(), json!("rejected"));
    reuse.insert("reason_code".to_owned(), json!(reason_code));
    reuse.insert("should_claim".to_owned(), json!(false));
    item.insert("approval_reuse".to_owned(), Value::Object(reuse));
    let mut updates = Map::new();
    updates.insert("claim_revalidation".to_owned(), json!(revalidation));
    updates.insert("claim_revalidation_reason".to_owned(), json!(reason_code));
    rebuilt(item, Some(reason_code), &updates, &[])
}

fn terminal_failure(
    args: &Map<String, Value>,
    affected: Option<&Vec<&str>>,
    code: &str,
    reason: &str,
    claim_status: &str,
    revalidation: &str,
) -> KindResult {
    let evidence = json!({
        "source": REUSE_SOURCE, "status": "rejected", "reason_code": code, "reason": reason,
    });
    let mut ids: Vec<&str> = affected.cloned().unwrap_or_default();
    let artifacts = artifact_patches(
        args.get("artifacts")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default(),
        |item| {
            let in_scope = affected.is_none_or(|ids| {
                item.get("artifact_id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| ids.contains(&id))
            });
            in_scope.then(|| rejected_reuse_artifact(item, &evidence, code, revalidation))
        },
    );
    ids.sort_unstable();
    ids.dedup();
    Ok(json!({
        "set": {
            "artifact_patches": artifacts,
            "blocked": true,
            "approval_claim": {"status": claim_status, "reason_code": code, "artifact_ids": ids},
        },
        "receipt_evidence": evidence,
    }))
}

fn id_list(args: &Map<String, Value>, key: &str) -> Result<Vec<String>, &'static str> {
    args.get(key)
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|id| id.as_str().map(str::to_owned).ok_or(ERR_INVALID))
        .collect()
}

pub(crate) fn preclaim_failure(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let ids = id_list(args, "affected_artifact_ids")?;
    let scope: Vec<&str> = ids.iter().map(String::as_str).collect();
    let (reason, status, revalidation) = match args.get("reason_code").and_then(Value::as_str) {
        Some("approval_reuse_launch_identity_unverified") => (
            "saved approval could not be reused because the harness launch identity was not stable and path-pinned",
            "rejected",
            "unverified",
        ),
        Some("approval_reuse_claim_failed") => (
            "saved approval could not be atomically claimed",
            "failed",
            "claim-failed",
        ),
        _ => return Err(ERR_INVALID),
    };
    let code = args["reason_code"].as_str().ok_or(ERR_INVALID)?;
    terminal_failure(args, Some(&scope), code, reason, status, revalidation)
}

pub(crate) fn claim_context_failure(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let ids = id_list(args, "claimed_artifact_ids")?;
    let mut result = terminal_failure(
        args,
        None,
        CONTEXT_CHANGED_CODE,
        "launch authority changed after the saved approval was claimed",
        "rejected",
        "changed",
    )?;
    // Every object artifact is rewritten, but the claim reports only the ids
    // that were actually claimed.
    let mut claimed = ids;
    claimed.sort_unstable();
    claimed.dedup();
    result["set"]["approval_claim"]["artifact_ids"] = json!(claimed);
    Ok(result)
}

/// Row-level evidence merge; the caller keeps the SQL and applies the updates.
pub(crate) fn receipt_evidence_merge(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let rows = args
        .get("rows")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let evidence = args
        .get("evidence")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let artifact_ids = id_list(args, "artifact_ids")?;
    let source_actions = id_list(args, "source_actions")?;
    let approval_source = args.get("approval_source").cloned().unwrap_or(Value::Null);
    let replace = args.get("replace_existing_source") == Some(&Value::Bool(true));
    let (source, reason_code) = (
        evidence.get("source").unwrap_or(&Value::Null),
        evidence.get("reason_code").unwrap_or(&Value::Null),
    );
    let mut updates = Vec::new();
    for row in rows {
        let row = row.as_object().ok_or(ERR_INVALID)?;
        let artifact_id = row
            .get("artifact_id")
            .and_then(Value::as_str)
            .ok_or(ERR_INVALID)?;
        if !artifact_ids.iter().any(|id| id == artifact_id) {
            continue;
        }
        let mut scanner_evidence: Vec<Value> = row
            .get("scanner_evidence_json")
            .and_then(Value::as_str)
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
            .and_then(|parsed| match parsed {
                Value::Array(entries) => Some(entries),
                _ => None,
            })
            .unwrap_or_default();
        if replace {
            scanner_evidence.retain(|entry| {
                entry
                    .as_object()
                    .is_none_or(|e| e.get("source").unwrap_or(&Value::Null) != source)
            });
        }
        if !scanner_evidence
            .iter()
            .any(|entry| same_evidence(entry, source, reason_code))
        {
            scanner_evidence.push(Value::Object(evidence.clone()));
        }
        let decision = row
            .get("policy_decision")
            .and_then(Value::as_str)
            .unwrap_or("");
        let next_source = if source_actions.iter().any(|action| action == decision) {
            approval_source.clone()
        } else {
            row.get("approval_source").cloned().unwrap_or(Value::Null)
        };
        updates.push(json!({
            "rowid": row.get("rowid").cloned().unwrap_or(Value::Null),
            "scanner_evidence": scanner_evidence,
            "approval_source": next_source,
        }));
    }
    Ok(json!({"updates": updates}))
}
