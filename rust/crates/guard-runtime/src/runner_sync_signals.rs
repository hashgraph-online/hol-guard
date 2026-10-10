//! Pain-signal selection, value metrics and sync-status evidence for
//! `RunnerAuthority`.
//!
//! Python hands over the stored guard events; every decision about which
//! events become cloud pain signals, how often a warning must repeat before it
//! escalates, and what the local value metrics and weekly digest say is made
//! here. The caller uploads or stores what comes back, nothing more.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use super::policy_bundle_py::non_empty;
use super::runner_authority_detector::args_object;
use super::runner_authority_op::{KindResult, ERR_INVALID};

const INSTALL_TIME_STOP_EVENTS: [&str; 4] = [
    "install_time_block",
    "install_time_review",
    "install_time_require-reapproval",
    "install_time_sandbox-required",
];
const STOP_ACTIONS: [&str; 4] = ["review", "require-reapproval", "sandbox-required", "block"];

type WarnKey = (String, String);

fn payload_string<'a>(payload: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    non_empty(payload.get(key))
}

fn warning_key(payload: &Map<String, Value>) -> Option<WarnKey> {
    let artifact_id = payload_string(payload, "artifact_id")?;
    let harness =
        payload_string(payload, "harness").or_else(|| payload_string(payload, "executor"))?;
    Some((harness.to_owned(), artifact_id.to_owned()))
}

fn artifact_identity(event_name: &str, payload: &Map<String, Value>) -> Option<(String, String)> {
    let artifact_id = payload_string(payload, "artifact_id");
    let artifact_name = payload_string(payload, "artifact_name");
    if let (Some(id), Some(name)) = (artifact_id, artifact_name) {
        return Some((id.to_owned(), name.to_owned()));
    }
    match event_name {
        "supply_chain_bundle_refresh_requested" => {
            let fallback = artifact_id.unwrap_or("guard:supply-chain:feed");
            Some((
                fallback.to_owned(),
                artifact_name.unwrap_or(fallback).to_owned(),
            ))
        }
        "approval_gate/remote_policy_sync_blocked" => Some((
            "guard:policy:disable".to_owned(),
            "remote policy sync disabled".to_owned(),
        )),
        _ => None,
    }
}

fn should_emit(
    event_name: &str,
    payload: &Map<String, Value>,
    warn_counts: &BTreeMap<WarnKey, u64>,
) -> bool {
    if INSTALL_TIME_STOP_EVENTS.contains(&event_name) {
        return true;
    }
    match event_name {
        "install_time_warn" => {
            warning_key(payload).is_some_and(|key| warn_counts.get(&key).copied().unwrap_or(0) >= 2)
        }
        "changed_artifact_caught" => payload_string(payload, "policy_action")
            .is_some_and(|action| STOP_ACTIONS.contains(&action)),
        "supply_chain_bundle_refresh_requested" => {
            payload_string(payload, "reason") == Some("feed_stale")
        }
        other => other == "approval_gate/remote_policy_sync_blocked",
    }
}

fn string_labels(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn summary(event_name: &str, payload: &Map<String, Value>) -> String {
    if let Some(reason) = payload_string(payload, "reason") {
        return reason.to_owned();
    }
    if event_name == "changed_artifact_caught" {
        let changed = string_labels(payload.get("changed_fields"));
        if !changed.is_empty() {
            return format!("Artifact changed across: {}.", changed.join(", "));
        }
    }
    let risks = string_labels(payload.get("risk_signals"));
    if !risks.is_empty() {
        return format!("Guard flagged install-time risk: {}.", risks.join(", "));
    }
    if let (Some(expires_at), "exception_expiring") =
        (payload_string(payload, "expires_at"), event_name)
    {
        return format!("Guard exception expires at {expires_at}.");
    }
    format!(
        "Guard recorded {} for this artifact.",
        event_name.replace('_', " ")
    )
}

fn pain_signal_item(event: &Value, warn_counts: &BTreeMap<WarnKey, u64>) -> Option<Value> {
    let event = event.as_object()?;
    let event_name = non_empty(event.get("event_name"))?;
    let payload = event.get("payload")?.as_object()?;
    let occurred_at = non_empty(event.get("occurred_at"))?;
    let (artifact_id, artifact_name) = artifact_identity(event_name, payload)?;
    if !should_emit(event_name, payload, warn_counts) {
        return None;
    }
    let harness = payload_string(payload, "harness")
        .or_else(|| payload_string(payload, "executor"))
        .unwrap_or("unknown");
    let artifact_type = match payload_string(payload, "artifact_type") {
        Some(kind @ ("plugin" | "skill")) => kind,
        _ if artifact_id.starts_with("skill:") => "skill",
        _ => "plugin",
    };
    Some(json!({
        "signalId": format!("{event_name}:{harness}:{artifact_id}"),
        "signalName": event_name,
        "artifactId": artifact_id,
        "artifactName": artifact_name,
        "artifactType": artifact_type,
        "harness": harness,
        "latestSummary": summary(event_name, payload),
        "occurredAt": occurred_at,
        "source": "scanner",
        "publisher": payload_string(payload, "publisher"),
    }))
}

fn read_warn_counts(value: Option<&Value>) -> Result<BTreeMap<WarnKey, u64>, &'static str> {
    let mut counts = BTreeMap::new();
    for row in value.and_then(Value::as_array).ok_or(ERR_INVALID)? {
        let row = row
            .as_array()
            .filter(|row| row.len() == 3)
            .ok_or(ERR_INVALID)?;
        let (Some(harness), Some(artifact), Some(count)) =
            (row[0].as_str(), row[1].as_str(), row[2].as_u64())
        else {
            return Err(ERR_INVALID);
        };
        counts.insert((harness.to_owned(), artifact.to_owned()), count);
    }
    Ok(counts)
}

/// `pain_signal_batch`: the cloud pain signals for one batch of stored events,
/// plus the repeat-warning counters to carry into the next batch.
pub(crate) fn pain_signal_batch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let events = args
        .get("events")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let mut warn_counts = read_warn_counts(args.get("warn_counts"))?;
    let mut items = Vec::new();
    for event in events {
        if non_empty(event.get("event_name")) == Some("install_time_warn") {
            if let Some(key) = event
                .get("payload")
                .and_then(Value::as_object)
                .and_then(warning_key)
            {
                *warn_counts.entry(key).or_insert(0) += 1;
            }
        }
        if let Some(item) = pain_signal_item(event, &warn_counts) {
            items.push(item);
        }
    }
    let counts: Vec<Value> = warn_counts
        .into_iter()
        .map(|((harness, artifact), count)| json!([harness, artifact, count]))
        .collect();
    Ok(json!({"items": items, "warn_counts": counts}))
}

/// `str(value).lower()` for the substring probes the metrics apply.
fn probe_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.to_lowercase(),
        Value::Null => "none".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        other => other.to_string().to_lowercase(),
    }
}

fn any_signal(value: Option<&Value>, test: impl Fn(&str) -> bool) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|signals| signals.iter().any(|signal| test(&probe_text(signal))))
}

fn value_metrics_counts(events: &[Value]) -> (u64, u64, u64) {
    let (mut installs, mut scripts, mut tokens) = (0, 0, 0);
    for event in events {
        let name = non_empty(event.get("event_name")).unwrap_or("");
        let Some(payload) = event.get("payload").and_then(Value::as_object) else {
            continue;
        };
        if INSTALL_TIME_STOP_EVENTS.contains(&name) {
            installs += 1;
            let kind = payload_string(payload, "install_kind")
                .unwrap_or("")
                .to_lowercase();
            if kind.contains("script")
                || any_signal(payload.get("risk_signals"), |text| text.contains("script"))
            {
                scripts += 1;
            }
        }
        if name == "changed_artifact_caught" {
            let launch_surface = payload
                .get("changed_fields")
                .and_then(Value::as_array)
                .is_some_and(|fields| {
                    fields
                        .iter()
                        .any(|field| matches!(field.as_str(), Some("command" | "args")))
                });
            let secret = any_signal(payload.get("risk_signals"), |text| {
                ["token", "secret", ".env", "credential"]
                    .iter()
                    .any(|needle| text.contains(needle))
            });
            if launch_surface && secret {
                tokens += 1;
            }
        }
    }
    (installs, scripts, tokens)
}

/// `value_metrics`: the local value metrics and the weekly digest built from
/// them.
pub(crate) fn value_metrics(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let events = args
        .get("events")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let now = args.get("now").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let (installs, scripts, tokens) = value_metrics_counts(events);
    let headline = format!(
        "Package firewall summary: {installs} installs stopped before execution, \
         {scripts} scripts prevented, {tokens} token-protection incidents."
    );
    Ok(json!({
        "metrics": {
            "installs_stopped_before_execution": {
                "value": installs,
                "source": "guard_events:install_time_block|review|require-reapproval|sandbox-required",
            },
            "scripts_prevented": {
                "value": scripts,
                "source": "guard_events:risk_signals|install_kind",
            },
            "tokens_protected": {
                "value": tokens,
                "source": "guard_events:changed_artifact_caught",
            },
        },
        "weekly_digest": {
            "subject": "HOL Guard weekly package firewall summary",
            "generated_at": now,
            "period_days": 7,
            "headline": headline,
            "body_preview": format!(
                "HOL Guard weekly digest\n{headline}\nReview the approval queue and sync health to keep package protection current."
            ),
        },
    }))
}

/// `completed_event_ids`: event ids the cloud has finished with.
pub(crate) fn completed_event_ids(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let payload = args
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let statuses = payload.get("statuses").and_then(Value::as_array);
    let ids: Vec<&str> = statuses
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .filter(|item| {
            matches!(
                item.get("status").and_then(Value::as_str),
                Some("accepted" | "duplicate" | "rejected")
            )
        })
        .filter_map(|item| item.get("eventId").and_then(Value::as_str))
        .collect();
    Ok(json!({"ids": ids}))
}
