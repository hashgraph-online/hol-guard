//! `ConsumerArtifactCompose` — resident decision composition for consumer
//! artifact evaluation (`guard run`, `guard scan`, inventory refresh).
//!
//! Python gathers evidence; this op owns every verdict: the artifact scoring
//! recommendation and the current-action lattice live here, and the saved,
//! claimed and trusted-request reuse plus runtime-detector authority live in
//! `consumer_artifact_compose_runtime`. Every query is pure and fails closed:
//! unknown configured actions normalize to `require-reapproval`.

use std::collections::BTreeSet;

use guard_contracts::{
    most_restrictive_of as stricter, normalize_guard_action, ConsumerArtifactComposeQueryV1,
    ConsumerArtifactComposeRequestV1, ConsumerArtifactComposeResultV1,
    ConsumerCurrentActionQueryV1, ConsumerDeltaV1, ConsumerSignalV1, GuardAction,
    CONSUMER_ARTIFACT_COMPOSE_REQUEST_SCHEMA, CONSUMER_ARTIFACT_COMPOSE_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::consumer_artifact_compose_runtime::runtime_decision;

const REQUEST_ARTIFACT_TYPES: [&str; 3] =
    ["prompt_request", "file_read_request", "tool_action_request"];
const EVIDENCE_SOURCES: [&str; 4] = ["artifact", "prompt", "history", "cloud"];
const REAPPROVAL_DELTAS: [&str; 3] = [
    "secret_scope_expanded",
    "subprocess_added",
    "approval_surface_changed",
];
const PRIOR_APPROVALS_REASON: &str = "Artifact has prior local approvals without recent incidents.";
const FLAGGED_PUBLISHER_REASON: &str = "Publisher trust is flagged by local advisory intelligence.";

pub(crate) fn evaluate_consumer_artifact_compose_request(
    request: &ConsumerArtifactComposeRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != CONSUMER_ARTIFACT_COMPOSE_REQUEST_SCHEMA {
        return Err("native_consumer_artifact_compose_schema_mismatch".to_owned());
    }
    let (status, code, payload) = match compose(&request.query) {
        Ok(payload) => ("ok", "ok", payload),
        Err(message) => (
            "error",
            "native_consumer_artifact_compose_validation_refused",
            json!({"error_type": "ValueError", "message": message.chars().take(1024).collect::<String>()}),
        ),
    };
    crate::resident_protocol::encode_response(&ConsumerArtifactComposeResultV1 {
        schema: CONSUMER_ARTIFACT_COMPOSE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload: Some(payload),
    })
}

fn request_digest(request: &ConsumerArtifactComposeRequestV1) -> Result<String, String> {
    let invalid = || "native_consumer_artifact_compose_request_invalid".to_owned();
    let material = serde_json::to_value(request).map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| invalid())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

pub(crate) fn compose(query: &ConsumerArtifactComposeQueryV1) -> Result<Value, String> {
    Ok(match query {
        ConsumerArtifactComposeQueryV1::CurrentAction(query) => current_action(query),
        ConsumerArtifactComposeQueryV1::RuntimeDecision(query) => runtime_decision(query),
        ConsumerArtifactComposeQueryV1::RuntimeAuthoritative(query) => {
            use guard_command::decisions::{build_authoritative_decision, parse_signals};
            let invalid = || "native_consumer_artifact_compose_payload_invalid".to_owned();
            let mut result = runtime_decision(&query.runtime);
            let action = result["policy_action"]
                .as_str()
                .and_then(GuardAction::from_canonical)
                .ok_or_else(invalid)?;
            let reason = result["decision_reason"].as_str().ok_or_else(invalid)?;
            let trace = result["policy_composition"]
                .as_object()
                .ok_or_else(invalid)?;
            let finalized = result["authority_finalized"]
                .as_bool()
                .ok_or_else(invalid)?;
            let signals = parse_signals(&query.signals).map_err(|error| error.to_string())?;
            let decision = build_authoritative_decision(
                action,
                reason,
                trace,
                &signals,
                finalized,
                "composed-consumer-policy",
            )
            .map_err(|error| error.to_string())?;
            result["authoritative_decision"] = decision.to_value();
            result
        }
    })
}

/// The policy engine's configured/changed/default resolution; unknown values
/// fail closed to `require-reapproval`.
fn decide_action(query: &ConsumerCurrentActionQueryV1, changed: bool) -> GuardAction {
    let source = if !query.configured_action.is_null() {
        &query.configured_action
    } else if changed {
        &query.config_changed_hash_action
    } else if !query.effective_default_action.is_null() {
        &query.effective_default_action
    } else {
        &query.config_default_action
    };
    normalize_guard_action(source, GuardAction::RequireReapproval)
}

fn current_action(query: &ConsumerCurrentActionQueryV1) -> Value {
    let floor = |action: GuardAction| {
        if query.skill_directory_identity_reusable == Some(false) {
            stricter(action, GuardAction::RequireReapproval)
        } else {
            action
        }
    };
    if query.removed {
        // A removed artifact has no body to score.
        let current = floor(decide_action(query, true));
        return json!({
            "current_action": current.as_str(),
            "scanner_action": null,
            "verdict": null,
        });
    }
    let verdict = score(query);
    let unconfigured = query.configured_action.is_null();
    let is_request = query
        .artifact_type
        .as_str()
        .is_some_and(|kind| REQUEST_ARTIFACT_TYPES.contains(&kind));
    let effective_default = canonical(&query.effective_default_action);
    let base = if unconfigured && is_request {
        canonical(&query.guard_default_action).unwrap_or(GuardAction::RequireReapproval)
    } else if let (true, true, Some(default)) = (query.first_seen, unconfigured, effective_default)
    {
        default
    } else {
        decide_action(query, query.changed)
    };
    // A low registry trust score raises an unconfigured artifact's fresh
    // decision; a saved approval still applies in the runtime decision.
    let base = match canonical(&query.low_trust_action) {
        Some(low_trust) if unconfigured && (query.first_seen || query.changed) => {
            stricter(base, low_trust)
        }
        _ => base,
    };
    let scanner = verdict.guard_action();
    let current = floor(stricter(base, scanner));
    json!({
        "current_action": current.as_str(),
        "scanner_action": scanner.as_str(),
        "verdict": verdict.to_value(),
    })
}

fn canonical(value: &Value) -> Option<GuardAction> {
    value.as_str().and_then(GuardAction::from_canonical)
}

/// The non-authoritative scoring recommendation that floors the current action.
struct Verdict {
    action: &'static str,
    severity: i64,
    confidence: f64,
    reasons: Vec<String>,
    recommended_next_actions: Vec<&'static str>,
    suppressible: bool,
    review_priority: &'static str,
    evidence_sources: Vec<&'static str>,
    provenance_state: String,
}

impl Verdict {
    fn guard_action(&self) -> GuardAction {
        match self.action {
            "allow" => GuardAction::Allow,
            "warn" => GuardAction::Warn,
            "block" => GuardAction::Block,
            "sandbox_required" => GuardAction::SandboxRequired,
            _ => GuardAction::RequireReapproval,
        }
    }

    fn to_value(&self) -> Value {
        json!({
            "action": self.action,
            "severity": self.severity,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "recommended_next_actions": self.recommended_next_actions,
            "suppressible": self.suppressible,
            "review_priority": self.review_priority,
            "evidence_sources": self.evidence_sources,
            "provenance_state": self.provenance_state,
        })
    }
}

fn score(query: &ConsumerCurrentActionQueryV1) -> Verdict {
    let signals = &query.signals;
    let deltas = &query.deltas;
    let signal_severity = signals.iter().map(|item| item.severity).max().unwrap_or(1);
    let delta_severity = deltas.iter().map(|item| item.severity).max().unwrap_or(1);
    let mut severity = signal_severity.max(delta_severity);
    let mut pool: Vec<f64> = signals.iter().map(|item| item.confidence).collect();
    if !deltas.is_empty() {
        pool.push(0.78);
    }
    if query.provenance_source_kind != "none" {
        pool.push(0.74);
    }
    let mut confidence = pool.into_iter().reduce(f64::max).unwrap_or(0.55);
    let mut ranked: Vec<&ConsumerSignalV1> = signals.iter().collect();
    ranked.sort_by(|left, right| right.severity.cmp(&left.severity));
    let mut reasons: Vec<String> = ranked
        .iter()
        .take(3)
        .map(|item| item.explanation.clone())
        .collect();
    reasons.extend(deltas.iter().take(2).map(|item| item.explanation.clone()));
    if query.prior_approvals > 0 && query.prior_incidents == 0 && severity < 8 {
        reasons.push(PRIOR_APPROVALS_REASON.to_owned());
        confidence = (confidence + 0.05).min(0.98);
    }
    let flagged = matches!(query.publisher_trust.as_str(), "flagged" | "revoked");
    if flagged {
        severity = severity.max(9);
        reasons.push(FLAGGED_PUBLISHER_REASON.to_owned());
    }
    let mut sources: BTreeSet<&'static str> = signals
        .iter()
        .filter_map(|item| evidence_source(&item.evidence_source))
        .collect();
    if query.prior_approvals > 0 || query.prior_incidents > 0 {
        sources.insert("history");
    }
    if matches!(
        query.provenance_source_kind.as_str(),
        "curated" | "signed" | "attested"
    ) {
        sources.insert("cloud");
    }
    let mut evidence_sources: Vec<&'static str> = sources.into_iter().collect();
    if evidence_sources.is_empty() {
        evidence_sources.push("artifact");
    }
    reasons.truncate(4);
    Verdict {
        action: action_from_scoring(severity, confidence, query, deltas),
        severity,
        confidence: python_round3(confidence),
        reasons,
        recommended_next_actions: recommended_actions(signals, deltas, severity),
        suppressible: severity <= 6 && query.publisher_trust != "flagged",
        review_priority: review_priority(severity),
        evidence_sources,
        provenance_state: query.provenance_source_kind.clone(),
    }
}

fn evidence_source(value: &str) -> Option<&'static str> {
    EVIDENCE_SOURCES.into_iter().find(|source| *source == value)
}

fn action_from_scoring(
    severity: i64,
    confidence: f64,
    query: &ConsumerCurrentActionQueryV1,
    deltas: &[ConsumerDeltaV1],
) -> &'static str {
    let flagged = matches!(query.publisher_trust.as_str(), "flagged" | "revoked");
    if (flagged && confidence >= 0.7) || (severity >= 9 && confidence >= 0.75) {
        "block"
    } else if severity >= 8 && query.provenance_source_kind == "none" {
        "sandbox_required"
    } else if severity >= 7
        || deltas
            .iter()
            .any(|delta| REAPPROVAL_DELTAS.contains(&delta.delta_type.as_str()))
    {
        "require_reapproval"
    } else if severity >= 5 {
        "warn"
    } else {
        "allow"
    }
}

fn review_priority(severity: i64) -> &'static str {
    match severity {
        9.. => "critical",
        7..=8 => "high",
        5..=6 => "medium",
        _ => "low",
    }
}

fn recommended_actions(
    signals: &[ConsumerSignalV1],
    deltas: &[ConsumerDeltaV1],
    severity: i64,
) -> Vec<&'static str> {
    let has_delta = |kind: &str| deltas.iter().any(|delta| delta.delta_type == kind);
    let mut actions: Vec<&'static str> = Vec::new();
    if has_delta("new_network_host") {
        actions.push("review_network_destination");
    }
    if has_delta("secret_scope_expanded") {
        actions.push("rotate_exposed_secret");
    }
    if has_delta("subprocess_added") || has_delta("approval_surface_changed") {
        actions.push("approve_once");
    }
    if signals.iter().any(|signal| signal.family == "policy") {
        actions.push("open_investigation");
    }
    if severity >= 8 {
        actions.push("run_in_sandbox");
    }
    if actions.is_empty() {
        actions.extend(["approve_once", "defer_and_notify_team"]);
    }
    actions
}

/// CPython `round(value, 3)`: the exact decimal expansion rounded half-even,
/// read back as the nearest double.
fn python_round3(value: f64) -> f64 {
    format!("{value:.3}").parse().unwrap_or(value)
}

#[cfg(test)]
#[path = "consumer_artifact_compose_op_tests.rs"]
mod tests;
