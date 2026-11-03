//! What one consumer artifact evaluation concluded.
//!
//! Python gathers the evidence, asks the resident to compose the runtime
//! decision and does the store writes. This module decides what that composed
//! decision means for the evaluation: the policy action, whether the harness
//! blocks, whether the stored snapshot may advance, the risk copy, the result
//! row, the receipt fields and the change event. Without a composed decision
//! the artifact blocks with the transport error attached; no authority or
//! permission is synthesized for it.

use guard_command::decisions::{parse_signals, AuthoritativeGuardDecision};
use guard_contracts::RiskSignalV2;
use serde_json::{json, Value};

use crate::consumer_result::{artifact_result, removed_result};

const INVALID: &str = "native_consumer_artifact_project_request_invalid";
const COMPOSE_UNAVAILABLE_REASON: &str = "consumer_artifact_compose_unavailable";
const REMOVED_SCORING_RECOMMENDATION: &str = "warn";

/// The compose reason a runtime detector block records.
const RUNTIME_DETECTOR_BLOCK_REASON: &str = "runtime_detector_block";

/// The composed runtime answer, or the refusal shown in its place.
struct Runtime {
    answer: Value,
    decision: Option<AuthoritativeGuardDecision>,
}

impl Runtime {
    /// Decode the compose answer, or build the refusal for `compose_error`.
    /// An answer must carry its authoritative decision; a query with neither
    /// is malformed.
    fn resolve(
        query: &Value,
        scanner_action: &Value,
        raw_scoring_recommendation: &Value,
    ) -> Result<Self, &'static str> {
        let runtime = &query["runtime"];
        if runtime.is_object() {
            let decision = AuthoritativeGuardDecision::decode(&runtime["authoritative_decision"])
                .map_err(|_| INVALID)?;
            return Ok(Self {
                answer: runtime.clone(),
                decision: Some(decision),
            });
        }
        let code = query["compose_error"].as_str().ok_or(INVALID)?;
        Ok(Self {
            answer: compose_unavailable(
                code,
                &query["configured_action"],
                scanner_action,
                raw_scoring_recommendation,
            ),
            decision: None,
        })
    }

    fn policy_action(&self) -> &'static str {
        self.decision
            .as_ref()
            .map_or("block", |decision| decision.action.as_str())
    }

    fn blocking(&self) -> bool {
        self.decision
            .as_ref()
            .is_none_or(|decision| decision.enforcement.blocking)
    }

    fn snapshot_permitted(&self) -> bool {
        self.decision
            .as_ref()
            .is_some_and(|decision| decision.enforcement.snapshot_permitted)
    }

    /// `to_artifact_projection()` of the decision, or the refusal fields.
    fn projection(&self) -> Value {
        let Some(decision) = &self.decision else {
            return json!({
                "policy_action": "block",
                "decision_reason": self.answer["decision_reason"],
                "policy_composition": self.answer["policy_composition"],
                "evaluation_error": self.answer["evaluation_error"],
            });
        };
        let raw = &self.answer["authoritative_decision"];
        json!({
            "authoritative_decision": raw,
            "policy_action": decision.action.as_str(),
            "decision_v2_json": raw["decision_v2"],
            "policy_composition": raw["composition_trace"],
            "verdict_action": decision.action.as_str(),
        })
    }

    /// The decision's signals as sent, or the signals it would have been
    /// composed from, with their plain reasons.
    fn signals(&self, fallback: &Value) -> Result<(Value, Vec<Value>), &'static str> {
        let (raw, decoded) = match &self.decision {
            Some(decision) => (
                self.answer["authoritative_decision"]["signals"].clone(),
                decision.signals.clone(),
            ),
            None => (
                fallback.clone(),
                parse_signals(fallback).map_err(|_| INVALID)?,
            ),
        };
        Ok((raw, plain_reasons(&decoded)))
    }

    /// The runtime detector decided when it contributed signals or its
    /// action shaped the composition.
    fn runtime_authority(&self, runtime_signals_present: bool) -> bool {
        runtime_signals_present
            || self.answer["policy_composition"]
                .get("runtime_detector_action")
                .is_some()
    }

    fn dashboard_detail(&self) -> Option<&str> {
        self.decision
            .as_ref()
            .map(|decision| decision.decision_v2.dashboard_primary_detail.as_str())
    }

    /// The request's override label, only when the trusted request decided
    /// and no runtime detector block overruled it.
    fn user_override(&self, query: &Value) -> Value {
        if self.answer["trusted_request_override"] == Value::Bool(true)
            && self.answer["decision_reason"] != RUNTIME_DETECTOR_BLOCK_REASON
        {
            query["user_override"].clone()
        } else {
            Value::Null
        }
    }

    fn event(
        &self,
        artifact_id: &Value,
        artifact_name: &Value,
        changed_fields: &Value,
        harness: &Value,
    ) -> Value {
        let reuse = &self.answer["approval_reuse"];
        json!({
            "harness": harness,
            "artifact_id": artifact_id,
            "artifact_name": artifact_name,
            "policy_action": self.policy_action(),
            "changed_fields": changed_fields,
            "approval_reuse_status": reuse["status"],
            "approval_reuse_reason_code": reuse["reason_code"],
        })
    }
}

fn plain_reasons(signals: &[RiskSignalV2]) -> Vec<Value> {
    signals
        .iter()
        .map(|signal| Value::String(signal.plain_reason.clone()))
        .collect()
}

/// Refusal presentation when the resident composed nothing: the artifact
/// blocks and carries the transport error for diagnosis.
pub(crate) fn compose_unavailable(
    code: &str,
    configured_action: &Value,
    scanner_action: &Value,
    raw_scoring_recommendation: &Value,
) -> Value {
    json!({
        "approval_claim": null,
        "approval_reuse": {
            "action": "block",
            "current_action": "block",
            "current_normalization_reason_code": null,
            "original_current_action": "block",
            "original_current_type": "str",
            "original_saved_action": null,
            "original_saved_type": null,
            "reason_code": COMPOSE_UNAVAILABLE_REASON,
            "saved_action": null,
            "saved_normalization_reason_code": null,
            "should_claim": false,
            "status": "not-applicable",
        },
        "approval_source": "policy",
        "append_pending_claim": false,
        "evaluation_error": {"code": code, "component": "consumer_artifact_compose"},
        "decision_reason": COMPOSE_UNAVAILABLE_REASON,
        "policy_action": "block",
        "policy_composition": {
            "configured_action": configured_action,
            "current_action": "block",
            "final_action": "block",
            "native_compose_error": code,
            "raw_scoring_recommendation": raw_scoring_recommendation,
            "saved_action": null,
            "saved_state_present": false,
            "scanner_action": scanner_action,
            "scoring_recommendation_non_authoritative": true,
            "trusted_request_override": false,
        },
        "saved_state_present": false,
        "scanner_evidence": [],
        "trusted_request_override": false,
    })
}

/// Scoring verdict shown when the current-action query failed.
pub(crate) fn unscored_verdict() -> Value {
    json!({
        "action": "block",
        "confidence": 0.0,
        "evidence_sources": [],
        "provenance_state": "none",
        "reasons": ["Guard could not score this artifact, so it stays blocked."],
        "recommended_next_actions": ["open_investigation"],
        "review_priority": "critical",
        "severity": 9,
        "suppressible": false,
    })
}

fn outcome(runtime: &Runtime, result: Value, receipt: Value, event: Value) -> Value {
    json!({
        "result": result,
        "policy_action": runtime.policy_action(),
        "blocking": runtime.blocking(),
        "snapshot_permitted": runtime.snapshot_permitted(),
        "receipt": receipt,
        "event": event,
    })
}

/// Outcome of a detected artifact.
pub(crate) fn artifact_outcome(query: &Value) -> Result<Value, &'static str> {
    let verdict = match &query["verdict"] {
        Value::Object(_) => query["verdict"].clone(),
        // Only a failed current-action query leaves the artifact unscored.
        Value::Null if query["compose_error"].is_string() => unscored_verdict(),
        _ => return Err(INVALID),
    };
    let scanner_action = &query["scanner_action"];
    let runtime = Runtime::resolve(query, scanner_action, &verdict["action"])?;
    let (_, risk_signals) = runtime.signals(&query["decision_signals"])?;
    let runtime_authority =
        runtime.runtime_authority(query["runtime_signals_present"] == Value::Bool(true));
    let risk_summary = match runtime.dashboard_detail() {
        Some(detail) if runtime_authority => json!(detail),
        _ => query["static_risk_summary"].clone(),
    };
    let policy_action = runtime.policy_action();
    let result = artifact_result(&json!({
        "harness": query["harness"],
        "artifact": query["artifact"],
        "evidence": query["evidence"],
        "projection": runtime.projection(),
        "verdict": verdict,
        "scanner_action": scanner_action,
        "runtime": runtime.answer,
        "signals": query["signals"],
        "risk_signals": risk_signals,
        "risk_summary": risk_summary,
        "approval_context_hash": query["approval_context_hash"],
        "effective_workspace": query["effective_workspace"],
        "policy_action": policy_action,
    }))?;
    let artifact = &query["artifact"];
    let evidence = &query["evidence"];
    let receipt = json!({
        "artifact_hash": evidence["current_hash"],
        "policy_decision": policy_action,
        "capabilities_summary": evidence["capabilities_summary"],
        "changed_capabilities": evidence["changed_capabilities"],
        "provenance_summary": evidence["provenance_summary"],
        "artifact_name": artifact["name"],
        "source_scope": artifact["source_scope"],
        "user_override": runtime.user_override(query),
        "diff_summary": evidence["diff_summary"],
        "approval_source": runtime.answer["approval_source"],
        "scanner_evidence": runtime.answer["scanner_evidence"],
    });
    let caught =
        evidence["changed"] == Value::Bool(true) && evidence["first_seen"] != Value::Bool(true);
    let event = if caught {
        runtime.event(
            &artifact["artifact_id"],
            &artifact["name"],
            &evidence["changed_fields"],
            &query["harness"],
        )
    } else {
        Value::Null
    };
    Ok(outcome(&runtime, result, receipt, event))
}

/// Outcome of an artifact removed from the harness.
pub(crate) fn removed_outcome(query: &Value) -> Result<Value, &'static str> {
    // Removal has no artifact body to score. The historical warn
    // recommendation stays diagnostic evidence, never an enforcement input.
    let runtime = Runtime::resolve(query, &Value::Null, &json!(REMOVED_SCORING_RECOMMENDATION))?;
    let decision_signals = &query["decision_signals"];
    let (signals, risk_signals) = runtime.signals(decision_signals)?;
    let runtime_signals_present = decision_signals
        .as_array()
        .is_some_and(|items| !items.is_empty());
    let policy_action = runtime.policy_action();
    let removed = removed_result(&json!({
        "harness": query["harness"],
        "artifact_id": query["artifact_id"],
        "previous": query["previous"],
        "previous_hash": query["previous_hash"],
        "projection": runtime.projection(),
        "runtime": runtime.answer,
        "signals": signals,
        "risk_signals": risk_signals,
        "has_runtime_authority": runtime.decision.is_some()
            && runtime.runtime_authority(runtime_signals_present),
        "dashboard_detail": runtime.dashboard_detail(),
        "approval_context_hash": query["approval_context_hash"],
        "effective_workspace": query["effective_workspace"],
        "policy_action": policy_action,
    }))?;
    let summary = &removed["receipt"];
    let receipt = json!({
        "artifact_hash": query["previous_hash"],
        "policy_decision": policy_action,
        "capabilities_summary": summary["capabilities_summary"],
        "changed_capabilities": ["removed"],
        "provenance_summary": summary["provenance_summary"],
        "artifact_name": summary["artifact_name"],
        "source_scope": summary["source_scope"],
        "user_override": runtime.user_override(query),
        "diff_summary": "artifact removed",
        "approval_source": runtime.answer["approval_source"],
        "scanner_evidence": runtime.answer["scanner_evidence"],
    });
    let event = runtime.event(
        &query["artifact_id"],
        &summary["artifact_name"],
        &json!(["removed"]),
        &query["harness"],
    );
    Ok(outcome(&runtime, removed["result"].clone(), receipt, event))
}

#[cfg(test)]
#[path = "consumer_outcome_tests.rs"]
mod tests;
