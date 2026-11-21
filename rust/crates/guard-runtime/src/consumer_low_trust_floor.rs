//! The review floor for an artifact with a low HOL Registry trust score.
//!
//! Port of `guard/consumer/low_trust.py`. Python keeps the registry lookup —
//! an HTTP request with an on-disk cache — and sends what it read; every
//! judgement is made here: whether the artifact qualifies for a score at all,
//! what the `low_trust_artifact` risk action resolves to under the sent
//! configuration, whether the score is below the threshold, and the signal
//! that explains the floor.
//!
//! The lookup is costly, so the answer asks for it rather than assuming it.
//! A query without a score that would otherwise raise the floor comes back
//! with `score_required`, and Python asks again with the score it read. A
//! configured, settled or unscored artifact, or an allowed risk class, is
//! answered without a lookup, exactly as the Python version short-circuited.

use guard_contracts::{
    ConsumerLowTrustFloorQueryV1, RiskConfidenceLabel, RiskRedactionLevel, RiskSeverityLabel,
    RiskSignalCategory, RiskSignalV2,
};
use serde_json::{json, Value};

/// `low_trust_artifact` — the risk class this floor is configured under.
const LOW_TRUST_RISK_KEY: &str = "low_trust_artifact";
/// A registry trust score below this asks the user to review the artifact.
const LOW_TRUST_THRESHOLD: i64 = 80;
/// `allow` adds no floor, so the lookup is skipped entirely.
const FLOOR_ACTIONS: [&str; 5] = [
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
/// Guard artifact types the registry scores. The kind itself is not read here;
/// an artifact type the registry cannot score never reaches a lookup.
const REGISTRY_SCORED_TYPES: [&str; 5] =
    ["skill", "skill_file", "mcp_server", "plugin", "extension"];

pub(crate) fn low_trust_floor(query: &ConsumerLowTrustFloorQueryV1) -> Value {
    let none = || json!({"score_required": false, "floor": null});
    let scored_type = query
        .artifact_type
        .as_str()
        .is_some_and(|kind| REGISTRY_SCORED_TYPES.contains(&kind));
    // A configured override or an unchanged, already decided artifact keeps
    // its decision, and an unscored kind has no score to read.
    if !query.configured_action.is_null() || !query.fresh_decision || !scored_type {
        return none();
    }
    let harness = query.harness.as_str();
    let Some(action) = crate::risk_action::configured_risk_action(
        &query.risk_action_config,
        LOW_TRUST_RISK_KEY,
        harness,
    ) else {
        return none();
    };
    if !FLOOR_ACTIONS.contains(&action.as_str()) {
        return none();
    }
    let Some(score) = query.trust_score else {
        return json!({"score_required": true, "floor": null});
    };
    if score >= LOW_TRUST_THRESHOLD {
        return none();
    }
    json!({
        "score_required": false,
        "floor": {
            "action": action,
            "score": score,
            "signal": signal(query, score).to_value(),
        },
    })
}

fn signal(query: &ConsumerLowTrustFloorQueryV1, score: i64) -> RiskSignalV2 {
    RiskSignalV2 {
        signal_id: format!("{LOW_TRUST_RISK_KEY}:{}", query.artifact_id),
        category: RiskSignalCategory::Publisher,
        severity: RiskSeverityLabel::Medium,
        confidence: RiskConfidenceLabel::Likely,
        detector: "hol_registry_trust".to_owned(),
        title: "Low HOL Registry trust score".to_owned(),
        plain_reason: format!(
            "{} has a HOL Registry trust score of {score}, below the {LOW_TRUST_THRESHOLD} Guard asks you to review.",
            query.artifact_name
        ),
        technical_detail: Some(format!(
            "registry trust score {score} < {LOW_TRUST_THRESHOLD}"
        )),
        evidence_ref: None,
        redaction_level: RiskRedactionLevel::None,
        false_positive_hint: Some(
            "Allow it if you trust this publisher; set low_trust_artifact to allow to stop these reviews."
                .to_owned(),
        ),
        advisory_id: None,
    }
}

#[cfg(test)]
#[path = "consumer_low_trust_floor_tests.rs"]
mod tests;
