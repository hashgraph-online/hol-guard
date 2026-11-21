//! `HookDecide` `artifact_reuse_step` — the artifact hook's approval-reuse
//! state machine.
//!
//! Python used to walk this ladder itself: look up the saved approval, decide
//! whether to claim it, ask again after a failed claim, let a trusted browser
//! request override a review, and settle the claimed approval's re-evaluation.
//! Every rung was a verdict. This answers the whole walk in one query, as a
//! plan the transport executes: a `claim` effect (with the plan for each of its
//! two outcomes), a `revalidate` effect, or the settlement.
//!
//! The approval invariant is held by construction. A saved approval that can be
//! claimed is claimed only through a `claim` effect, and a won claim always
//! continues into `revalidate`, so an Allow once binding is spent only by the
//! execution it was issued for and an Always allow is claimed (retained) and
//! revalidated against its command hash like any other. A lost claim continues
//! into the already-settled answer for that case, so no resident round trip
//! sits between consuming an approval and acting on it.
//!
//! The pieces are the pure `saved_reuse`, `package_reuse_settle`,
//! `trusted_override` and `claimed_reuse` queries of `HookArtifactCompose`;
//! this module sequences them and shapes the evidence Python records.

use guard_contracts::{
    ArtifactReusePlanV1, ArtifactReuseStepInputsV1, ClaimedReuseQueryV1, PackageReuseSettleQueryV1,
    PriorReuseV1, ReuseLookupV1, ReuseSavedFactsV1, SavedReuseQueryV1, TrustedOverrideQueryV1,
};
use serde_json::{json, Value};

use crate::hook_artifact_compose_reuse::{
    claimed_reuse, input_evidence, package_reuse_settle, saved_reuse, trusted_override,
};

const INVALID: &str = "native_hook_decision_artifact_reuse_step_invalid";
const CLAIM_FAILED: &str = "approval_reuse_claim_failed";
const REAPPROVAL_REQUIRED: &str = "approval_reuse_reapproval_required";

/// The keys Python's `ApprovalReuseDecision.to_evidence()` always emits. The
/// native decision leaves the unset ones out; the evidence records them as
/// explicit nulls, as it always has.
const EVIDENCE_KEYS: [&str; 12] = [
    "action",
    "status",
    "reason_code",
    "current_action",
    "saved_action",
    "should_claim",
    "current_normalization_reason_code",
    "saved_normalization_reason_code",
    "original_current_action",
    "original_saved_action",
    "original_current_type",
    "original_saved_type",
];

fn invalid() -> String {
    INVALID.to_owned()
}

/// A decision's evidence with every always-present key spelled out.
fn shaped(reuse: &Value) -> Value {
    let mut fields = reuse.as_object().cloned().unwrap_or_default();
    for key in EVIDENCE_KEYS {
        fields.entry(key).or_insert(Value::Null);
    }
    Value::Object(fields)
}

fn text(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn required_text(value: &Value, key: &str) -> Result<String, String> {
    text(value, key).ok_or_else(invalid)
}

fn reuse_of(answer: &Value) -> Result<Value, String> {
    answer
        .get("approval_reuse")
        .filter(|reuse| reuse.is_object())
        .cloned()
        .ok_or_else(invalid)
}

/// The saved action as a trimmed, non-empty string, the way the hook always
/// read it (Python's `str.strip` also strips the four ASCII separators).
fn trimmed_action(value: &Value) -> Value {
    let separators = |c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c);
    value
        .as_str()
        .map(|action| action.trim_matches(separators))
        .filter(|action| !action.is_empty())
        .map_or(Value::Null, |action| json!(action))
}

/// Everything the walk has settled so far.
#[derive(Clone)]
struct Walk<'a> {
    inputs: &'a ArtifactReuseStepInputsV1,
    policy_action: String,
    source: Option<String>,
    reuse: Option<Value>,
    package_reuse: Option<Value>,
    evidence: Vec<Value>,
    override_applied: bool,
    override_reason: Option<String>,
    package_risk_refresh: bool,
}

pub(crate) fn artifact_reuse_step(
    inputs: &ArtifactReuseStepInputsV1,
) -> Result<ArtifactReusePlanV1, String> {
    let walk = Walk {
        inputs,
        policy_action: String::new(),
        source: None,
        reuse: None,
        package_reuse: None,
        evidence: Vec::new(),
        override_applied: false,
        override_reason: None,
        package_risk_refresh: false,
    };
    match &inputs.lookup {
        ReuseLookupV1::Package {
            reasons,
            evaluation_policy_action,
        } => walk.package(reasons, evaluation_policy_action),
        ReuseLookupV1::Tool {
            saved,
            workflow_preflight,
        } => walk.tool(saved, *workflow_preflight),
    }
}

impl Walk<'_> {
    fn action(&self) -> Value {
        json!(self.policy_action)
    }

    /// A package request's evaluation already read the saved decision; the
    /// settlement says what its reasons recorded.
    fn package(
        mut self,
        reasons: &[Value],
        evaluation_policy_action: &Value,
    ) -> Result<ArtifactReusePlanV1, String> {
        let inputs = self.inputs;
        let stored = inputs.stored.as_ref();
        let settle = package_reuse_settle(&PackageReuseSettleQueryV1 {
            reasons: reasons.to_vec(),
            claim_saved_approval: inputs.claim_saved_approval,
            current_action: inputs.current_action.clone(),
            evaluation_policy_action: evaluation_policy_action.clone(),
            stored_policy_action: stored.map_or(Value::Null, |row| trimmed_action(&row.action)),
            stored_artifact_hash: stored.map_or(Value::Null, |row| row.artifact_hash.clone()),
            approval_reuse_source: Value::Null,
        });
        self.reuse = settle["approval_reuse"]
            .is_object()
            .then(|| settle["approval_reuse"].clone());
        if let Some(appends) = settle["evidence_appends"].as_array() {
            self.evidence.extend(appends.iter().cloned());
        }
        if settle["revalidate_required"] == json!(true) {
            // The package resolver already claimed the saved approval; what is
            // left is the execution-boundary re-evaluation.
            return Ok(ArtifactReusePlanV1::Revalidate {
                trusted_request_override: false,
                package_approval_consumed: settle["claim_disposition"] == json!("consumed"),
                request_id: None,
            });
        }
        self.policy_action = required_text(&settle, "policy_action")?;
        self.source = text(&settle, "approval_reuse_source");
        self.package_reuse = settle["reuse_evidence"]
            .is_object()
            .then(|| settle["reuse_evidence"].clone());
        if let Some(appends) = settle["settled_evidence_appends"].as_array() {
            self.evidence.extend(appends.iter().cloned());
        }
        self.package_risk_refresh = self.action() != inputs.current_action;
        self.override_stage()
    }

    /// A tool request: the saved approval is looked up, and claimed when the
    /// decision says it should be.
    fn tool(
        mut self,
        saved: &ReuseSavedFactsV1,
        workflow_preflight: bool,
    ) -> Result<ArtifactReusePlanV1, String> {
        let inputs = self.inputs;
        // The lookup and the store read one saved decision; facts that
        // disagree about whether it exists describe no real request.
        if saved.stored_present != inputs.stored.is_some() {
            return Err(invalid());
        }
        let query = saved.query(&inputs.current_action);
        let answer = saved_reuse(&query);
        let reuse = reuse_of(&answer)?;
        self.source = text(&answer, "approval_reuse_source");
        let request_id = inputs
            .stored
            .as_ref()
            .and_then(|row| row.request_id.clone());
        let workflow_pending = text(&reuse, "reason_code").as_deref() == Some(REAPPROVAL_REQUIRED)
            && request_id.is_some()
            && workflow_preflight;
        let should_claim = reuse["should_claim"] == json!(true);
        if (should_claim || workflow_pending)
            && inputs.stored.is_some()
            && inputs.claim_saved_approval
        {
            let failed = saved_reuse(&SavedReuseQueryV1 {
                stored_present: true,
                integrity_failure: false,
                stored_validation_reason: Some(CLAIM_FAILED.to_owned()),
                ..query
            });
            let mut lost = self.clone();
            lost.reuse = Some(reuse_of(&failed)?);
            return Ok(ArtifactReusePlanV1::Claim {
                on_claimed: Box::new(ArtifactReusePlanV1::Revalidate {
                    trusted_request_override: false,
                    package_approval_consumed: false,
                    request_id,
                }),
                on_failed: Box::new(lost.saved_settled()?),
            });
        }
        self.reuse = Some(reuse);
        self.saved_settled()
    }

    /// The saved lookup is settled: its action stands and its evidence is
    /// recorded.
    fn saved_settled(mut self) -> Result<ArtifactReusePlanV1, String> {
        let reuse = self.reuse.clone().ok_or_else(invalid)?;
        self.policy_action = required_text(&reuse, "action")?;
        if let Some(source) = &self.source {
            self.evidence.push(input_evidence(source, &shaped(&reuse)));
        }
        self.override_stage()
    }

    /// A trusted browser request resolved this exact request: its saved allow
    /// is claimed, then the request is revalidated as that approval's run.
    fn override_stage(self) -> Result<ArtifactReusePlanV1, String> {
        let inputs = self.inputs;
        let Some(facts) = &inputs.trusted_override else {
            return self.claimed_stage();
        };
        let stored = inputs.stored.as_ref();
        let query = TrustedOverrideQueryV1 {
            token_validation_reason: facts.token_validation_reason.clone(),
            policy_action: self.action(),
            remembered_rule_rejected: inputs.remembered_rule_rejected,
            prior_reuse_reason_code: self
                .reuse
                .as_ref()
                .and_then(|reuse| text(reuse, "reason_code")),
            stored_present: stored.is_some(),
            stored_action: stored.map_or(Value::Null, |row| row.action.clone()),
            stored_source: stored.map_or(Value::Null, |row| row.source.clone()),
            stored_validation_reason: stored.and_then(|_| facts.stored_validation_reason.clone()),
            claim_succeeded: None,
        };
        let answer = trusted_override(&query);
        let Some(row) = stored.filter(|_| answer["claim_required"] == json!(true)) else {
            return self.with_override(&answer).claimed_stage();
        };
        let lost = trusted_override(&TrustedOverrideQueryV1 {
            claim_succeeded: Some(false),
            ..query
        });
        Ok(ArtifactReusePlanV1::Claim {
            on_claimed: Box::new(ArtifactReusePlanV1::Revalidate {
                trusted_request_override: true,
                package_approval_consumed: false,
                request_id: row.request_id.clone(),
            }),
            on_failed: Box::new(self.with_override(&lost).claimed_stage()?),
        })
    }

    fn with_override(mut self, answer: &Value) -> Self {
        self.override_reason = text(answer, "reason_code");
        self.evidence.push(answer["evidence"].clone());
        self
    }

    /// The pass that re-evaluates a claimed approval settles what the claim
    /// left behind.
    fn claimed_stage(mut self) -> Result<ArtifactReusePlanV1, String> {
        let inputs = self.inputs;
        let Some(claimed) = &inputs.claimed else {
            return self.settled();
        };
        let answer = claimed_reuse(&ClaimedReuseQueryV1 {
            claimed_hash: json!(claimed.claimed_hash),
            token_validation_reason: claimed.token_validation_reason.clone(),
            post_claim_refresh_failed: claimed.post_claim_refresh_failed,
            remembered_rule_rejected: inputs.remembered_rule_rejected,
            prior_reuse: self.reuse.as_ref().map(|reuse| PriorReuseV1 {
                action: reuse["action"].clone(),
                saved_action: reuse["saved_action"].clone(),
                reason_code: text(reuse, "reason_code"),
            }),
            package_reuse_saved_action: self
                .package_reuse
                .as_ref()
                .map_or(Value::Null, |reuse| reuse["saved_action"].clone()),
            workflow_capability_required: claimed.workflow_capability_required,
            workflow_authorization_claimed: claimed.workflow_authorization_claimed,
            policy_action: self.action(),
            current_policy_action: inputs.current_action.clone(),
            claimed_trusted_request_override: claimed.claimed_trusted_request_override,
            claimed_package_approval_consumed: claimed.claimed_package_approval_consumed,
        });
        self.reuse = Some(reuse_of(&answer)?);
        self.policy_action = required_text(&answer, "policy_action")?;
        self.source = text(&answer, "approval_reuse_source");
        self.override_applied = answer["trusted_request_override_applied"] == json!(true);
        self.override_reason = text(&answer, "trusted_request_override_reason");
        self.evidence.push(answer["evidence"].clone());
        self.settled()
    }

    fn settled(self) -> Result<ArtifactReusePlanV1, String> {
        if self.policy_action.is_empty() {
            return Err(invalid());
        }
        Ok(ArtifactReusePlanV1::Settled {
            policy_action: self.policy_action,
            approval_reuse_source: self.source,
            trusted_request_override_applied: self.override_applied,
            trusted_request_override_reason: self.override_reason,
            evidence: self.evidence,
            approval_reuse: match &self.reuse {
                Some(reuse) => Some(shaped(reuse)),
                None => self.package_reuse,
            },
            package_risk_refresh: self.package_risk_refresh,
        })
    }
}

#[cfg(test)]
#[path = "hook_decision_artifact_reuse_step_tests.rs"]
mod tests;
