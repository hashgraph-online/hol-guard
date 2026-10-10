//! The decision DTO an MCP tool-call policy pass produces.

use guard_command::approval_reuse::{
    ApprovalReuseDecision, APPROVAL_REUSE_ACCEPTED, APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN,
    APPROVAL_REUSE_NO_SAVED_DECISION, APPROVAL_REUSE_SAVED_ACTION_UNKNOWN,
};
use guard_command::effect_decision::GuardAction;
use serde_json::{json, Map, Value};

use crate::approval_proof_op::Disposition;

/// The recommendation for this call before saved authority is composed.
#[derive(Debug, Clone)]
pub(crate) struct Current {
    pub(crate) action: GuardAction,
    pub(crate) source: String,
    pub(crate) signals: Vec<String>,
    pub(crate) summary: String,
    pub(crate) risk_categories: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct Decision {
    pub(crate) action: GuardAction,
    pub(crate) source: String,
    pub(crate) signals: Vec<String>,
    pub(crate) summary: String,
    pub(crate) risk_categories: Vec<String>,
    pub(crate) normalization_reason_code: Option<String>,
    pub(crate) original_action: Option<String>,
    pub(crate) approval_reuse_status: Option<&'static str>,
    pub(crate) approval_reuse_reason_code: Option<String>,
    pub(crate) current_action: Option<GuardAction>,
    pub(crate) saved_action: Option<GuardAction>,
    pub(crate) pending: Option<Map<String, Value>>,
    pub(crate) claim_disposition: Option<Disposition>,
    pub(crate) post_claim_revalidated: bool,
}

impl Decision {
    /// A decision with no saved-approval composition behind it.
    pub(crate) fn plain(current: Current) -> Self {
        Self {
            action: current.action,
            source: current.source,
            signals: current.signals,
            summary: current.summary,
            risk_categories: current.risk_categories,
            normalization_reason_code: None,
            original_action: None,
            approval_reuse_status: None,
            approval_reuse_reason_code: None,
            current_action: None,
            saved_action: None,
            pending: None,
            claim_disposition: None,
            post_claim_revalidated: false,
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        json!({
            "action": self.action.as_str(),
            "source": self.source,
            "signals": self.signals,
            "summary": self.summary,
            "risk_categories": self.risk_categories,
            "normalization_reason_code": self.normalization_reason_code,
            "original_action": self.original_action,
            "approval_reuse_status": self.approval_reuse_status,
            "approval_reuse_reason_code": self.approval_reuse_reason_code,
            "current_action": self.current_action.map(GuardAction::as_str),
            "saved_action": self.saved_action.map(GuardAction::as_str),
            "pending_approval_reuse_decision": self.pending,
            "approval_reuse_claim_disposition": self.claim_disposition.map(Disposition::as_str),
            "post_claim_revalidated": self.post_claim_revalidated,
            "post_claim_authority": if self.post_claim_revalidated { json!("fresh") } else { Value::Null },
        })
    }
}

/// Python `a or b` over optional strings: an empty string is falsy.
fn first_truthy(first: &Option<String>, second: &Option<String>) -> Option<String> {
    match first {
        Some(text) if !text.is_empty() => Some(text.clone()),
        _ => second.clone(),
    }
}

/// Present a reuse composition as a decision for the current call.
pub(crate) fn with_reuse(
    current: &Current,
    reuse: &ApprovalReuseDecision,
    pending: Option<Map<String, Value>>,
) -> Decision {
    let (source, summary) = match reuse.reason_code.as_str() {
        APPROVAL_REUSE_SAVED_ACTION_UNKNOWN => (
            "policy-invalid".to_owned(),
            "Local Guard found an unknown policy action in saved state and requires reapproval."
                .to_owned(),
        ),
        APPROVAL_REUSE_CURRENT_ACTION_UNKNOWN => (
            "policy-invalid".to_owned(),
            "Local Guard found an unknown current policy action and blocked the tool call."
                .to_owned(),
        ),
        APPROVAL_REUSE_ACCEPTED => (
            "policy".to_owned(),
            "Local Guard reused an exact saved approval for the current reviewable tool call."
                .to_owned(),
        ),
        APPROVAL_REUSE_NO_SAVED_DECISION => (current.source.clone(), current.summary.clone()),
        _ if reuse.saved_action == Some(GuardAction::Block) => (
            "policy".to_owned(),
            "Local Guard kept this tool call blocked by saved policy.".to_owned(),
        ),
        reason => (
            current.source.clone(),
            format!(
                "{} Saved approval was not reused ({reason}).",
                current.summary
            ),
        ),
    };
    Decision {
        action: reuse.action,
        source,
        signals: current.signals.clone(),
        summary,
        risk_categories: current.risk_categories.clone(),
        normalization_reason_code: reuse
            .saved_normalization_reason_code
            .clone()
            .or_else(|| reuse.current_normalization_reason_code.clone()),
        original_action: first_truthy(&reuse.original_saved_action, &reuse.original_current_action),
        approval_reuse_status: Some(reuse.status),
        approval_reuse_reason_code: Some(reuse.reason_code.clone()),
        current_action: Some(reuse.current_action),
        saved_action: reuse.saved_action,
        pending,
        claim_disposition: None,
        post_claim_revalidated: false,
    }
}
