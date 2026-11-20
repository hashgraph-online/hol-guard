use super::*;

/// Draft data, requiring a separate trusted host review before binding.
#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BrokerAnswerClaim {
    pub text: String,
    pub citations: Vec<String>,
    pub confidence_bps: Option<u16>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerReviewVerdict {
    Supported,
    Unsupported,
    Contradicted,
    Unknown,
}

#[derive(Clone, Serialize)]
pub struct BrokerClaimReview {
    pub claim_key: String,
    pub verdict: BrokerReviewVerdict,
    pub reviewed_counterevidence: Vec<String>,
}

#[derive(Clone, Default, Serialize)]
pub struct BrokerAnswerPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_sources: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high_confidence_bps: Option<u16>,
}

/// Native host input. Do not derive Deserialize or accept it from an agent.
#[derive(Clone, Serialize)]
pub struct BrokerExecutionReview {
    pub authority_revision: String,
    pub reviews: Vec<BrokerClaimReview>,
    pub policy: BrokerAnswerPolicy,
}

/// Private native handle; IDs and a submitted draft grant no review authority.
pub struct BrokerSubmission {
    pub(super) client: BrokerClientHandle,
    pub(super) retention_id: u64,
    pub(super) id: String,
    pub(super) keys: Vec<String>,
}
impl BrokerSubmission {
    pub fn review_keys(&self) -> &[String] {
        &self.keys
    }
}

// SDK tickets and complete binding bytes stay in native memory and owned IPC.
// Neither handle can be cloned, deserialized, debug-printed or publicly exported.
pub struct BrokerBoundExecution {
    pub(super) client: BrokerClientHandle,
    pub(super) retention_id: u64,
    pub(super) wire: WireBinding,
    pub(super) draft_id: String,
}
pub struct BrokerExecutionHandoff {
    pub(super) effect_id: String,
    pub(super) intent_digest: String,
    pub(super) snapshot_id: String,
}
impl BrokerExecutionHandoff {
    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }
    pub fn intent_digest(&self) -> &str {
        &self.intent_digest
    }
    pub fn metadata(&self) -> Value {
        json!({"schema":"guard-cigar-execution-precondition.v1","data_role":true,
            "effect_id":self.effect_id,"snapshot_id":self.snapshot_id,
            "observation":"context_checked_at_take","approval_grant":false,
            "dispatch_confirmed":false})
    }
}

#[derive(Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct WireBinding {
    pub schema: String,
    pub id: String,
    pub epoch: String,
    pub ticket: String,
    pub submission_id: String,
    pub context_id: String,
    pub snapshot_id: String,
    pub source_authority_digest: String,
    pub review_digest: String,
    pub effect_id: String,
    pub intent_digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireDraft {
    pub snapshot_id: String,
    pub claims: Vec<BrokerAnswerClaim>,
    #[serde(default)]
    pub abstain: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WireSubmission {
    pub submission_id: String,
    pub draft: WireDraft,
    pub review_keys: Vec<String>,
}
