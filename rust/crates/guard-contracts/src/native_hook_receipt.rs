use serde::{Deserialize, Serialize};

use super::{GuardHookPayloadKindV2, NATIVE_PROTOCOL_VERSION};

/// Versioned, aggregate-only evidence emitted by the Rust decision edge.
///
/// This contract intentionally contains no request payload, command, prompt,
/// path, URL, secret, or free-form reason.  It is safe to hand to an
/// asynchronous persistence consumer because it cannot reconstruct the input
/// that produced the decision.
pub const NATIVE_HOOK_DECISION_RECEIPT_V1_SCHEMA: &str = "guard-native-hook-decision-receipt.v1";
pub const NATIVE_HOOK_DECISION_RECEIPT_MAX_BYTES: usize = 16 * 1024;
pub const NATIVE_HOOK_DECISION_RECEIPT_MAX_STRING_BYTES: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeHookDecisionReceiptV1 {
    pub schema: String,
    pub version: u16,
    pub authority: String,
    /// SHA-256 of the remaining receipt identity fields.  This is the stable
    /// idempotency key for retries and process restarts.
    pub decision_id: String,
    pub request_id: String,
    pub request_digest: String,
    /// Policy-independent native evidence for the exact action/source input.
    /// This is integrity evidence only, never an approval or execution grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_intent_digest: Option<String>,
    /// Commitment to a private prepared business review, not provider identity
    /// evidence or an execution grant. Ordinary hook evaluation omits it.
    #[serde(
        default,
        deserialize_with = "present_business_binding",
        skip_serializing_if = "Option::is_none"
    )]
    pub business_review_binding: Option<String>,
    pub harness: String,
    pub event_name: String,
    pub payload_kind: GuardHookPayloadKindV2,
    pub policy_generation: u64,
    pub policy_digest: Option<String>,
    pub rule_digest: Option<String>,
    pub runtime_identity: Option<String>,
    pub decision: String,
    pub model_output_action: String,
    pub policy_action: Option<String>,
    pub observed_policy_action: Option<String>,
    pub reason_code: String,
    pub workspace_bound: bool,
    pub source_ref_external_allowed: bool,
    pub reviewed_output_sha256: Option<String>,
    pub observe_mode: bool,
    pub deadline_budget_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_extensions: Option<super::NativeCommandReceiptBindingV1>,
    /// Resident-authenticated origin evidence, not an approval or execution grant.
    /// Omitted by legacy and isolated evaluation paths that have no trusted store.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_authentication: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_risk_classes: Vec<super::NativePromptRiskClassV1>,
}

fn present_business_binding<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(d).map(Some)
}

impl NativeHookDecisionReceiptV1 {
    pub fn protocol_version(&self) -> u16 {
        NATIVE_PROTOCOL_VERSION
    }
}
