use serde::{Deserialize, Serialize};

use super::{
    GuardHookEnvelopeV2, NativeApprovalFloorClassV3, PreToolActionTypeV1, PreToolOperationV1,
};

/// Root-signed passkey authority. Credential and COSE key values are encoded
/// as lower-case hex so the Rust resident can compare exact bytes without
/// relying on a presentation-layer decoder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalAuthorityV4 {
    pub schema: String,
    pub version: u16,
    pub key_id: String,
    pub rp_id: String,
    pub origin: String,
    pub credential_id: String,
    pub cose_public_key: String,
    pub algorithm: i32,
    pub device_binding: String,
    pub installation_binding: String,
    pub enrollment_generation: u64,
    pub previous_key_id: Option<String>,
    pub status: String,
    pub enrollment_signature: String,
}

/// Public ceremony request. The external passkey ceremony returns a
/// root-signed `ApprovalAuthorityV4`; this request never authorizes anything.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalEnrollmentRequestV4 {
    pub schema: String,
    pub version: u16,
    pub rp_id: String,
    pub origin: String,
    pub device_binding: String,
    pub installation_binding: String,
    pub enrollment_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnChallengeV4 {
    pub rp_id: String,
    pub origin: String,
    pub credential_id: String,
    pub algorithm: i32,
    /// Base64url, without padding, of the exact Rust-issued challenge bytes.
    pub challenge: String,
    pub user_verification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnAssertionV4 {
    /// Browser credential identifier, base64url without padding.
    pub id: String,
    /// Browser raw credential identifier, base64url without padding.
    #[serde(rename = "rawId")]
    pub raw_id: String,
    #[serde(rename = "type")]
    pub assertion_type: String,
    pub response: WebAuthnAssertionResponseV4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnAssertionResponseV4 {
    /// Standard WebAuthn response members, base64url without padding.
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalChallengeRequestV4 {
    pub schema: String,
    pub version: u16,
    pub envelope: GuardHookEnvelopeV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalValidateRequestV4 {
    pub schema: String,
    pub version: u16,
    pub envelope: GuardHookEnvelopeV2,
    pub artifact: ApprovalArtifactV4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConsumeRequestV4 {
    pub schema: String,
    pub version: u16,
    pub envelope: GuardHookEnvelopeV2,
    pub artifact: ApprovalArtifactV4,
}

/// V4 repeats the V3 action/policy/runtime/scope fields deliberately. This
/// makes the signed transport object self-contained and prevents a caller
/// from substituting a V3 object or a database row for a V4 assertion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalChallengeV4 {
    pub schema: String,
    pub version: u16,
    pub request_id: String,
    pub request_digest: String,
    pub action_digest: String,
    pub action_type: PreToolActionTypeV1,
    pub operation: PreToolOperationV1,
    pub intrinsic_action: String,
    pub minimum_action: String,
    pub floor_class: NativeApprovalFloorClassV3,
    pub approval_eligible: bool,
    pub policy_generation: u64,
    pub policy_digest: String,
    pub rule_digest: String,
    pub runtime_identity: String,
    pub runtime_protocol_version: u16,
    pub runtime_package: String,
    pub runtime_version: String,
    pub runtime_binary_identity: String,
    pub harness: String,
    pub workspace_binding: Option<String>,
    pub device_binding: Option<String>,
    pub installation_binding: Option<String>,
    pub publisher_binding: Option<String>,
    pub artifact_binding: Option<String>,
    pub scope_contract_version: String,
    pub scope_contract_digest: String,
    pub scope_binding: Option<String>,
    pub resident_epoch: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub requested_action: String,
    pub signing_key_id: String,
    pub webauthn: WebAuthnChallengeV4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalArtifactV4 {
    pub schema: String,
    pub version: u16,
    pub request_id: String,
    pub request_digest: String,
    pub action_digest: String,
    pub action_type: PreToolActionTypeV1,
    pub operation: PreToolOperationV1,
    pub intrinsic_action: String,
    pub minimum_action: String,
    pub floor_class: NativeApprovalFloorClassV3,
    pub approval_eligible: bool,
    pub policy_generation: u64,
    pub policy_digest: String,
    pub rule_digest: String,
    pub runtime_identity: String,
    pub runtime_protocol_version: u16,
    pub runtime_package: String,
    pub runtime_version: String,
    pub runtime_binary_identity: String,
    pub harness: String,
    pub workspace_binding: Option<String>,
    pub device_binding: Option<String>,
    pub installation_binding: Option<String>,
    pub publisher_binding: Option<String>,
    pub artifact_binding: Option<String>,
    pub scope_contract_version: String,
    pub scope_contract_digest: String,
    pub scope_binding: Option<String>,
    pub resident_epoch: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub requested_action: String,
    pub approved_action: String,
    pub signing_key_id: String,
    pub webauthn: WebAuthnAssertionV4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReceiptV4 {
    pub schema: String,
    pub version: u16,
    pub phase: String,
    pub request_id: String,
    pub request_digest: String,
    pub action_digest: String,
    pub policy_generation: u64,
    pub policy_digest: String,
    pub rule_digest: String,
    pub runtime_identity: String,
    pub runtime_protocol_version: u16,
    pub runtime_package: String,
    pub runtime_version: String,
    pub runtime_binary_identity: String,
    pub harness: String,
    pub workspace_binding: Option<String>,
    pub device_binding: Option<String>,
    pub installation_binding: Option<String>,
    pub publisher_binding: Option<String>,
    pub artifact_binding: Option<String>,
    pub scope_contract_version: String,
    pub scope_contract_digest: String,
    pub scope_binding: Option<String>,
    pub resident_epoch: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub decision: String,
    pub requested_action: String,
    pub approved_action: Option<String>,
    pub reason_code: String,
    pub nonce_digest: String,
    pub replay_claimed: bool,
    pub rp_id: String,
    pub origin: String,
    pub credential_id_digest: String,
    pub algorithm: i32,
    pub authenticator_sign_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResultV4 {
    pub schema: String,
    pub version: u16,
    pub authority: String,
    pub receipt: ApprovalReceiptV4,
}
