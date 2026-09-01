use serde::{Deserialize, Serialize};

use super::{GuardHookEnvelopeV2, PreToolActionTypeV1, PreToolOperationV1};

pub const NATIVE_APPROVAL_ARTIFACT_V3_SCHEMA: &str = "guard-native-approval-artifact.v3";
pub const NATIVE_APPROVAL_CHALLENGE_REQUEST_V3_SCHEMA: &str =
    "guard-native-approval-challenge-request.v3";
pub const NATIVE_APPROVAL_CHALLENGE_V3_SCHEMA: &str = "guard-native-approval-challenge.v3";
pub const NATIVE_APPROVAL_VALIDATE_REQUEST_V3_SCHEMA: &str =
    "guard-native-approval-validate-request.v3";
pub const NATIVE_APPROVAL_CONSUME_REQUEST_V3_SCHEMA: &str =
    "guard-native-approval-consume-request.v3";
pub const NATIVE_APPROVAL_RESULT_V3_SCHEMA: &str = "guard-native-approval-result.v3";
pub const NATIVE_APPROVAL_RECEIPT_V3_SCHEMA: &str = "guard-native-approval-receipt.v3";
pub const NATIVE_APPROVAL_AUTHORITY_V4_SCHEMA: &str = "guard-native-approval-authority.v4";
pub const NATIVE_APPROVAL_ENROLLMENT_REQUEST_V4_SCHEMA: &str =
    "guard-native-approval-enrollment-request.v4";
pub const NATIVE_APPROVAL_ARTIFACT_V4_SCHEMA: &str = "guard-native-approval-artifact.v4";
pub const NATIVE_APPROVAL_CHALLENGE_REQUEST_V4_SCHEMA: &str =
    "guard-native-approval-challenge-request.v4";
pub const NATIVE_APPROVAL_CHALLENGE_V4_SCHEMA: &str = "guard-native-approval-challenge.v4";
pub const NATIVE_APPROVAL_VALIDATE_REQUEST_V4_SCHEMA: &str =
    "guard-native-approval-validate-request.v4";
pub const NATIVE_APPROVAL_CONSUME_REQUEST_V4_SCHEMA: &str =
    "guard-native-approval-consume-request.v4";
pub const NATIVE_APPROVAL_RESULT_V4_SCHEMA: &str = "guard-native-approval-result.v4";
pub const NATIVE_APPROVAL_RECEIPT_V4_SCHEMA: &str = "guard-native-approval-receipt.v4";
pub const NATIVE_APPROVAL_V4_ENROLLMENT_DOMAIN: &[u8] =
    b"guard-native-approval-webauthn-enrollment-v4\0";
pub const NATIVE_APPROVAL_V4_ARTIFACT_DOMAIN: &[u8] =
    b"guard-native-approval-webauthn-artifact-v4\0";
pub const NATIVE_APPROVAL_V4_ALGORITHM_ES256: i32 = -7;
pub const NATIVE_APPROVAL_V4_ALGORITHM_ED25519: i32 = -8;
pub const NATIVE_APPROVAL_V4_MAX_AUTHENTICATOR_DATA_BYTES: usize = 4 * 1024;
pub const NATIVE_APPROVAL_V4_MAX_CLIENT_DATA_BYTES: usize = 16 * 1024;
pub const NATIVE_APPROVAL_V4_MAX_SIGNATURE_BYTES: usize = 256;
pub const NATIVE_APPROVAL_V4_MAX_CREDENTIAL_ID_BYTES: usize = 1024;
pub const NATIVE_APPROVAL_V4_MAX_COSE_KEY_BYTES: usize = 2048;
pub const NATIVE_ACTION_IDENTITY_V3_SCHEMA: &str = "guard-native-action-identity.v3";
/// Approval artifacts are signed by a user-facing authority whose private
/// key never enters the Python control plane or the Guard state directory.
pub const NATIVE_APPROVAL_INTEGRITY_ALGORITHM: &str = "ed25519";
pub const NATIVE_APPROVAL_INTEGRITY_DOMAIN: &[u8] = b"guard-native-approval-v3\0";
pub const NATIVE_APPROVAL_DEVICE_BINDING_DOMAIN: &[u8] =
    b"guard-native-approval-device-binding-v3\0";
pub const NATIVE_APPROVAL_INSTALLATION_BINDING_DOMAIN: &[u8] =
    b"guard-native-approval-installation-binding-v3\0";
/// Maximum number of live challenge entries retained by one resident.
pub const NATIVE_APPROVAL_REPLAY_MEMORY_MAX_ENTRIES: usize = 4096;
pub const NATIVE_APPROVAL_MAX_BYTES: usize = 64 * 1024;
/// Maximum encoded size of a privacy-safe approval challenge or receipt.
/// Request envelopes use `MAX_NATIVE_REQUEST_BYTES` because their resident-
/// only raw payload may legitimately be much larger.
pub const NATIVE_APPROVAL_RESPONSE_MAX_BYTES: usize = 64 * 1024;
pub const NATIVE_APPROVAL_MAX_STRING_BYTES: usize = 4 * 1024;
pub const NATIVE_APPROVAL_MAX_REASON_BYTES: usize = 256;
pub const NATIVE_APPROVAL_MAX_TTL_MS: u64 = 15 * 60 * 1000;
pub const NATIVE_APPROVAL_MAX_CLOCK_SKEW_MS: u64 = 2 * 60 * 1000;
pub const NATIVE_APPROVAL_NONCE_BYTES: usize = 32;

/// Every approval error that may cross the resident transport boundary.
///
/// Keep this list finite and synchronized with the Python decoder. An error
/// string is not a capability: unknown or future strings are redacted to the
/// generic transport error until this contract is deliberately extended.
pub const NATIVE_APPROVAL_ERROR_CODES: &[&str] = &[
    "native_approval_action_digest_failed",
    "native_approval_action_identity_invalid",
    "native_approval_action_not_approvable",
    "native_approval_action_reconstruction_failed",
    "native_approval_artifact_invalid",
    "native_approval_artifact_schema_mismatch",
    "native_approval_artifact_serialization_failed",
    "native_approval_artifact_too_large",
    "native_approval_already_enrolled",
    "native_approval_authority_already_enrolled",
    "native_approval_authority_busy",
    "native_approval_authority_enrollment_invalid",
    "native_approval_authority_generation_invalid",
    "native_approval_authority_generation_rollback",
    "native_approval_authority_invalid",
    "native_approval_authority_key_id_mismatch",
    "native_approval_authority_lock_failed",
    "native_approval_authority_lock_invalid",
    "native_approval_authority_lock_not_private",
    "native_approval_authority_missing",
    "native_approval_authority_noncanonical",
    "native_approval_authority_provenance_mismatch",
    "native_approval_authority_recovery_pending",
    "native_approval_authority_revoked",
    "native_approval_authority_root_invalid",
    "native_approval_authority_root_provenance_invalid",
    "native_approval_authority_root_provenance_unconfigured",
    "native_approval_authority_root_unconfigured",
    "native_approval_binding_ambiguous",
    "native_approval_binding_invalid",
    "native_approval_binding_mismatch",
    "native_approval_challenge_request_invalid",
    "native_approval_clock_invalid",
    "native_approval_consume_request_invalid",
    "native_approval_consumed",
    "native_approval_device_identity_invalid",
    "native_approval_digest_invalid",
    "native_approval_edge_result_invalid",
    "native_approval_edge_result_too_large",
    "native_approval_enrollment_request_invalid",
    "native_approval_enrollment_required",
    "native_approval_event_not_approvable",
    "native_approval_failed",
    "native_approval_floor_mismatch",
    "native_approval_floor_not_approvable",
    "native_approval_floor_not_overridable",
    "native_approval_integrity_invalid",
    "native_approval_integrity_mismatch",
    "native_approval_intrinsic_action_invalid",
    "native_approval_ledger_busy",
    "native_approval_ledger_claim_invalid",
    "native_approval_ledger_corrupt",
    "native_approval_ledger_encode_failed",
    "native_approval_ledger_full",
    "native_approval_ledger_lock_failed",
    "native_approval_ledger_lock_invalid",
    "native_approval_ledger_lock_not_private",
    "native_approval_ledger_not_private",
    "native_approval_ledger_parent_invalid",
    "native_approval_ledger_parent_not_private",
    "native_approval_ledger_persistence_failed",
    "native_approval_ledger_read_failed",
    "native_approval_ledger_replace_failed",
    "native_approval_ledger_stat_failed",
    "native_approval_ledger_sync_failed",
    "native_approval_ledger_unavailable",
    "native_approval_ledger_write_failed",
    "native_approval_minimum_action_invalid",
    "native_approval_nonce_invalid",
    "native_approval_policy_context_mismatch",
    "native_approval_random_failed",
    "native_approval_receipt_consumed",
    "native_approval_receipt_expired",
    "native_approval_receipt_invalid",
    "native_approval_receipt_not_claimed",
    "native_approval_replay",
    "native_approval_replay_full",
    "native_approval_replay_unavailable",
    "native_approval_request_bounds_exceeded",
    "native_approval_request_id_mismatch",
    "native_approval_request_id_missing",
    "native_approval_response_too_large",
    "native_approval_result_invalid",
    "native_approval_runtime_mismatch",
    "native_approval_secure_state_invalid",
    "native_approval_secure_state_unavailable",
    "native_approval_signing_authority_replaced",
    "native_approval_signing_authority_unavailable",
    "native_approval_time_invalid",
    "native_approval_validate_request_invalid",
    "native_approval_validated",
    "native_approval_v4_authority_invalid",
    "native_approval_v4_authority_missing",
    "native_approval_v4_authority_revoked",
    "native_approval_v4_authority_generation_rollback",
    "native_approval_v4_authority_provenance_mismatch",
    "native_approval_v4_authority_unavailable",
    "native_approval_v4_authority_key_id_mismatch",
    "native_approval_v4_algorithm_invalid",
    "native_approval_v4_artifact_invalid",
    "native_approval_v4_artifact_schema_mismatch",
    "native_approval_v4_challenge_request_invalid",
    "native_approval_v4_authenticator_data_invalid",
    "native_approval_v4_authenticator_flags_invalid",
    "native_approval_v4_cbor_invalid",
    "native_approval_v4_cbor_bounds_exceeded",
    "native_approval_v4_client_data_invalid",
    "native_approval_v4_client_data_type_invalid",
    "native_approval_v4_counter_replay",
    "native_approval_v4_credential_mismatch",
    "native_approval_v4_enrollment_invalid",
    "native_approval_v4_origin_mismatch",
    "native_approval_v4_rp_id_mismatch",
    "native_approval_v4_signature_invalid",
    "native_approval_v4_secure_state_invalid",
    "native_approval_v4_secure_state_unavailable",
    "native_approval_v4_validate_request_invalid",
    "native_approval_v4_consume_request_invalid",
    "native_approval_v4_validated",
    "native_approval_v4_consumed",
    "native_overloaded",
    "native_policy_snapshot_authority_persistence_failed",
    "native_policy_snapshot_context_mismatch",
    "native_policy_snapshot_generation_downgrade",
    "native_policy_snapshot_generation_reused",
    "native_policy_snapshot_invalid",
    "native_policy_snapshot_missing",
    "native_policy_snapshot_not_current",
    "native_policy_snapshot_push_invalid",
    "native_policy_snapshot_push_schema_mismatch",
    "native_policy_snapshot_request_mismatch",
    "native_policy_snapshot_required",
    "native_policy_snapshot_rule_mismatch",
    "native_policy_snapshot_scope_mismatch",
    "native_policy_snapshot_state_unavailable",
    "native_policy_snapshot_unavailable",
    "native_request_invalid_json",
    "native_resident_clock_invalid",
    "native_resident_request_invalid_json",
    "native_response_encode_failed",
    "native_response_too_large",
    "native_runtime_panicked",
    "snapshot_expired",
];

/// Typed native floor classification. A non-overridable floor is an
/// intrinsic safety boundary and cannot be changed by a presentation-layer
/// approval or by a policy value claiming a lower action.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeApprovalFloorClassV3 {
    Approvable,
    NonOverridable,
}

/// Bounded, typed action metadata. This type is safe to place in a result:
/// it contains no untrusted raw content and has no open-ended map.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreToolActionV1 {
    pub schema: String,
    pub version: u16,
    pub harness: String,
    pub event: String,
    pub action_type: PreToolActionTypeV1,
    pub operation: PreToolOperationV1,
    pub bounded: bool,
    pub sensitive_target: bool,
}

/// Stable, privacy-safe identity of the action reconstructed by Rust. Raw
/// command text, paths, URLs, prompts, and source content never enter this
/// value or its digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeActionIdentityV3 {
    pub schema: String,
    pub version: u16,
    pub harness: String,
    pub event: String,
    pub action_type: PreToolActionTypeV1,
    pub operation: PreToolOperationV1,
    pub bounded: bool,
    pub sensitive_target: bool,
    pub intrinsic_action: String,
    pub minimum_action: String,
    pub policy_action: String,
    pub floor_class: NativeApprovalFloorClassV3,
    pub approval_eligible: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeApprovalIntegrityV3 {
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
}

/// Single-purpose approval artifact. Bindings are digests; no raw request
/// material is copied into the artifact or returned receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalArtifactV3 {
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
    /// Random resident epoch. It is regenerated on every managed-resident
    /// start and makes an approval artifact useless after restart.
    pub resident_epoch: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub requested_action: String,
    pub approved_action: String,
    pub integrity: NativeApprovalIntegrityV3,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalChallengeRequestV3 {
    pub schema: String,
    pub version: u16,
    pub envelope: GuardHookEnvelopeV2,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalValidateRequestV3 {
    pub schema: String,
    pub version: u16,
    pub envelope: GuardHookEnvelopeV2,
    pub artifact: ApprovalArtifactV3,
}

/// Final, execution-adjacent receipt gate. Validation claims the nonce; the
/// presentation layer must call this operation immediately before continuing
/// so a policy replacement after validation cannot authorize execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConsumeRequestV3 {
    pub schema: String,
    pub version: u16,
    pub envelope: GuardHookEnvelopeV2,
    pub artifact: ApprovalArtifactV3,
}

/// Privacy-safe challenge returned to the presentation/orchestration layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalChallengeV3 {
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
    /// Random resident epoch bound to the live challenge table.
    pub resident_epoch: String,
    pub nonce: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub requested_action: String,
    pub signing_key_id: String,
}

/// A native receipt carries every field needed to prove that the resident
/// consumed this exact challenge. Python may compare these opaque fields but
/// cannot replace them with session-local or database-derived context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalReceiptV3 {
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResultV3 {
    pub schema: String,
    pub version: u16,
    pub authority: String,
    pub receipt: ApprovalReceiptV3,
}
