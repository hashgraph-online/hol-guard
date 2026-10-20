//! Resident preparation and execution of an exact captured Bash invocation.
//! These operations do not by themselves advertise a host delivery capability.

use serde::{Deserialize, Serialize};

use crate::{
    ClaimApprovalReuseDecisionsRequestV1, GuardHookEnvelopeV2, NativeBashCaptureV1,
    NativeBashSubjectV1, NativeHookDecisionReceiptV1, PreToolResultV1,
};

/// Native protocol support, not a host delivery or approval UI capability.
pub const NATIVE_BASH_OWNER_PROTOCOL_FEATURE: &str = "native-bash-owner-protocol-v1";
pub const NATIVE_BASH_HOST_LIVENESS_FEATURE: &str = "native-bash-host-liveness-v1";
pub const NATIVE_BASH_RESULT_POLICY_FEATURE: &str = "native-bash-result-policy-v1";
pub const NATIVE_BASH_REPLY_VALIDATION_FEATURE: &str = "native-bash-reply-validation-v1";
pub const NATIVE_BASH_ARTIFACT_ID: &str = "native-bash-owner:native-pretool:v3";
pub const NATIVE_BASH_REVIEW_LINEAGE_FEATURE: &str = "native-bash-review-lineage-v1";
pub const NATIVE_BASH_DELIVERY_REASON: &str = "native_bash_owner_required";
pub const NATIVE_BASH_DELIVERY_PROFILE: &str = "native-bash-owner-v1";

pub const NATIVE_BASH_PREPARE_REQUEST_SCHEMA: &str = "guard-native-bash-prepare-request.v1";
pub const NATIVE_BASH_PREPARE_RESULT_SCHEMA: &str = "guard-native-bash-prepare-result.v1";
pub const NATIVE_BASH_EXECUTE_REQUEST_SCHEMA: &str = "guard-native-bash-execute-request.v1";
pub const NATIVE_BASH_EXECUTE_RESULT_SCHEMA: &str = "guard-native-bash-execute-result.v1";
pub const NATIVE_BASH_HOST_REQUEST_SCHEMA: &str = "guard-native-bash-host-request.v1";
pub const NATIVE_BASH_HOST_RESULT_SCHEMA: &str = "guard-native-bash-host-result.v1";
pub const NATIVE_BASH_CANCEL_REQUEST_SCHEMA: &str = "guard-native-bash-cancel-request.v1";
pub const NATIVE_BASH_CANCEL_RESULT_SCHEMA: &str = "guard-native-bash-cancel-result.v1";
pub const NATIVE_BASH_LAUNCH_MAX_REQUEST_BYTES: usize = 512 * 1024;
pub const NATIVE_BASH_PREPARE_MAX_BUDGET_MS: u64 = 5000;
pub const NATIVE_BASH_EXECUTE_MAX_TIMEOUT_MS: u64 = 120_000;

pub fn native_bash_operation_id_is_valid(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
}

/// Local sink input. The earlier hook's capture fields are intentions only;
/// actual cwd, HOME, environment and mask are replaced in the sink process.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashHostRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub capture: NativeBashCaptureV1,
    pub budget_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashHostResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub payload: Option<NativeBashCaptureV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashPrepareRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub capture: NativeBashCaptureV1,
    pub envelope: GuardHookEnvelopeV2,
    pub budget_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashPreparedV1 {
    pub subject: NativeBashSubjectV1,
    /// Assessment input only; the caller cannot turn this into launch consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_artifact: Option<serde_json::Value>,
    pub artifact_id: String,
    pub artifact_hash: String,
    pub assessment: Vec<PreToolResultV1>,
    pub consent_required: bool,
    pub review: NativeBashReviewV1,
}

/// A current native judgment and receipt for the actual sink's envelope.
/// This is review evidence, not consent or a dispatch acknowledgment.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashReviewV1 {
    pub decision: PreToolResultV1,
    pub receipt: NativeHookDecisionReceiptV1,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashPrepareResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    pub payload: Option<NativeBashPreparedV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashExecuteRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Stable logical operation identity. A new transport request must retain
    /// this ID when recovering an uncertain reply. It is never consent.
    pub operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    pub capture: NativeBashCaptureV1,
    pub envelope: GuardHookEnvelopeV2,
    pub authorization: NativeBashAuthorizationV1,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeBashAuthorizationV1 {
    SavedGrant {
        claim: Box<ClaimApprovalReuseDecisionsRequestV1>,
    },
    CurrentPolicy {
        store_path: String,
    },
}

impl NativeBashAuthorizationV1 {
    pub fn store_path(&self) -> &str {
        match self {
            Self::SavedGrant { claim } => &claim.store_path,
            Self::CurrentPolicy { store_path } => store_path,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeBashAuthorizationKindV1 {
    SavedGrant,
    CurrentPolicy,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashCompletedV1 {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub output_limited: bool,
    pub timed_out: bool,
    pub cancelled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashExecuteResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    /// Transport/owner result; a nonzero payload exit is still an execution failure.
    pub status: String,
    pub code: String,
    /// Consent was spent or matched. This never implies dispatch or success.
    pub grant_claimed: bool,
    /// The native source protocol received S; absence means start is unproven.
    pub dispatch_acknowledged: bool,
    /// A replay reports authenticated state; stdout/stderr are not retained.
    pub replayed: bool,
    pub operation: Option<NativeBashOperationV1>,
    /// Native-minted pending-operation identity, never execution permission.
    pub review_lineage: Option<NativeBashReviewLineageV1>,
    pub payload: Option<NativeBashCompletedV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashReviewLineageV1 {
    pub schema: String,
    pub lineage_id: String,
    pub operation_id: String,
    pub artifact_hash: String,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeBashOperationStateV1 {
    Claimed,
    Dispatched,
    Completed,
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashCompletionSummaryV1 {
    pub exit_code: Option<i32>,
    pub output_limited: bool,
    pub timed_out: bool,
    pub cancelled: bool,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashOperationV1 {
    pub operation_id: String,
    pub artifact_hash: String,
    pub authorization: NativeBashAuthorizationKindV1,
    pub state: NativeBashOperationStateV1,
    pub dispatch_acknowledged: bool,
    pub completion: Option<NativeBashCompletionSummaryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashCancelRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub guard_home: String,
    pub operation_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBashCancelResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    /// A live owner was signalled. Only its final response proves teardown.
    pub cancel_requested: bool,
}
