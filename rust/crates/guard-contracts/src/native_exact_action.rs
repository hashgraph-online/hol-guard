//! `NativeExactAction` — wire contract for the resident exact-action identity op.
//!
//! A native review may carry a persistent "Always" decision only when the action
//! binds to a stable, content-addressed identity: the code a command would run,
//! the files it reads, the repository configuration git would consult, and the
//! Rust rules that judged it. The resident owns every one of those proofs and the
//! short-lived review binding that fences a retry. Python only transports the
//! request facts and the facts it alone holds (the verified policy binding, the
//! ambient environment and the extension-control digest). A transport failure is
//! "no identity" and the caller fails closed.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Schema discriminator for the request.
pub const NATIVE_EXACT_ACTION_REQUEST_SCHEMA: &str = "guard-native-exact-action-request.v1";
/// Schema discriminator for the result.
pub const NATIVE_EXACT_ACTION_RESULT_SCHEMA: &str = "guard-native-exact-action-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const NATIVE_EXACT_ACTION_FEATURE: &str = "native-exact-action-v1";
/// Largest canonical request serialization the op will accept.
pub const NATIVE_EXACT_ACTION_MAX_BYTES: usize = 256 * 1024;
/// Longest filesystem budget a request may ask for.
pub const NATIVE_EXACT_ACTION_MAX_BUDGET_MS: u64 = 30_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeExactActionRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: NativeExactActionQueryV1,
}

/// The Rust-owned facts of one native review, each `None` when the verdict
/// carried no text for it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeReviewFactsV1 {
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub minimum_action: Option<String>,
    #[serde(default)]
    pub policy_action: Option<String>,
    #[serde(default)]
    pub reason_code: Option<String>,
    #[serde(default)]
    pub action_type: Option<String>,
}

/// Outcome of Python's receipt validation for the review's policy binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativePolicyBindingV1 {
    /// The receipt or verdict did not validate.
    Invalid,
    /// The verdict is not bound to extension policy.
    Unbound,
    /// The validated binding (`rule_digest`, `command_extensions`, ...).
    Bound { value: Value },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeExactActionQueryV1 {
    /// The persistent exact-action token of one review, or the reason it must
    /// stay a one-time allow.
    ExactAction {
        harness: String,
        tool_name: String,
        #[serde(default)]
        command: Option<String>,
        /// The tool input as `[key, value]` pairs in payload order.
        #[serde(default)]
        tool_input: Option<Vec<(String, Value)>>,
        /// The payload's own `cwd`, when it was non-blank text.
        #[serde(default)]
        payload_cwd: Option<String>,
        #[serde(default)]
        workspace: Option<String>,
        #[serde(default)]
        home_dir: Option<String>,
        /// The ambient environment the action would launch in.
        environment: BTreeMap<String, String>,
        facts: NativeReviewFactsV1,
        policy_binding: NativePolicyBindingV1,
        extension_control_digest: String,
        budget_ms: u64,
    },
    /// The short-lived binding that fences a retry of one review.
    ReviewBinding {
        harness: String,
        #[serde(default)]
        command: Option<String>,
        /// The payload's own `cwd`, which resolves files fed on standard input.
        #[serde(default)]
        cwd: Option<String>,
        workspace_bound: bool,
        facts: NativeReviewFactsV1,
        /// The verified decision receipt as Python decoded it.
        #[serde(default)]
        receipt: Option<Value>,
        policy_binding: NativePolicyBindingV1,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeExactActionPayloadV1 {
    /// Exactly one of `token` and `once_only_reason` is set.
    ExactAction {
        token: Option<String>,
        once_only_reason: Option<String>,
    },
    ReviewBinding {
        binding: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NativeExactActionResultV1 {
    pub schema: String,
    pub request_id: String,
    pub request_sha256: String,
    pub status: String,
    pub code: String,
    #[serde(default)]
    pub payload: Option<NativeExactActionPayloadV1>,
}
