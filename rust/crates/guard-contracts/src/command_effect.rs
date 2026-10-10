//! Bounded native command/effect-composition contract.
//!
//! The factor composition, floor lattice, and decision plane behind
//! `CompositeCommandEvaluation` are authority-bearing semantics: approval reuse
//! and command gating key on the result. Python callers send the request
//! inputs and receive the evaluation payload back through the resident
//! protocol; they never recompute it.
//!
//! The response `payload` is the serialized evaluation wire form
//! (`CompositeCommandEvaluation.to_dict()` plus a `control_resolution`
//! summary). The contract's stability guarantee is that dict shape, not a
//! parallel Rust type.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const COMMAND_EFFECT_REQUEST_SCHEMA: &str = "guard-command-effect-request.v1";
/// Schema discriminator for the result.
pub const COMMAND_EFFECT_RESULT_SCHEMA: &str = "guard-command-effect-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const COMMAND_EFFECT_FEATURE: &str = "command-effect-v1";

/// Largest canonical request serialization the op will accept.
pub const COMMAND_EFFECT_MAX_BYTES: usize = 1024 * 1024;

/// Schema discriminator for the batched request.
pub const COMMAND_EFFECT_BATCH_REQUEST_SCHEMA: &str = "guard-command-effect-batch-request.v1";
/// Schema discriminator for the batched result.
pub const COMMAND_EFFECT_BATCH_RESULT_SCHEMA: &str = "guard-command-effect-batch-result.v1";
/// Capability advertised by the runtime when the batched operation is available.
pub const COMMAND_EFFECT_BATCH_FEATURE: &str = "command-effect-batch-v1";
/// Most items one batched request may carry. Bounds both evaluation time and
/// the aggregate response, which must stay inside `MAX_NATIVE_RESPONSE_BYTES`.
pub const COMMAND_EFFECT_BATCH_MAX_ITEMS: usize = 64;
/// Largest total canonical serialization of all items in one batched request.
pub const COMMAND_EFFECT_BATCH_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Most permission ids one counterfactual overlay may enable.
pub const COMMAND_EFFECT_COUNTERFACTUAL_MAX: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandEffectRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// Raw command text under evaluation.
    pub command_text: String,
    /// Canonical command produced by the native command-model op. Required:
    /// the evaluator never re-parses command text on its own authority.
    pub canonical_command: Value,
    /// Optional compatibility attribution: when the command only matched via a
    /// compatibility fallback, the action class it is attributed to
    /// (`evaluate_command` `compatibility_action_class`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility_action_class: Option<String>,
    /// Human-readable reason for the compatibility fallback
    /// (`evaluate_command` `compatibility_reason`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility_reason: Option<String>,
    /// Native command-safety extension evidence (per-extension observations +
    /// floor/benign/uncertainty flags). Mirrors `native_extension_evidence`.
    #[serde(default)]
    pub native_extension_evidence: Value,
    /// Authenticated control snapshot binding the request runs under. Its
    /// layers, health and revision are the only control authority: the
    /// evaluator derives the layer set and authority failure from it.
    pub control_snapshot: Value,
    /// Workflow authorization context (the `workflow_authorization` arg).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_authorization: Option<Value>,
    /// Current working directory used for workspace-relative proof checks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Home directory used for the private-scope fence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_dir: Option<String>,
    /// Counterfactual only: permission ids to treat as enabled in the local
    /// admin layer. The resident validates `control_snapshot` as supplied
    /// (digest included) and applies this overlay afterwards, so a caller can
    /// ask "would this allow if these permissions were on" without forging a
    /// binding. At most `COMMAND_EFFECT_COUNTERFACTUAL_MAX` ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counterfactual_enabled_permission_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandEffectResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the raw request bytes, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_command_effect_*` failure codes.
    pub code: String,
    /// The `CompositeCommandEvaluation.to_dict()` payload on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

/// Batched form of the op. Every item is an ordinary single request: it keeps
/// its own `request_id`, is evaluated under exactly the single-op rules and is
/// answered with its own result bound to its own `request_sha256`. Batching
/// only amortizes the resident round trip; it never relaxes a single-op check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandEffectBatchRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    pub items: Vec<CommandEffectRequestV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandEffectBatchResultV1 {
    pub schema: String,
    pub request_id: String,
    /// `ok` when every item was evaluated and answered (an item may still carry
    /// its own `error` status), or `error` when the batch itself was refused.
    pub status: String,
    /// `ok`, or one of the `native_command_effect_batch_*` refusal codes.
    pub code: String,
    /// One result per request item, in request order; empty on a refused batch.
    #[serde(default)]
    pub items: Vec<CommandEffectResultV1>,
}
