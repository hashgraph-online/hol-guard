//! Bounded native command/effect-composition contract.
//!
//! `evaluate_command`'s factor composition, floor lattice, and decision plane
//! are authority-bearing semantics: the `CompositeCommandEvaluation` it returns
//! is what approval reuse and command gating key on. Computing it is therefore
//! native work — Python callers send the request inputs and receive the
//! canonical `CompositeCommandEvaluation.to_dict()` payload back through the
//! resident protocol.
//!
//! The response `payload` field intentionally carries the serialized
//! `CompositeCommandEvaluation.to_dict()` shape verbatim rather than a
//! re-derived Rust type. The Python-side wire shape is already that dict, so a
//! `Value` payload is byte-stable while the factor/lattice producers port
//! incrementally; the contract's stability guarantee is the dict shape, not a
//! parallel type.

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandEffectRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    /// Raw command text under evaluation.
    pub command_text: String,
    /// Canonical command produced by the command-model op. Optional because a
    /// caller may request canonicalization inside the op.
    #[serde(default)]
    pub canonical_command: Option<Value>,
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
    /// Control snapshot the request runs under (the `control_snapshot` arg).
    #[serde(default)]
    pub control_snapshot: Option<Value>,
    /// Control layers to scope against (the `control_layers` arg).
    #[serde(default)]
    pub control_layers: Value,
    /// Workflow authorization context (the `workflow_authorization` arg).
    #[serde(default)]
    pub workflow_authorization: Option<Value>,
    /// Current working directory used for workspace-relative proof checks.
    pub cwd: String,
    /// Home directory used for the private-scope fence.
    pub home_dir: String,
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
