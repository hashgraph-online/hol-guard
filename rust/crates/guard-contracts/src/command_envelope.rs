//! `CommandEnvelope` - wire contract for the resident op that signs and
//! verifies the locally signed envelopes around Guard Cloud's command flow.
//!
//! Two envelopes sit beside the capability itself: the capability the local
//! CLI issues, and the grant a user writes when they confirm a leased job at
//! their own machine. Both are HMAC envelopes over the local policy integrity
//! secret, and until this op existed `command_capability.py` produced and
//! checked them with its own `hmac` calls. That made the Python edge a second
//! evaluator on the approval boundary: a caller reaching the helper could mint
//! a grant, or accept one, without the runtime ever seeing it.
//!
//! The op takes the payload and the caller's copy of the signing key and
//! answers one of three questions: sign this payload, verify this stored
//! envelope, or digest this identity for the replay rows. Reading the key out
//! of the secret store, deciding when to mint one, and persisting what comes
//! back stay with the caller, because none of those is a verdict.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const COMMAND_ENVELOPE_REQUEST_SCHEMA: &str = "guard-command-envelope-request.v1";
/// Schema discriminator for the result.
pub const COMMAND_ENVELOPE_RESULT_SCHEMA: &str = "guard-command-envelope-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const COMMAND_ENVELOPE_FEATURE: &str = "command-envelope-v1";
/// Largest canonical request serialization the op will accept.
pub const COMMAND_ENVELOPE_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Produce `{payload, keyId, signature}` over the supplied key.
pub const COMMAND_ENVELOPE_ACTION_SIGN: &str = "sign";
/// Check a stored envelope's signature and return its unsigned fields.
pub const COMMAND_ENVELOPE_ACTION_VERIFY: &str = "verify";
/// Digest a job identity exactly as the replay rows record it.
pub const COMMAND_ENVELOPE_ACTION_DIGEST: &str = "digest";

/// Whether `action` names a question this op answers.
#[must_use]
pub fn command_envelope_action_supported(action: &str) -> bool {
    matches!(
        action,
        COMMAND_ENVELOPE_ACTION_SIGN
            | COMMAND_ENVELOPE_ACTION_VERIFY
            | COMMAND_ENVELOPE_ACTION_DIGEST
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandEnvelopeRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// `sign`, `verify` or `digest`.
    pub action: String,
    /// The payload to sign, the stored envelope to verify, or the identity to
    /// digest, depending on `action`.
    #[serde(default)]
    pub payload: Value,
    /// The local policy integrity secret, base64url without padding. Absent
    /// where the caller's store holds none; `digest` never reads it.
    #[serde(default)]
    pub integrity_key_b64: Option<String>,
    /// The key id that envelope's `keyId` must name.
    #[serde(default)]
    pub integrity_key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CommandEnvelopeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_command_envelope_*` codes.
    pub code: String,
    /// The answer: `accepted`, the refusal `reason` when it is not, and the
    /// signed envelope, unsigned fields or digest when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
