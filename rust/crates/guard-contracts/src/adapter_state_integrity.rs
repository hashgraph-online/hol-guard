//! `AdapterStateIntegrity` - wire contract for the resident op that
//! authenticates an adapter's durable lifecycle state.
//!
//! Hermes and Copilot write a small JSON manifest under the Guard home that
//! records which configuration file Guard took over, where it put the user's
//! original, and which workspace the takeover belongs to. Install, repair and
//! uninstall read those paths back and write to them. A manifest an attacker
//! can edit therefore names a file Guard will overwrite or restore, so the
//! manifest carries an HMAC and nothing in it is trusted until that MAC
//! verifies.
//!
//! `adapters/adapter_state_integrity.py` computed and compared that MAC in
//! Python, which made the Python edge the thing deciding whether a stored path
//! was Guard's own. The runtime now owns the canonical message, the MAC and
//! every field check; the caller resolves the key file and applies the answer.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const ADAPTER_STATE_INTEGRITY_REQUEST_SCHEMA: &str = "guard-adapter-state-integrity-request.v1";
/// Schema discriminator for the result.
pub const ADAPTER_STATE_INTEGRITY_RESULT_SCHEMA: &str = "guard-adapter-state-integrity-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const ADAPTER_STATE_INTEGRITY_FEATURE: &str = "adapter-state-integrity-v1";
/// Largest canonical request serialization the op will accept.
pub const ADAPTER_STATE_INTEGRITY_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Domain separator the authenticated message opens with.
pub const ADAPTER_STATE_INTEGRITY_DOMAIN: &str = "hol-guard.adapter-state.v1";
/// The only MAC this runtime produces or accepts.
pub const ADAPTER_STATE_INTEGRITY_MAC_ALGORITHM: &str = "hmac-sha256";
/// The only state authentication schema version this runtime accepts.
pub const ADAPTER_STATE_INTEGRITY_SCHEMA_VERSION: i64 = 1;
/// The key the authentication block is stored under inside the manifest.
pub const ADAPTER_STATE_AUTHENTICATION_KEY: &str = "state_authentication";

/// Stamp a manifest with its authentication block.
pub const ADAPTER_STATE_ACTION_AUTHENTICATE: &str = "authenticate";
/// Report whether a manifest's stored authentication block verifies.
pub const ADAPTER_STATE_ACTION_VERIFY: &str = "verify";
/// Return one authenticated field's value, or null when it is unusable.
pub const ADAPTER_STATE_ACTION_FIELD: &str = "authenticated_field";

/// Whether `action` is one this runtime answers.
pub fn adapter_state_action_supported(action: &str) -> bool {
    matches!(
        action,
        ADAPTER_STATE_ACTION_AUTHENTICATE
            | ADAPTER_STATE_ACTION_VERIFY
            | ADAPTER_STATE_ACTION_FIELD
    )
}

/// One adapter state integrity request.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterStateIntegrityRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// `authenticate`, `verify` or `authenticated_field`.
    pub action: String,
    /// The harness the manifest belongs to. It is bound into the message, so a
    /// manifest signed for one adapter never authenticates for another.
    pub harness: String,
    /// The manifest. For `authenticate` it carries no authentication block;
    /// for the other two actions it carries the stored one.
    #[serde(default)]
    pub payload: Value,
    /// The field `authenticated_field` reads once the manifest verifies.
    #[serde(default)]
    pub field: Option<String>,
    /// Unpadded URL-safe base64 of the adapter state key, or null when the
    /// caller holds none.
    #[serde(default)]
    pub integrity_key_b64: Option<String>,
    /// Identifier of that key, compared against the manifest's stored one.
    #[serde(default)]
    pub integrity_key_id: Option<String>,
}

/// The answer to one adapter state integrity request.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterStateIntegrityResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    /// The key is nulled before digesting, so the digest reveals no secret.
    pub request_sha256: String,
    /// `ok` when the runtime answered, `error` when it refused the request.
    pub status: String,
    /// `ok`, or one of the `native_adapter_state_integrity_*` refusal codes.
    pub code: String,
    /// The authenticated manifest, the verification verdict, or the field's
    /// value. Absent when the request was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
