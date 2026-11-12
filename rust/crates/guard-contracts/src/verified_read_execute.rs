//! Request/result contract for the `VerifiedReadExecute` resident op.
//!
//! A verified workspace read is performed by Guard itself, not by the agent.
//! The resident plans the read from the argv, opens the target beneath the
//! working directory's repository, slices the text it read, binds a proof to
//! the repository, target and output identity, and composes the decision that
//! lets the read run silently. The host only prints what comes back.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERIFIED_READ_EXECUTE_FEATURE: &str = "verified-read-execute-v1";
pub const VERIFIED_READ_EXECUTE_REQUEST_SCHEMA: &str = "guard-verified-read-execute-request.v1";
pub const VERIFIED_READ_EXECUTE_RESULT_SCHEMA: &str = "guard-verified-read-execute-result.v1";
/// Largest canonical request the op accepts; longer input fails closed. The
/// cohort takes at most three short arguments plus two paths, so this is
/// generous by a wide margin.
pub const VERIFIED_READ_EXECUTE_MAX_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedReadExecuteRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub query: VerifiedReadExecuteQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerifiedReadExecuteQueryV1 {
    /// One bounded read in the caller's working directory.
    Local {
        /// The command as the executor received it, executable first.
        argv: Vec<String>,
        /// The caller's working directory; it must already be canonical.
        cwd: String,
        /// The caller's home directory, for the secret-path tables.
        home_dir: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerifiedReadExecutePayloadV1 {
    Local {
        /// The operation the plan named, and the one the decision belongs to.
        operation_id: String,
        /// The bounded text the read may show.
        stdout: String,
        /// The proof's binding digest.
        binding_digest: String,
        /// `effect_decision_to_payload` output; always silent-verified.
        decision: Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedReadExecuteResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_verified_read_execute_*` failure codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<VerifiedReadExecutePayloadV1>,
}
