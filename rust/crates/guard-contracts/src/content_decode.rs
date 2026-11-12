//! Contained HTTP content-decode request/response contract.
//!
//! A managed fetch reads the raw response body without letting its HTTP stack
//! decompress it, then hands the body and its `Content-Encoding` values to
//! `hol-guard-runtime content-decode --stdin`. The worker refuses unsupported
//! or over-deep codings before any decoder exists, and decodes the rest only
//! after process containment is applied and proven. The request carries no
//! credentials and no destination; the decoded body is still untrusted.

use serde::{Deserialize, Serialize};

/// Schema discriminator for the stdin request.
pub const CONTENT_DECODE_REQUEST_SCHEMA: &str = "guard-content-decode.v1";
/// Schema discriminator for the stdout result.
pub const CONTENT_DECODE_RESULT_SCHEMA: &str = "guard-content-decode-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CONTENT_DECODE_FEATURE: &str = "content-decode-v1";

/// Upper bounds the runtime enforces on caller-supplied caps. The raw body
/// travels base64-encoded inside the native request, so its ceiling is the
/// largest body whose encoding still fits the strict parser's 4 MiB string
/// limit (3 MiB encodes to exactly 4 MiB) and so the request frame.
pub const CONTENT_CAP_INPUT_BYTES: u64 = 3 * 1024 * 1024;
pub const CONTENT_CAP_OUTPUT_BYTES: u64 = 32 * 1024 * 1024;
pub const CONTENT_CAP_RATIO: u64 = 1_000;
pub const CONTENT_CAP_LAYERS: u64 = 4;
pub const CONTENT_CAP_MEMORY_BYTES: u64 = 1024 * 1024 * 1024;
/// Longest decode budget the runtime will accept.
pub const CONTENT_CAP_TIMEOUT_MS: u64 = 30_000;
/// At most this many `Content-Encoding` header lines are forwarded.
pub const CONTENT_CAP_HEADER_VALUES: usize = 8;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContentDecodeCapsV1 {
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    /// Largest decoded size of any layer as a multiple of the raw body.
    pub max_ratio: u64,
    pub max_layers: u64,
    pub max_memory_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContentDecodeRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// Every `Content-Encoding` header value, in order of appearance.
    pub content_encoding: Vec<String>,
    /// The raw response body exactly as received, base64 (standard, padded).
    pub body_base64: String,
    /// Canonical Guard-home directory. The worker shares the contained
    /// archive-inspection lease inside it, so decode and inspection workers
    /// contend on one bounded slot and a saturated slot is a result, not a
    /// queue.
    pub state_dir: String,
    pub timeout_ms: u64,
    pub caps: ContentDecodeCapsV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContentDecodeCountersV1 {
    /// Decoders constructed. Zero on every refusal made before decode.
    pub decoder_calls: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub layers: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContentDecodeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the raw request bytes, binding the result to its request.
    pub request_sha256: String,
    /// `decoded`, `rejected`, or `incomplete`.
    pub status: String,
    pub code: String,
    pub message: String,
    /// Present only when `status` is `decoded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_sha256: Option<String>,
    /// SHA-256 of the runtime binary that produced this result.
    pub runtime_sha256: String,
    pub counters: ContentDecodeCountersV1,
}
