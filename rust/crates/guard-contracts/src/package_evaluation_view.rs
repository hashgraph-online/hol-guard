//! `PackageEvaluationView` — wire contract for the resident op that reads a
//! stored or replayed package evaluation back into the shape a caller shows.
//!
//! The payload a caller holds is whatever was written at evaluation time: a
//! cache row, a replayed artifact, a reply from an older runtime. Turning it
//! into the view a harness reads means knowing every default, which policy
//! actions are recognised, what an unrecognised one costs, and how the user
//! copy reads once the local route has no cloud inbox to send anyone to. That
//! grammar is the resident's, so the caller sends the payload and the four
//! identity fields the row does not carry, and reads the answer back.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Capability advertised when the package-evaluation view op exists.
pub const PACKAGE_EVALUATION_VIEW_FEATURE: &str = "package-evaluation-view-v1";

/// Largest request the view accepts. Every row it reads back was answered by
/// the resident inside one reply, so it fits the reply budget; a request above
/// it could only produce a view the resident cannot send back, and is refused
/// before any work rather than after it.
pub const PACKAGE_EVALUATION_VIEW_MAX_REQUEST_BYTES: usize = crate::MAX_NATIVE_RESPONSE_BYTES;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageEvaluationViewRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// The evaluation exactly as the caller holds it, in `to_cache_dict`
    /// spelling. Anything that is not an object has no view.
    pub payload: Value,
    /// Identity the stored row does not carry and the caller must supply.
    pub package_intent_hash: String,
    pub policy_version: String,
    /// Absent identity travels as an explicit null, never as a missing key: the
    /// reply binds the request by its canonical digest, and a key one side
    /// omits and the other re-serializes would unbind every such request.
    #[serde(default)]
    pub bundle_version: Option<String>,
    #[serde(default)]
    pub workspace_fingerprint: Option<String>,
}
