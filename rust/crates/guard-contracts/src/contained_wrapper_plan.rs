//! `ContainedWrapperPlan` - wire contract for the resident op that tells the
//! execution sink which wrapper the pre-tool classification peeled.
//!
//! The sink used to peel the shape a second time in Python, from its own
//! lexer, its own sibling-repository rule and its own output-filter grammar.
//! Two peels of one shape drift: the Python copy cannot read a Windows owner
//! SID, so it accepted checkouts the classifier had refused and handed the
//! sandbox a core that no receipt covered. The classifier now answers the
//! question it already decided, and the sink executes that answer.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const CONTAINED_WRAPPER_PLAN_REQUEST_SCHEMA: &str = "guard-contained-wrapper-plan-request.v1";
/// Schema discriminator for the result.
pub const CONTAINED_WRAPPER_PLAN_RESULT_SCHEMA: &str = "guard-contained-wrapper-plan-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const CONTAINED_WRAPPER_PLAN_FEATURE: &str = "contained-wrapper-plan-v1";
/// Largest canonical request serialization the op will accept.
pub const CONTAINED_WRAPPER_PLAN_MAX_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContainedWrapperPlanRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// The command text the harness delivered, exactly as the classifier saw it.
    pub command: String,
    /// The sandbox root the sink would run in.
    pub workspace: String,
    /// The directory the command was issued from.
    #[serde(default)]
    pub cwd: Option<String>,
    /// The agent's home directory, or null when the sink has none to offer.
    #[serde(default)]
    pub home_dir: Option<String>,
    /// A directory to classify as a sibling repository, independently of the
    /// command. The sink asks this before it knows whether a wrapper exists.
    #[serde(default)]
    pub project_root_query: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContainedWrapperPlanResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_contained_wrapper_plan_*` codes.
    pub code: String,
    /// `{"plan": ..., "refusal": ..., "anchored_sibling_root": ...,
    /// "project_root": ...}`; see
    /// `contained_wrapper_plan`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
