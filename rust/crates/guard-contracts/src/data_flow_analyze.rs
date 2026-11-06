//! Request/result contract for the `DataFlowAnalyze` resident op (RTM-032).
//!
//! The resident owns data-flow exfiltration detection for shell actions. The
//! Python side sends the action type, command, and workspace and receives the
//! ordered `RiskSignalV2` payloads back, bound to the request by
//! `request_id` plus the canonical `request_sha256`.
//!
//! The request also carries the naming the artifact for those signals is built
//! under. The signals and the artifact they earn are one answer: the artifact
//! id is the key the review is saved under, and deriving it anywhere but here
//! would put a second implementation in charge of what a saved approval
//! matches. `naming` is optional so a caller that only wants the signals — the
//! recorder, the conformance vectors — still asks the same question.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// v2 added `naming` to the request and `artifact` to the result; a v1
/// resident cannot answer the new shape, so clients ask for v2 by name.
pub const DATA_FLOW_ANALYZE_FEATURE: &str = "data-flow-analyze-v2";
pub const DATA_FLOW_ANALYZE_REQUEST_SCHEMA: &str = "guard-data-flow-analyze-request.v1";
pub const DATA_FLOW_ANALYZE_RESULT_SCHEMA: &str = "guard-data-flow-analyze-result.v1";
/// Largest command the op accepts; longer input fails closed.
pub const DATA_FLOW_ANALYZE_MAX_COMMAND_BYTES: usize = 256 * 1024;

/// How the artifact built for a request's signals is named. Every field is
/// the caller's: the harness it speaks for, the policy file the review cites,
/// whether the scope is the project or the global install, and the tool the
/// action came in on, which the artifact is titled after.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DataFlowArtifactNamingV1 {
    pub harness: String,
    pub config_path: String,
    pub source_scope: String,
    pub tool_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DataFlowAnalyzeRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub action_type: String,
    pub command: Option<String>,
    pub workspace: Option<String>,
    /// Absent when the caller wants the signals alone.
    #[serde(default)]
    pub naming: Option<DataFlowArtifactNamingV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DataFlowAnalyzeResultV1 {
    pub schema: String,
    pub request_id: String,
    /// Hex SHA-256 of the canonical request serialization.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    pub code: String,
    /// Ordered `RiskSignalV2.to_dict()` payloads; present only when `ok`.
    pub signals: Option<Vec<Value>>,
    /// The artifact those signals earn, built under the request's `naming`.
    /// Null when the request carried no naming or the command raised no
    /// signals, because an action with no data flow earns no review.
    pub artifact: Option<Value>,
}
