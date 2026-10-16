//! Request/result contract for the `DataFlowAnalyze` resident op (RTM-032).
//!
//! The resident owns data-flow exfiltration detection for shell actions. The
//! Python side sends the action type, command, and workspace and receives the
//! ordered `RiskSignalV2` payloads back, bound to the request by
//! `request_id` plus the canonical `request_sha256`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DATA_FLOW_ANALYZE_FEATURE: &str = "data-flow-analyze-v1";
pub const DATA_FLOW_ANALYZE_REQUEST_SCHEMA: &str = "guard-data-flow-analyze-request.v1";
pub const DATA_FLOW_ANALYZE_RESULT_SCHEMA: &str = "guard-data-flow-analyze-result.v1";
/// Largest command the op accepts; longer input fails closed.
pub const DATA_FLOW_ANALYZE_MAX_COMMAND_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DataFlowAnalyzeRequestV1 {
    pub schema: String,
    pub request_id: String,
    pub action_type: String,
    pub command: Option<String>,
    pub workspace: Option<String>,
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
}
