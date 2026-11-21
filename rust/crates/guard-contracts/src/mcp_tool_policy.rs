//! Current MCP recommendation inputs; saved approvals remain separate authority.
use crate::BrowserMcpArtifactV1;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolPolicyRequestV1 {
    pub artifact: BrowserMcpArtifactV1,
    pub arguments: Value,
    pub config: Map<String, Value>,
    pub harness: String,
    pub artifact_id: String,
    pub publisher: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolPolicyResultV1 {
    pub action: String,
    pub source: String,
    pub summary_code: String,
    pub risk_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct McpToolApprovalContextRequestV1 {
    pub config: Map<String, Value>,
    pub harness: String,
    pub artifact_id: String,
    pub publisher: Option<String>,
    pub identity: Value,
    pub content: Value,
    pub capabilities: Value,
    pub sandbox: Value,
    pub extension_control_digest: String,
}
