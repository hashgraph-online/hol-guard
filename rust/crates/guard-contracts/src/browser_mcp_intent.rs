//! Native browser MCP intent and privacy-safe display contract.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BrowserIntentV1 {
    #[serde(rename = "browser.navigation")]
    Navigation,
    #[serde(rename = "browser.inspect")]
    Inspect,
    #[serde(rename = "browser.interact")]
    Interact,
    #[serde(rename = "browser.transfer")]
    Transfer,
    #[serde(rename = "browser.privileged")]
    Privileged,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserMethodV1 {
    Navigate,
    Read,
    Interact,
    Upload,
    Privileged,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserSensitiveSurfaceV1 {
    Cookies,
    Storage,
    AuthHeaders,
    Cdp,
    ScriptEval,
    Upload,
    Download,
    Clipboard,
    NetworkIntercept,
    PasswordField,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProfileModeV1 {
    Isolated,
    Dedicated,
    #[serde(rename = "remote-debugging")]
    RemoteDebugging,
    Shared,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BrowserMcpArtifactV1 {
    pub name: String,
    pub command: Option<String>,
    pub metadata: Map<String, Value>,
}

/// Ordered entries retain the order of volatile fields without giving Python
/// classification authority. JSON argument strings are parsed by Rust.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "format", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserMcpArgumentsV1 {
    Mapping { entries: Vec<(String, Value)> },
    Json { text: String },
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BrowserAutomationIntentV1 {
    pub version: u32,
    pub intent: BrowserIntentV1,
    pub operation: String,
    pub target_url: Option<String>,
    pub target_origin: Option<String>,
    pub target_domain: Option<String>,
    pub target_path_prefix: Option<String>,
    pub method: BrowserMethodV1,
    pub profile_mode: BrowserProfileModeV1,
    pub mcp_server_name: String,
    pub mcp_server_identity_hash: Option<String>,
    pub mcp_tool_name: String,
    pub mcp_tool_identity_hash: Option<String>,
    pub mcp_schema_hash: Option<String>,
    pub sensitive_surface_flags: Vec<BrowserSensitiveSurfaceV1>,
    pub volatile_fields_dropped: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BrowserMcpDisplayIntentV1 {
    pub intent: BrowserIntentV1,
    pub operation: String,
    pub target_domain: Option<String>,
    pub target_origin: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserMcpRequestV1 {
    Server {
        artifact: BrowserMcpArtifactV1,
    },
    Classify {
        tool_operation: String,
        server_name: String,
    },
    Normalize {
        artifact: BrowserMcpArtifactV1,
        arguments: BrowserMcpArgumentsV1,
    },
    Display {
        intent: BrowserMcpDisplayIntentV1,
        arguments: BrowserMcpArgumentsV1,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserMcpResultV1 {
    Server {
        is_browser: bool,
    },
    Classify {
        intent: Option<BrowserIntentV1>,
    },
    Normalize {
        intent: Option<Box<BrowserAutomationIntentV1>>,
    },
    Display {
        target: String,
    },
}
