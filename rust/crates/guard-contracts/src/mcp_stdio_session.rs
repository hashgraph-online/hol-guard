//! `McpStdioSession*` resident contracts — bounded native MCP stdio data plane
//! (RTM-022/023). The resident owns the child process, newline JSON-RPC
//! framing, cross-correlation, and process-group teardown; Python relays
//! policy/approval authority out-of-band. Every request carries `schema`; the
//! result envelope is a single `McpStdioSessionResultV1`.
use serde::Deserialize;
use serde_json::Value;

pub const MCP_STDIO_SESSION_FEATURE: &str = "mcp-stdio-session-v1";

pub const MCP_STDIO_SESSION_OPEN_REQUEST_SCHEMA: &str = "guard-mcp-stdio-session-open-request.v1";
pub const MCP_STDIO_SESSION_IO_REQUEST_SCHEMA: &str = "guard-mcp-stdio-session-io-request.v1";
pub const MCP_STDIO_SESSION_RESULT_SCHEMA: &str = "guard-mcp-stdio-session-result.v1";

/// `open` — spawn the scrubbed child and register a live session.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpStdioSessionOpenRequestV1 {
    pub schema: String,
    /// Caller-chosen opaque session id (bounded length, validated op-side).
    pub session_id: String,
    /// Resolved launch argv (tokens resolved by the control plane, like the
    /// probe's `mcp_launch_tokens`/`resolve_argv_from_tokens`).
    pub argv: Vec<String>,
    /// Proxy process whose lifetime owns this session. Required; never inferred from the id.
    pub owner_pid: u32,
    /// Optional harness/env overlay applied on top of the scrubbed env.
    #[serde(default)]
    pub extra_env: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    pub home_dir: Option<String>,
    /// Optional working directory for the child process.
    #[serde(default)]
    pub cwd: Option<String>,
}

/// `send` — write a client→child JSON-RPC frame (or relay a verdict).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpStdioSessionSendRequestV1 {
    pub schema: String,
    pub session_id: String,
    /// Raw JSON-RPC message to frame onto the child's stdin.
    pub message: Value,
}

/// `recv` — drain the next inbound child frame within `timeout_ms`. When
/// `await_request_id` is set, the op correlates and returns the matching
/// response, buffering interleaved frames (mirrors `_drain_child_messages`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpStdioSessionRecvRequestV1 {
    pub schema: String,
    pub session_id: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Correlate to this request id: returns the matching child response,
    /// stashing interleaved responses/requests for later surfacing.
    #[serde(default)]
    pub await_request_id: Option<Value>,
    /// Query child status without consuming a queued child frame.
    #[serde(default)]
    pub poll_only: bool,
}

/// `close`/`cancel` — cooperative cancel + process-group teardown.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpStdioSessionCloseRequestV1 {
    pub schema: String,
    pub session_id: String,
}

/// Unified result envelope. `kind` discriminates which field is populated.
#[derive(Debug, serde::Serialize)]
pub struct McpStdioSessionResultV1 {
    pub schema: String,
    /// `"opened" | "sent" | "event" | "closed" | "cancelled" | "timeout" | "running" | "exited" | "eof" | "error"`.
    pub status: String,
    /// For `event`: `"child_response" | "child_request" | "child_notification"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_kind: Option<String>,
    /// The surfaced JSON-RPC frame for `event`, or the open ack payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    /// True when the await correlation timed out (`status:"timeout"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timed_out: Option<bool>,
    /// Process exit code when `status:"exited"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

impl McpStdioSessionResultV1 {
    pub fn status(status: &str) -> Self {
        Self {
            schema: MCP_STDIO_SESSION_RESULT_SCHEMA.to_owned(),
            status: status.to_owned(),
            event_kind: None,
            payload: None,
            timed_out: None,
            exit_code: None,
        }
    }
}
