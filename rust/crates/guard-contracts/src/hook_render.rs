//! `HookRender` - wire contract for the resident op that renders a harness
//! response from a verdict the daemon adjusted after the edge decision.
//!
//! The edge result already carries the rendered response for the verdict Rust
//! produced. Review-tier outcomes (saved approval, queued review, policy
//! repair) change the verdict afterwards, so they ask the resident to render
//! the adjusted verdict. The op is pure: no IO and no state.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema discriminator for the request.
pub const HOOK_RENDER_REQUEST_SCHEMA: &str = "guard-hook-render-request.v1";
/// Schema discriminator for the result.
pub const HOOK_RENDER_RESULT_SCHEMA: &str = "guard-hook-render-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const HOOK_RENDER_FEATURE: &str = "hook-render-v2";
/// Largest canonical request serialization the op will accept.
pub const HOOK_RENDER_MAX_BYTES: usize = 256 * 1024;
/// Largest canonical `cli_hook_emit` request. That kind carries a whole daemon
/// answer as escaped JSON text, and the answer is built in-process from the
/// hook payload with no cap of its own, so it gets a budget that still fits
/// the resident's request frame.
pub const HOOK_RENDER_CLI_EMIT_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Largest canonical `cursor_shell_route` request. That kind carries the edge
/// result the daemon already produced, and a native response may be as large as
/// [`crate::MAX_NATIVE_RESPONSE_BYTES`], so a valid large edge would not fit the
/// ordinary budget. Refusing it would drop the probe back to an ordinary review
/// and lose the containment route, so the kind gets a budget that holds one.
pub const HOOK_RENDER_CURSOR_ROUTE_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Largest canonical `hermes_bridge` / `muse_bridge` request. Each carries the
/// whole daemon reply it renders, and a native response may be as large as
/// [`crate::MAX_NATIVE_RESPONSE_BYTES`], so a valid reply over the ordinary
/// budget would be refused before rendering -- turning an allow the daemon
/// already reached into a fail-closed refusal of a permitted call.
pub const HOOK_RENDER_DAEMON_REPLY_MAX_BYTES: usize = 4 * 1024 * 1024;

/// The canonical request budget for one render `kind`.
#[must_use]
pub fn hook_render_max_bytes(kind: &str) -> usize {
    match kind {
        "cli_hook_emit" => HOOK_RENDER_CLI_EMIT_MAX_BYTES,
        "cursor_shell_route" => HOOK_RENDER_CURSOR_ROUTE_MAX_BYTES,
        "hermes_bridge" | "muse_bridge" => HOOK_RENDER_DAEMON_REPLY_MAX_BYTES,
        _ => HOOK_RENDER_MAX_BYTES,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookRenderRequestV1 {
    pub schema: String,
    #[serde(default)]
    pub request_id: String,
    /// `pre_tool`, `pre_tool_review`, `recording_only_pre_tool`, `cli_response`,
    /// `cli_document`, `copilot_hook_response`, `claude_approval_copy`,
    /// `artifact_id`, `terminal_policy_action`, `cursor_after_shell_observed`,
    /// `cursor_observer_event`, `hermes_bridge`, `muse_bridge` or `cli_hook_emit`.
    pub kind: String,
    pub harness: String,
    /// The verdict to render; absent for `recording_only_pre_tool`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Value>,
    /// The queued approval a review response points at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<Value>,
    /// The review reason with the signed approval link already applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_reason: Option<String>,
    /// Reason code and reason for `recording_only_pre_tool`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Composed outcome for the `cli_*` kinds: canonical harness, event,
    /// policy action, reason, system message, envelope and the path flags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HookRenderResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_hook_render_*` failure codes.
    pub code: String,
    /// `{"response": {...}}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}
