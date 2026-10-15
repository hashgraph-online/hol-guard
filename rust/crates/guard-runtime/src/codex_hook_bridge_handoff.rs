//! What the native Codex bridge does with a daemon answer after rendering
//! it, as Python's bridge `main` does through `_bridge_output`.
//!
//! For a `PreToolUse` deny, `_bridge_output` changes the answer only in two
//! ways: `route_codex_containment` rewrites a sandbox requirement, and
//! `apply_browser_approval_wait` holds a deny that names a pending browser
//! approval. Both run natively (see `contain` and `approval`), as does the
//! transition observation written before it (see `observation`). Any other
//! answer comes out of `_bridge_output` as `codex_hook_response(response)`,
//! which the native bridge renders identically.

use super::approval::{pending_pretool_approval, Pending};
use crate::codex_hook_response::PRE_TOOL_USE;
use crate::pyjson::PyVal;

/// What follows the native render of one daemon answer.
#[derive(Debug, PartialEq)]
pub(super) enum Post {
    /// The render is the answer.
    Native,
    /// `route_codex_containment` settles the sandbox requirement first.
    Contain,
    /// The deny waits for the browser's decision on this request.
    Approval(Pending),
}

/// How `_bridge_output` would treat `response`.
pub(super) fn post_render(response: &PyVal, event_name: &str) -> Post {
    if event_name != PRE_TOOL_USE {
        return Post::Native;
    }
    // `route_codex_containment` acts only on this exact policy action.
    if matches!(response.get("policy_action"), Some(PyVal::Str(text)) if text == "sandbox-required")
    {
        return Post::Contain;
    }
    pending_pretool_approval(response, event_name).map_or(Post::Native, Post::Approval)
}

#[cfg(all(test, unix))]
#[path = "codex_hook_bridge_handoff_tests.rs"]
mod tests;
