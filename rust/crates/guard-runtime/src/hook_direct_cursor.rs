//! The Cursor `PreToolUse` the resident answers.
//!
//! A Cursor `PostToolUse` (the client's `afterShellExecution` and
//! `afterMCPExecution` observers) takes the shared `PostToolUse` lane: the
//! daemon has no Cursor step for it and records the edge's response, as the
//! drain does. A Cursor prompt takes the shared prompt lane: the daemon
//! accepts its receipt and returns the edge's response, with no notice.
//! Outside Watch, a review this module leaves takes the shared saved
//! decision, approve-once and approval inbox path, which keeps a pause the
//! Cursor client would rewrite with the daemon.

use super::{reviewed_edge, HookDirectDefer, PRE_TOOL_USE, REPAIRABLE_BLOCK_REASON};
use serde_json::Value;

/// The edge result for a Cursor `PreToolUse`, when the daemon would return
/// it unchanged and the Cursor client renders it without Guard's Python:
/// a response the edge rendered as an allow or warn, for an allow with an
/// allow or warn floor or, in Watch, for any verdict; and outside Watch a
/// response the edge rendered as a block or sandbox requirement, for a
/// terminal block or sandbox floor. The daemon may pause a review and repair
/// an authority block, and Cursor has no contained route, so neither of
/// those is answered here; the caller hands a review to the saved decision
/// path.
pub(super) fn answer(edge: &[u8], recording_only: bool) -> Result<Value, HookDirectDefer> {
    let parsed = reviewed_edge(edge, PRE_TOOL_USE)?;
    let text = |value: Option<&Value>, name: &str| {
        value
            .and_then(|value| value.get(name))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let result = parsed.get("result");
    let field = |name: &str| text(result, name);
    let rendered = text(parsed.get("harness_response"), "policy_action");
    let rendered_allow = matches!(rendered.as_deref(), Some("allow" | "warn"));
    let rendered_deny = matches!(rendered.as_deref(), Some("block" | "sandbox-required"));
    let passed_through = if recording_only {
        rendered_allow
    } else {
        match (
            field("decision").as_deref(),
            field("minimum_action").as_deref(),
        ) {
            (Some("allow"), Some("allow" | "warn")) => rendered_allow,
            (Some("deny" | "block"), Some("block")) => {
                rendered_deny && field("reason_code").as_deref() != Some(REPAIRABLE_BLOCK_REASON)
            }
            (Some("deny" | "block"), Some("sandbox-required")) => rendered_deny,
            _ => false,
        }
    };
    if !passed_through {
        return Err(HookDirectDefer::NotAllow);
    }
    Ok(parsed)
}
