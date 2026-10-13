//! The Cursor `PreToolUse` the resident answers.

use super::{reviewed_edge, HookDirectDefer, PRE_TOOL_USE};
use serde_json::Value;

/// The edge result for a Cursor `PreToolUse`, when the daemon would return
/// it unchanged and the Cursor client runs it as an allow: a response the
/// edge rendered as an allow or warn, for an allow with an allow or warn
/// floor or, in Watch, for any verdict. Outside Watch the daemon may pause or
/// repair a denial, which the Cursor client then renders itself.
pub(super) fn answer(edge: &[u8], recording_only: bool) -> Result<Value, HookDirectDefer> {
    let parsed = reviewed_edge(edge, PRE_TOOL_USE)?;
    let text = |value: Option<&Value>, name: &str| {
        value
            .and_then(|value| value.get(name))
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let result = parsed.get("result");
    let response = parsed.get("harness_response");
    let allowed = (recording_only
        || text(result, "decision").as_deref() == Some("allow")
            && matches!(
                text(result, "minimum_action").as_deref(),
                Some("allow" | "warn")
            ))
        && matches!(
            text(response, "policy_action").as_deref(),
            Some("allow" | "warn")
        );
    if !allowed {
        return Err(HookDirectDefer::NotAllow);
    }
    Ok(parsed)
}
