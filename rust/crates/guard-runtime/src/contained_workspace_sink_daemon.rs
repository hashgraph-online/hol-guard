//! The daemon's receipt for a contained call the live resident did not
//! answer.
//!
//! The hook bridges ask the resident first and post anything it defers to
//! the loopback daemon, which reviews it with the same native policy. The
//! sink asks again before it runs anything, and it used to ask the resident
//! only, so a resident that deferred for a while (after an upgrade restarted
//! the daemon, for example) failed every contained run the hook had already
//! routed here. The daemon is now asked the same receipt-only question, as
//! Guard's CLI sink asks its own in-process worker. Its answer is a receipt
//! like the resident's and still has to pass every check the sink applies.

use std::time::Instant;

use super::Arguments;
use crate::bounded_hook_bridge::daemon_target;
use crate::codex_hook_bridge_direct_resident::DirectMiss;
use crate::cursor_hook_bridge::hook_query;

/// The daemon's response text for the stamped receipt-only `data`, or
/// `None` when no daemon is reachable or it answered with anything but 200.
pub(super) fn daemon_answer(
    arguments: &Arguments,
    workspace: &str,
    data: &str,
    deadline: Instant,
) -> Option<String> {
    let harness = arguments.harness.as_str();
    let target = daemon_target(&arguments.guard_home, harness)?;
    let query = hook_query(
        arguments.guard_home.to_str()?,
        Some(workspace),
        Some(arguments.home.to_str()?),
    );
    let path = format!("/v1/hooks/{harness}?{query}");
    let (status, body) = target.post_status(&path, data, deadline, DirectMiss::Unanswered)?;
    if status != 200 {
        return None;
    }
    let text = String::from_utf8(body).ok()?;
    Some(text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned())
}

#[cfg(test)]
#[path = "contained_workspace_sink_daemon_tests.rs"]
mod tests;
