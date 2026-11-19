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
//!
//! The daemon serves the Codex and Claude Code hook routes only to a client
//! that redeems an identity challenge on the same connection, so those two
//! harnesses take the authenticated exchange their bridges use. The other
//! harnesses post with the daemon token alone, as their bridges do.

use std::time::Instant;

use super::Arguments;
use crate::bounded_hook_bridge::daemon_target;
use crate::claude_hook_bridge_http::remaining;
use crate::claude_hook_bridge_transport::authenticated_claude_hook_response;
use crate::codex_hook_bridge_direct_resident::DirectMiss;
use crate::codex_hook_bridge_transport::authenticated_codex_hook_response;
use crate::cursor_hook_bridge::hook_query;

const STATE_FILE: &str = "daemon-state.json";

/// The daemon's response text for the stamped receipt-only `data`, or
/// `None` when no daemon is reachable or it answered with anything but 200.
pub(super) fn daemon_answer(
    arguments: &Arguments,
    workspace: &str,
    data: &str,
    deadline: Instant,
) -> Option<String> {
    let harness = arguments.harness.as_str();
    let query = hook_query(
        arguments.guard_home.to_str()?,
        Some(workspace),
        Some(arguments.home.to_str()?),
    );
    let state = arguments.guard_home.join(STATE_FILE);
    let miss = DirectMiss::Unanswered;
    let text = match harness {
        "codex" => authenticated_codex_hook_response(&state, &query, data, deadline, miss).ok()?,
        "claude-code" => {
            authenticated_claude_hook_response(&state, &query, data, remaining(deadline), miss)
                .ok()?
        }
        _ => {
            let target = daemon_target(&arguments.guard_home, harness)?;
            let path = format!("/v1/hooks/{harness}?{query}");
            let (status, body) = target.post_status(&path, data, deadline, miss)?;
            if status != 200 {
                return None;
            }
            String::from_utf8(body).ok()?
        }
    };
    Some(text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned())
}

#[cfg(test)]
#[path = "contained_workspace_sink_daemon_tests.rs"]
mod tests;
