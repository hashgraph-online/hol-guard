//! The approval link an MCP block hands the agent.
//!
//! The agent relays this text to the user, and the user can only act on the
//! link it carries. A bare `/requests/<id>` page opens without a dashboard
//! session, so the user cannot see the request it names. The block therefore
//! names the same link a reviewed hook answer does: the review page signed
//! with the daemon's short approval code, with the HOL Guard Desktop link
//! first when Desktop on this machine opens request links.

use std::path::Path;

use crate::daemon_policy_authority::load_guard_daemon_auth_token;
use crate::desktop_review_link::with_desktop_link;
use crate::native_review_link::{
    approval_browser_url, native_review_reason, now_micros, APPROVAL_CENTER_SURFACE, OPEN_GUARD,
    SIGNED_LINK_UNAVAILABLE,
};

/// What the block tells the agent, and the link its structured data names.
pub(super) struct AgentReview {
    pub(super) message: String,
    pub(super) review_url: String,
}

/// `stopped` (one sentence, no trailing period) followed by the signed link
/// for `review_url`, the request it names and the retry step.
pub(super) fn agent_review(
    guard_home: &str,
    stopped: &str,
    request_id: &str,
    review_url: &str,
) -> AgentReview {
    let home = Path::new(guard_home);
    let auth_token = load_guard_daemon_auth_token(home).filter(|token| !token.is_empty());
    agent_review_with(
        home,
        auth_token.as_deref(),
        now_micros(),
        stopped,
        request_id,
        review_url,
    )
}

pub(super) fn agent_review_with(
    home: &Path,
    auth_token: Option<&str>,
    now: Option<i64>,
    stopped: &str,
    request_id: &str,
    review_url: &str,
) -> AgentReview {
    let unavailable = || AgentReview {
        message: format!("{stopped} (request {request_id}). {SIGNED_LINK_UNAVAILABLE}"),
        review_url: review_url.to_owned(),
    };
    let Some(now) = now else {
        return unavailable();
    };
    let raw = format!(
        "{stopped} (request {request_id}). {OPEN_GUARD} {review_url}, then retry the same action."
    );
    // The rule every hook harness but Codex follows: the loopback link is
    // signed in place whenever the daemon has a session secret, which it
    // writes before it serves any page.
    let Some(linked) = native_review_reason("mcp", &raw, review_url, auth_token, now) else {
        return unavailable();
    };
    let signed = approval_browser_url(
        review_url,
        || auth_token.map(str::to_owned),
        APPROVAL_CENTER_SURFACE,
        now,
    );
    AgentReview {
        message: with_desktop_link(linked, home, review_url),
        review_url: signed.unwrap_or_else(|| review_url.to_owned()),
    }
}

#[cfg(test)]
#[path = "mcp_relay_decide_review_link_tests.rs"]
mod tests;
