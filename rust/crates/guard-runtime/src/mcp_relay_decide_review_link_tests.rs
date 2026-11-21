//! The MCP block hands the agent a link the user can open signed in.

use super::*;

const REQUEST_ID: &str = "b6d4d55da3984b94b4b2930f5e99f8fa";
const DAEMON_AUTH: &str = "mcp-review-link-daemon-auth-for-tests";
const NOW: i64 = 1_800_000_000_000_000;
const RELAY: &str = crate::native_review_link::RELAY_SIGNED_LINK;
const STOPPED: &str = "HOL Guard stopped tool call SEARCH_TOOLS from composio";

fn review_url() -> String {
    format!("http://127.0.0.1:5474/requests/{REQUEST_ID}")
}

fn signed_url() -> String {
    crate::native_review_link::handoff_url_for_tests(&review_url(), DAEMON_AUTH, NOW)
        .expect("a request link signs")
}

/// True when `text` names the review page with nothing signed after it.
fn names_bare_page(text: &str) -> bool {
    text.match_indices(&review_url())
        .any(|(at, url)| !text[at + url.len()..].starts_with('/'))
}

#[test]
fn the_block_names_the_signed_link_never_the_bare_page() {
    let home = Path::new("/nonexistent/guard-home");
    let review = agent_review_with(
        home,
        Some(DAEMON_AUTH),
        Some(NOW),
        STOPPED,
        REQUEST_ID,
        &review_url(),
    );
    assert_eq!(
        review.message,
        format!(
            "{STOPPED} (request {REQUEST_ID}). {OPEN_GUARD} {}, then retry the same action. {RELAY}",
            signed_url()
        )
    );
    assert_eq!(review.review_url, signed_url());
    assert!(!names_bare_page(&review.message), "{}", review.message);
}

#[test]
fn a_home_whose_daemon_never_started_keeps_the_page_link() {
    // No daemon has written a session secret, so no page could open signed;
    // the block still names the request, as a hook answer does.
    let home = Path::new("/nonexistent/guard-home");
    let review = agent_review_with(home, None, Some(NOW), STOPPED, REQUEST_ID, &review_url());
    assert_eq!(
        review.message,
        format!(
            "{STOPPED} (request {REQUEST_ID}). {OPEN_GUARD} {}, then retry the same action.",
            review_url()
        )
    );
    assert_eq!(review.review_url, review_url());
    let clockless = agent_review_with(
        home,
        Some(DAEMON_AUTH),
        None,
        STOPPED,
        REQUEST_ID,
        &review_url(),
    );
    assert_eq!(
        clockless.message,
        format!("{STOPPED} (request {REQUEST_ID}). {SIGNED_LINK_UNAVAILABLE}")
    );
}

#[test]
fn an_external_center_link_is_named_as_it_is() {
    let home = Path::new("/nonexistent/guard-home");
    let external = format!("https://guard.example.com/requests/{REQUEST_ID}");
    let review = agent_review_with(
        home,
        Some(DAEMON_AUTH),
        Some(NOW),
        STOPPED,
        REQUEST_ID,
        &external,
    );
    assert_eq!(
        review.message,
        format!("{STOPPED} (request {REQUEST_ID}). {OPEN_GUARD} {external}, then retry the same action.")
    );
    assert_eq!(review.review_url, external);
}

#[cfg(unix)]
#[test]
fn a_desktop_user_gets_the_desktop_link_first_and_the_signed_link_after() {
    use crate::claude_hook_bridge_fixture::{write_private, GuardHome};

    let home = GuardHome::new("mcp-review-link-desktop");
    let marker = serde_json::json!({
        "version": 1,
        "scheme": "hol-guard-desktop",
        "routes": ["requests"],
        "app_path": home.home.to_string_lossy(),
    });
    write_private(
        &home.home.join("desktop-deep-link.json"),
        &marker.to_string(),
    );
    let review = agent_review_with(
        &home.home,
        Some(DAEMON_AUTH),
        Some(NOW),
        STOPPED,
        REQUEST_ID,
        &review_url(),
    );
    assert_eq!(
        review.message,
        format!(
            "{STOPPED} (request {REQUEST_ID}). {OPEN_GUARD} hol-guard-desktop://requests/{REQUEST_ID} \
             (HOL Guard Desktop), or in a browser: {}, then retry the same action. {RELAY}",
            signed_url()
        )
    );
    assert!(!names_bare_page(&review.message), "{}", review.message);
}
