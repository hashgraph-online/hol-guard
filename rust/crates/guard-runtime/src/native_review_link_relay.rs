//! The note that asks an agent to pass a signed review link on unchanged.

use super::carries_handoff_link;

/// Follows every signed link the agent is handed. Agents relay the link in
/// their own words, and one that shortens it to the bare request page leaves
/// the user on a page with no session, which cannot show the request.
pub(crate) const RELAY_SIGNED_LINK: &str = "Give the user this link exactly as written: the code after the request id signs them in, and the page cannot show the request without it.";

/// `text` with [`RELAY_SIGNED_LINK`] after it when it names a signed link for
/// `approval_url`. A raw or external link is left alone: nothing in it can be
/// lost on the way to the user.
pub(crate) fn with_relay_note(text: String, approval_url: &str) -> String {
    let signed =
        carries_handoff_link(&text, approval_url) || text.contains(&format!("{approval_url}#"));
    if !signed || text.contains(RELAY_SIGNED_LINK) {
        return text;
    }
    format!("{text} {RELAY_SIGNED_LINK}")
}
