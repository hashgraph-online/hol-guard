//! BP-T072: what the agent reads when Guard holds or blocks a browser action.
//!
//! A stored row whose call a first-party driver profile classifies carries a
//! browser card. Its hook reply then names the site, says whether the agent
//! should wait for the person, and tells it not to retry in a loop.
//!
//! The approval link stays in the reply for every profile mode, shared ones
//! included: `docs/guard/approval-invariant.md` requires every executable
//! review to offer Allow once and Always allow on every route, and a Codex
//! bridge holds its wait only when the block names the link. A shared or
//! remote-debugging session already keeps the page itself closed (R-SURFACE).

use serde_json::{Map, Value};

use crate::blocked_request_mode::{falsy_or_text, BLOCKED_REASON};
use crate::hook_decision_review_response::REVIEW_DEFAULT_REASON;

/// The longest origin the note names: a full DNS name with a scheme and port.
const MAX_ORIGIN_CHARS: usize = 280;
/// The site wording when the card names no origin the note can quote.
const UNNAMED_SITE: &str = "a site Guard could not name";

/// The note for `row`, or `None` when the row carries no browser card.
/// `approval_can_unblock` says whether the person's decision can let the
/// agent run the action, so the note asks it to wait only then.
pub(crate) fn browser_hold_note(
    row: &Map<String, Value>,
    approval_can_unblock: bool,
) -> Option<String> {
    let card = row.get("browser_card")?.as_object()?;
    let site = card
        .get("site")
        .and_then(|site| site.get("origin"))
        .and_then(Value::as_str)
        .filter(|origin| quotable(origin))
        .map_or_else(|| UNNAMED_SITE.to_owned(), |origin| format!("`{origin}`"));
    Some(if approval_can_unblock {
        format!(
            "Guard is holding this browser action on {site} until the person reviews it. \
             Wait for their decision and do not retry the action in a loop."
        )
    } else {
        format!(
            "Guard blocked this browser action on {site}. \
             Do not retry it in a loop; take another step or ask the person."
        )
    })
}

/// An origin the note can quote as is: printable ASCII with no backtick or
/// space, so the agent reads it as one literal.
fn quotable(origin: &str) -> bool {
    !origin.is_empty()
        && origin.len() <= MAX_ORIGIN_CHARS
        && origin
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'`')
}

/// Appends the note to a paused review's verdict reason.
pub(crate) fn note_paused(row: &Map<String, Value>, verdict: &mut Map<String, Value>) {
    let Some(note) = browser_hold_note(row, true) else {
        return;
    };
    let reason = match verdict.get("reason") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => REVIEW_DEFAULT_REASON,
    };
    let reason = format!("{reason} {note}");
    verdict.insert("reason".to_owned(), Value::String(reason));
}

/// Appends the note to the reason a silent block shows: the connector's
/// setup text when it has one, else the review's own reason.
pub(crate) fn note_silent(
    row: &Map<String, Value>,
    approval_can_unblock: bool,
    result: &mut Map<String, Value>,
    setup_reason: &mut Option<String>,
) {
    let Some(note) = browser_hold_note(row, approval_can_unblock) else {
        return;
    };
    if let Some(setup) = setup_reason.as_mut().filter(|text| !text.is_empty()) {
        *setup = format!("{setup} {note}");
        return;
    }
    // A reason the renderer cannot read stays as it is, so it still fails closed.
    if let Some(reason) = falsy_or_text(result.get("reason"), BLOCKED_REASON) {
        let reason = format!("{reason} {note}");
        result.insert("reason".to_owned(), Value::String(reason));
    }
}

#[cfg(test)]
#[path = "browser_hold_text_tests.rs"]
mod tests;
