//! The burst key on a stored browser approval row (BP-T066).
//!
//! Pending browser rows from one session on one origin coalesce into one card (PRD 5.5,
//! R-QUIET-2). The read model gives each such row a `browser_burst_key`: a digest of the harness,
//! the session, the driver and the origin, so the dashboard groups rows without seeing the raw
//! session id. A row whose session or origin is unknown gets no key and is never coalesced: a
//! step with no known site stands on its own card.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::approval_browser_card::envelope_text;

const KEY_VERSION: &str = "browser-burst:v1";
const SESSION_KEYS: [&str; 2] = ["session_id", "sessionId"];

fn text<'a>(fields: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// The session the row came from: the browser session when the filed intent names one, else the
/// agent session the hook payload names.
fn session(envelope: &Map<String, Value>, intent: Option<&Map<String, Value>>) -> Option<String> {
    if let Some(session) = intent.and_then(|intent| text(intent, "session_ref_digest")) {
        return Some(format!("browser:{session}"));
    }
    let Some(Value::Object(raw)) = envelope.get("raw_payload_redacted") else {
        return None;
    };
    SESSION_KEYS
        .iter()
        .find_map(|key| text(raw, key))
        .map(|session| format!("agent:{session}"))
}

/// The driver the call went to: the MCP server, else the server part of an `mcp__server__tool`
/// name.
fn driver(envelope: &Map<String, Value>) -> &str {
    envelope_text(envelope, "mcp_server")
        .or_else(|| {
            envelope_text(envelope, "tool_name")
                .and_then(|name| name.rsplit_once("__"))
                .map(|(server, _)| server)
        })
        .unwrap_or("")
}

/// The key for one carded row, or `None` when its session or origin is unknown.
pub(crate) fn approval_browser_burst_key(
    envelope: &Value,
    harness: &str,
    card: &Value,
    intent: &Value,
) -> Option<String> {
    let envelope = envelope.as_object()?;
    let intent = intent.as_object();
    let origin = card["site"]["origin"]
        .as_str()
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .or_else(|| intent.and_then(|intent| text(intent, "target_origin")))?;
    let session = session(envelope, intent)?;
    let driver = driver(envelope);
    let digest = Sha256::digest(
        format!("{KEY_VERSION}\0{harness}\0{session}\0{driver}\0{origin}").as_bytes(),
    );
    Some(hex::encode(digest))
}

#[cfg(test)]
#[path = "approval_browser_burst_tests.rs"]
mod tests;
