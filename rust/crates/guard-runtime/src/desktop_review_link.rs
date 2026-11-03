//! The HOL Guard Desktop link a paused review offers beside its browser link.
//!
//! HOL Guard Desktop registers the `hol-guard-desktop:` URL scheme and opens
//! `hol-guard-desktop://requests/<id>` in its own signed-in window, so a user
//! who runs Desktop never lands on a browser tab that has no local session.
//! Desktop says it handles that route by writing `desktop-deep-link.json` to
//! the Guard home it manages. Guard composes the link itself; the marker only
//! says whether to offer it, and a marker whose app bundle is gone offers
//! nothing. The signed browser link always stays in the reason as a fallback.

use std::path::Path;

use serde_json::Value;

use crate::native_review_link::OPEN_GUARD;

pub(crate) const DESKTOP_LINK_SCHEME: &str = "hol-guard-desktop";
const MARKER_FILE: &str = "desktop-deep-link.json";
const MARKER_MAX_BYTES: u64 = 4 * 1024;
const MARKER_VERSION: u64 = 1;
const REQUESTS_ROUTE: &str = "requests";
const REQUEST_ID_HEX: usize = 32;
pub(crate) const OPEN_IN_BROWSER: &str = "or in a browser:";

/// Whether Desktop's marker in `guard_home` says it opens request links.
pub(crate) fn desktop_opens_requests(guard_home: &Path) -> bool {
    let Some(text) = crate::daemon_policy_authority::read_private_regular_text(
        &guard_home.join(MARKER_FILE),
        MARKER_MAX_BYTES,
        true,
    ) else {
        return false;
    };
    let Ok(Value::Object(marker)) = serde_json::from_str::<Value>(&text) else {
        return false;
    };
    let version = marker.get("version").and_then(Value::as_u64) == Some(MARKER_VERSION);
    let scheme = marker.get("scheme").and_then(Value::as_str) == Some(DESKTOP_LINK_SCHEME);
    let routes = marker
        .get("routes")
        .and_then(Value::as_array)
        .is_some_and(|routes| routes.iter().any(|route| route == REQUESTS_ROUTE));
    let installed = marker
        .get("app_path")
        .and_then(Value::as_str)
        .is_some_and(|path| !path.is_empty() && Path::new(path).exists());
    version && scheme && routes && installed
}

/// The request id of a `/requests/<id>` approval link: 32 lowercase hex
/// characters, the shape the approval queue issues.
pub(crate) fn approval_request_id(approval_url: &str) -> Option<&str> {
    let without_fragment = approval_url.split('#').next()?;
    let (_, id) = without_fragment.rsplit_once("/requests/")?;
    let shaped = id.len() == REQUEST_ID_HEX
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    shaped.then_some(id)
}

/// `hol-guard-desktop://requests/<id>` for a request link.
pub(crate) fn desktop_request_url(request_id: &str) -> String {
    format!("{DESKTOP_LINK_SCHEME}://{REQUESTS_ROUTE}/{request_id}")
}

/// The Desktop link for `approval_url` when Desktop in `guard_home` opens it.
pub(crate) fn desktop_review_url(guard_home: &Path, approval_url: &str) -> Option<String> {
    let request_id = approval_request_id(approval_url)?;
    desktop_opens_requests(guard_home).then(|| desktop_request_url(request_id))
}

/// `reason` with the Desktop link put first in its Open-HOL-Guard step and
/// the browser link kept after it. A reason with no such step, one that
/// already names the Desktop link, or a user without Desktop is unchanged.
pub(crate) fn with_desktop_link(reason: String, guard_home: &Path, approval_url: &str) -> String {
    if !reason.contains(OPEN_GUARD) {
        return reason;
    }
    let Some(desktop_url) = desktop_review_url(guard_home, approval_url) else {
        return reason;
    };
    if reason.contains(&desktop_url) {
        return reason;
    }
    reason.replacen(
        OPEN_GUARD,
        &format!("{OPEN_GUARD} {desktop_url} (HOL Guard Desktop), {OPEN_IN_BROWSER}"),
        1,
    )
}

#[cfg(test)]
#[path = "desktop_review_link_tests.rs"]
mod tests;
