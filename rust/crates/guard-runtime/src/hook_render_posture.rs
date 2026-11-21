//! Whether an acknowledged policy binding records instead of stopping.
//!
//! `recording_only_for_binding` is what the daemon, the Cursor probe and the
//! review fence ask before they act on a binding. A per-harness override wins
//! over the snapshot mode in both directions: Watch records under an enforcing
//! snapshot, and Protected or Extra careful keeps stopping under a Watch one.
//! A missing binding never grants recording-only authority.

use guard_command::harness_identity::canonical_harness_id;
use serde_json::Value;

const POSTURES: [&str; 3] = ["protected", "extra_careful", "watch"];

/// `runtime_harness_key`: a registry id for a known name or alias, the
/// normalized name for an unknown one, nothing for a blank or non-text value.
fn harness_key(harness: &Value) -> Option<String> {
    let key = harness.as_str()?.trim().to_lowercase().replace('_', "-");
    if key.is_empty() {
        return None;
    }
    Some(canonical_harness_id(&key).map_or(key, str::to_owned))
}

/// The override this harness carries, ignoring malformed pairs.
fn override_for<'a>(binding: &'a Value, harness: &Value) -> Option<&'a str> {
    let key = harness_key(harness)?;
    let posture = binding.get("harness_postures")?.as_object()?.get(&key)?;
    posture
        .as_str()
        .filter(|posture| POSTURES.contains(posture))
}

pub(crate) fn recording_only_for_binding(binding: Option<&Value>, harness: &Value) -> bool {
    let Some(binding) = binding.filter(|binding| binding.is_object()) else {
        return false;
    };
    match override_for(binding, harness) {
        Some(posture) => posture == "watch",
        None => binding.get("mode").and_then(Value::as_str) == Some("observe"),
    }
}

/// Whether Cursor's silent probe goes on to the daemon's review: it needs a
/// workspace and an acknowledged binding that is not recording only.
pub(crate) fn cursor_probe_reviews(snapshot: Option<&Value>, has_workspace: bool) -> bool {
    has_workspace
        && snapshot.is_some_and(Value::is_object)
        && !recording_only_for_binding(snapshot, &Value::from("cursor"))
}

#[cfg(test)]
#[path = "hook_render_posture_tests.rs"]
mod tests;
