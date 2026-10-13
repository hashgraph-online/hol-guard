//! The package reviews the daemon queues without trying to settle them.
//!
//! Before it queues a review, `pause_native_pre_tool_for_approval`
//! (`hook_native_review_approval.py`) asks `native_package_review_response`
//! (`hook_native_package_review.py`) to settle a package install review. For
//! a plain `npm` command that step proves which npm the agent runs from its
//! `PATH` and config files, then hands the install to the package evaluator,
//! which may fetch registry metadata or answer that it is still loading.
//!
//! This ports only the checks that step makes before its first filesystem
//! probe. When one of them already returns `None`, the daemon queues the
//! review as it queues any other, and so may the resident. A review that
//! reaches a probe or the evaluator stays with the daemon.

use super::super::super::EXECUTION_ENVIRONMENT_FIELD;
use super::super::query::pre_tool_command;
use crate::context_digest::python_strip;
use guard_command::hook_responses::Object;
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::LazyLock;

/// `PACKAGE_REVIEW_REASON`: a review `native_package_review_response` may
/// settle before anything is queued.
pub(super) const PACKAGE_REVIEW_REASON: &str = "native_package_review";
/// `_ENVIRONMENT_OVERRIDES`: prefixes that change what npm or node load.
const ENVIRONMENT_OVERRIDES: [&str; 3] = ["npm_config_", "node_options", "node_path"];
/// `_ENVIRONMENT_NAMES`.
const ENVIRONMENT_NAMES: [&str; 3] = ["prefix", "destdir", "node_tls_reject_unauthorized"];
/// `_INERT_NPM_SETTINGS`: npm settings that leave the fetch where it was.
const INERT_NPM_SETTINGS: [&str; 7] = [
    "cache",
    "update-notifier",
    "fund",
    "audit",
    "loglevel",
    "progress",
    "color",
];

/// `_FILTERED_COMMAND`: one plain command, optionally trimmed by output
/// filters that read only the pipe.
static FILTERED_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    let word = r"[A-Za-z0-9@/._^:+,-][A-Za-z0-9@/._~^:=+,-]*";
    let pattern = r"[A-Za-z0-9@/._^:+,][A-Za-z0-9@/._~^:=+,-]*";
    let filter =
        format!(r"(?:tail|head)(?: +-[0-9]+| +-n *[0-9]+)?|grep(?: +-[iEFvcnw]+)* +{pattern}");
    Regex::new(&format!(
        r"^(?:(?P<command>{word}(?: +{word})*)(?: +2>&1)?(?P<filters>(?: *\| *(?:{filter}))*))$"
    ))
    .expect("filtered command pattern")
});

/// Whether `native_package_review_response` returns `None` for this review
/// before it probes the filesystem, so the daemon goes on to queue it.
///
/// `windows` is `os.name == "nt"`, and `payload` the payload as the daemon
/// records it, with the execution environment the hook bridge stamped. The
/// resident always has a workspace, so that check never returns `None` here.
/// `false` means the daemon may settle the review, or that the resident
/// cannot tell.
pub(super) fn left_to_queue(windows: bool, payload: &Map<String, Value>, result: &Object) -> bool {
    if windows
        || result.get("reason_code").and_then(Value::as_str) != Some(PACKAGE_REVIEW_REASON)
        || result.get("minimum_action").and_then(Value::as_str) != Some("review")
    {
        return true;
    }
    let command = match pre_tool_command(payload) {
        Ok(Some(command)) => command,
        Ok(None) => return true,
        Err(_) => return false,
    };
    let Some(shape) = FILTERED_COMMAND.captures(python_strip(&command)) else {
        return true;
    };
    let program = shape
        .name("command")
        .and_then(|command| command.as_str().split(' ').find(|word| !word.is_empty()));
    program != Some("npm") || npm_unverifiable(payload.get(EXECUTION_ENVIRONMENT_FIELD))
}

/// The checks `verified_npm_version` makes before its first filesystem
/// probe: `true` when one of them already returns `None`.
///
/// `_changes_npm` lowercases names with Python's full Unicode mapping, so a
/// name outside ASCII counts as unchanged here; when nothing else returns
/// `None`, the daemon probes and the review stays with it.
fn npm_unverifiable(environment: Option<&Value>) -> bool {
    let Some(Value::Object(environment)) = environment else {
        return true;
    };
    let Some(Value::Array(names)) = environment.get("environment_names") else {
        return true;
    };
    let moved = names.iter().any(|name| {
        name.as_str()
            .is_none_or(|name| name.is_ascii() && changes_npm(name))
    });
    moved || !matches!(environment.get("path"), Some(Value::String(path)) if !path.is_empty())
}

/// `_changes_npm` for an ASCII name: whether it may change what npm or node
/// load or fetch.
fn changes_npm(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    if let Some(setting) = lowered.strip_prefix("npm_config_") {
        // npm reads `npm_config_update_notifier` as `update-notifier`.
        return !INERT_NPM_SETTINGS.contains(&setting.replace('_', "-").as_str());
    }
    ENVIRONMENT_OVERRIDES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
        || ENVIRONMENT_NAMES.contains(&lowered.as_str())
}

#[cfg(test)]
#[path = "hook_direct_review_package_tests.rs"]
mod tests;
