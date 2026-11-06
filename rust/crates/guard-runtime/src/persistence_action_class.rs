//! Whether an artifact's `action_class` label names a boot or login mechanism.
//!
//! A protected posture stops a persistence action outright once the action
//! installs something that survives the session, so the label is read for the
//! mechanisms that do: launch agents and login items on macOS, `cron` and
//! `systemd` units elsewhere, and the tools that write them. The table lives
//! here because the stop is the resident's to decide; a caller that keeps its
//! own copy of it can disagree with the resident about the same label and
//! withhold a block the posture asked for.

/// Substrings of an `action_class` that name a surviving-boot mechanism.
const MECHANISM_TOKENS: [&str; 6] = [
    "launch agent",
    "login item",
    "launchctl",
    "cron",
    "systemd",
    "launchd",
];

/// True when `action_class` names one of those mechanisms.
///
/// The match is a lowercased substring test rather than a word match: the
/// labels are prose written by the detectors ("writes a LaunchAgent plist"),
/// so the mechanism appears inside a sentence rather than as a token.
pub(crate) fn action_class_writes_persistence_agent(action_class: Option<&str>) -> bool {
    let Some(label) = action_class else {
        return false;
    };
    let lowered = label.to_lowercase();
    MECHANISM_TOKENS.iter().any(|token| lowered.contains(token))
}

#[cfg(test)]
#[path = "persistence_action_class_tests.rs"]
mod tests;
