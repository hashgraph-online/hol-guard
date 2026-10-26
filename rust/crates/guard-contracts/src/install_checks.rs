//! Install-check constants ported from `cli/native_install_checks.py`.
//!
//! These are the pure data contracts (event-name allowlists) that the native
//! installer check consumes. The file-IO / HarnessContext orchestration that
//! walks a `hooks.json` and dispatches `is_grok_hook_command` stays host-side
//! in Python — only the stable required-event set is shared so a native
//! check cannot drift from the Python gate.

/// Required Grok observation events that must carry a managed Guard command
/// hook before a prompt hook is considered "observe" coverage.
///
/// `_grok_prompt_hook_is_observe` (`native_install_checks.py:148`): the
/// `required` tuple. Order matches Python for stable iteration.
pub const GROK_OBSERVE_REQUIRED_EVENTS: [&str; 3] =
    ["UserPromptSubmit", "SubagentStart", "SessionStart"];

/// `hook_entry["type"]` discriminator for a managed command hook.
/// `_grok_event_has_command_hook` (`native_install_checks.py:163`).
pub const GROK_HOOK_TYPE_COMMAND: &str = "command";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_events_stable_order() {
        assert_eq!(
            GROK_OBSERVE_REQUIRED_EVENTS,
            ["UserPromptSubmit", "SubagentStart", "SessionStart"]
        );
    }
}
