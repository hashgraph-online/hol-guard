use super::by_app;

#[test]
fn messages_the_app_writes_itself_are_recognised() {
    for prompt in [
        "<task-notification>\n<task-id>b1</task-id>\n<status>completed</status>",
        "  <system-reminder>\nThe user hasn't heard from you in a while.\n</system-reminder>",
        "Stop hook feedback: [goal] the cart total test still fails in src/cart.rs",
        "Goal check-in: «fix the cart total» is still active",
        "This session is being continued from a previous conversation that ran out of context.",
        "<bash-input>cargo test -p cart</bash-input>",
        "<bash-stdout></bash-stdout><bash-stderr>error[E0425]: cannot find `total_cents`</bash-stderr>",
        "<bash-stderr>Error: approval needs an interactive terminal</bash-stderr>",
        "<ci-monitor-event>A watcher saw a check fail on acme/cart pull request 12: \"ci (3.12)\"\n</ci-monitor-event>",
    ] {
        assert!(by_app(prompt), "{prompt}");
    }
}

#[test]
fn typed_prompts_are_not_taken_for_the_apps_own() {
    for prompt in [
        "fix the cart total in src/cart.rs",
        "why does the <task-notification> parser drop the status tag?",
        "Explain the stop hook feedback loop in hooks.rs",
        "resume",
        "why does <bash-input> show up in the cart log?",
        "fix the parser for `<ci-monitor-event>` blocks in src/events.rs",
    ] {
        assert!(!by_app(prompt), "{prompt}");
    }
}
