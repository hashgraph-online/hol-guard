use super::by_app;

#[test]
fn messages_the_app_writes_itself_are_recognised() {
    for prompt in [
        "<task-notification>\n<task-id>b1</task-id>\n<status>completed</status>",
        "  <system-reminder>\nThe user hasn't heard from you in a while.\n</system-reminder>",
        "Stop hook feedback: [goal] the cart total test still fails in src/cart.rs",
        "Goal check-in: «fix the cart total» is still active",
        "This session is being continued from a previous conversation that ran out of context.",
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
    ] {
        assert!(!by_app(prompt), "{prompt}");
    }
}
