//! An arithmetic expansion that assigns runs while the step's own words
//! expand, and the shell looks the program up only afterwards. A step such
//! as `last -n $((PATH=1))` therefore runs whatever `1/last` names, so a
//! probe that reads its words as a harmless status query must not allow it.
#![cfg(unix)]

use crate::git_helper_fixture::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn action(command: &str) -> String {
    evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":command}}),
        None,
        None,
        None,
        None,
    )
    .minimum_action
}

#[test]
fn a_probe_without_an_assignment_stays_allowed() {
    for command in ["last -n 1", "who am i"] {
        assert_eq!(action(command), "allow", "{command:?}");
    }
}

#[test]
fn an_assignment_in_the_step_s_own_words_is_not_allowed() {
    for command in [
        "last -n $((PATH=1))",
        "echo $((PATH=1))",
        "who $((PATH=1))",
        "gh api user --jq .login $((PATH=1))",
    ] {
        assert_ne!(action(command), "allow", "{command:?}");
    }
}
