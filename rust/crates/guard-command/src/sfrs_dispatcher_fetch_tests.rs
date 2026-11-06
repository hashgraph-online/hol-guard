//! The action class a fetch carries when no repository-bound proof settles it.

use super::command_refreshes_a_named_origin;

fn segments(command: &str) -> Vec<Vec<String>> {
    vec![command
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<String>>()]
}

#[test]
fn a_named_origin_refresh_keeps_its_action_class_in_every_admitted_spelling() {
    for command in [
        "git fetch origin",
        "git fetch origin main",
        "git fetch --quiet origin",
        "git fetch --prune origin",
        // The dry run reports the same refresh, so it names the same action
        // and carries the same network risk.
        "git fetch --dry-run origin",
        "git fetch origin main --dry-run",
        "git fetch -n origin",
    ] {
        assert!(
            command_refreshes_a_named_origin(&segments(command)),
            "{command}"
        );
    }
}

#[test]
fn a_fetch_that_names_no_origin_is_not_a_named_origin_refresh() {
    for command in [
        "git fetch --all",
        "git fetch https://example.com/repo.git",
        "git fetch origin --dry-run=payload",
        "git push origin main",
    ] {
        assert!(
            !command_refreshes_a_named_origin(&segments(command)),
            "{command}"
        );
    }
}
