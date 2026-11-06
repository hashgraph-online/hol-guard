//! Coverage for a list that changes directory before the steps an Allow owns.
//!
//! The proofs these tests read canonicalize a real directory, so they run on
//! Unix only: a canonical Windows path carries a `\\?\` prefix that no `cd`
//! operand ever spells, and the shape under test is not platform-specific.

use super::*;

fn action_in(
    controls: &CompiledNativeCommandControls,
    command: &str,
    home: &std::path::Path,
    cwd: &std::path::Path,
) -> String {
    crate::pretool::evaluate_pre_tool_envelope_with_context(
        "omp",
        "PreToolUse",
        &serde_json::json!({
            "tool_name": "bash",
            "tool_input": {"command": command},
            "cwd": cwd.to_str().expect("cwd text"),
        }),
        Some(controls),
        None,
        home.to_str(),
        cwd.to_str(),
    )
    .minimum_action
}

/// Every configurable permission of `extension_id`, as a user who turned the
/// whole extension on has them.
fn every_configurable_permission(extension_id: &str) -> Vec<String> {
    packaged_command_program()
        .unwrap()
        .extensions
        .iter()
        .find(|extension| extension.extension_id == extension_id)
        .expect("packaged extension")
        .permissions
        .iter()
        .filter(|permission| permission.configurable)
        .map(|permission| permission.permission_id.clone())
        .collect()
}

#[test]
fn an_allowed_extension_covers_a_list_that_changes_directory_before_a_sequence() {
    // `cd <dir> && gh pr merge 1; gh pr view 1` cannot prove what runs after
    // the `;` against the directory the `cd` names: a failed `cd` would leave
    // those steps running where the command started. That left the `cd`
    // itself proved by nothing, so a user who had turned on every GitHub
    // permission still got a review for the whole command.
    let root = tempfile::tempdir().expect("temp root");
    let home = std::fs::canonicalize(root.path()).expect("canonical home");
    let workspace = home.join("workspace");
    let target = home.join("projects").join("polish");
    std::fs::create_dir_all(&workspace).expect("workspace");
    std::fs::create_dir_all(&target).expect("target");
    let ids = every_configurable_permission("command.github");
    let enabled: Vec<&str> = ids.iter().map(String::as_str).collect();
    let controls = controls_with(&enabled);
    let merge = "gh pr merge 1 --repo example-org/example-repo --squash";
    let view = "gh pr view 1 --repo example-org/example-repo --json state,mergedAt";
    let directory = target.display();
    let inside = workspace.join("sub");
    std::fs::create_dir_all(&inside).expect("inside");
    let under_cwd = inside.display();
    let here = workspace.display();
    let shapes = [
        ("cd then pwd", format!("cd {directory} && pwd")),
        ("cd to cwd", format!("cd {here} && {merge}")),
        ("cd below cwd", format!("cd {under_cwd} && {merge}")),
        ("merge alone", merge.to_owned()),
        ("sequence, no cd", format!("{merge}; {view}")),
        ("cd then one step", format!("cd {directory} && {merge}")),
        (
            "cd then sequence",
            format!("cd {directory} && {merge}; {view}"),
        ),
        (
            "cd, read first",
            format!("cd {directory} && {view}; {merge}"),
        ),
        (
            "uncovered step",
            format!("cd {directory} && {merge}; curl https://example.test"),
        ),
        (
            "cd nowhere",
            format!("cd {directory}/gone && {merge}; {view}"),
        ),
    ];
    let actual: Vec<String> = shapes
        .iter()
        .map(|(name, command)| {
            let action = action_in(&controls, command, &home, &workspace);
            let allowed = if action == "allow" {
                "allow"
            } else {
                "not-allow"
            };
            format!("{name}: {allowed}")
        })
        .collect();
    assert_eq!(
        actual,
        vec![
            "cd then pwd: allow",
            "cd to cwd: allow",
            "cd below cwd: allow",
            "merge alone: allow",
            "sequence, no cd: allow",
            "cd then one step: allow",
            "cd then sequence: allow",
            "cd, read first: allow",
            // A step the Allow does not cover still keeps its review after a `cd`.
            "uncovered step: not-allow",
            // So does a list whose `cd` cannot be proved to reach its directory.
            "cd nowhere: not-allow",
        ]
    );
}
