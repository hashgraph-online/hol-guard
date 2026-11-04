//! A grouped or control-flow command gets the shape of the command list the
//! decision that routed it to the sandbox read, so the two layers agree.

use crate::pretool::workspace_contained_tests::workspace;
use std::path::{Path, PathBuf};

fn tree(name: &str) -> PathBuf {
    let ws = workspace(name, true);
    for dir in ["dashboard", "src"] {
        std::fs::create_dir_all(ws.join(dir)).unwrap();
    }
    std::fs::write(ws.join("dashboard/package.json"), "{}").unwrap();
    ws
}

fn shaped(command: &str, ws: &Path) -> bool {
    crate::pretool::workspace_exact_shape(command, ws).is_some()
}

/// Ordinary work written as a list of groups, a loop body or a branch body
/// plans. Without a shape the decision still asks for the sandbox and the
/// sandbox then refuses the run, which neither allows the work nor contains
/// it.
#[test]
fn a_grouped_command_plans_as_the_list_it_runs() {
    let ws = tree("group-list");
    for command in [
        "{ cd dashboard && npm run build; } && echo done",
        "(cd dashboard && npm run build) && (cd src && ls)",
        "for d in dashboard src; do (cd \"$d\" && ls); done",
        "if [ -d dashboard ]; then (cd dashboard && npm run build); fi",
        // One group that is the whole command already planned.
        "{ npm run build; ls; }",
    ] {
        assert!(shaped(command, &ws), "{command}");
    }
}

/// The plan runs the submitted bytes, so a grouped reading is taken only
/// where it grants nothing outside the workspace.
#[test]
fn a_grouped_plan_runs_the_text_whole_and_reads_nothing_outside() {
    let ws = tree("group-whole");
    let shape = crate::pretool::workspace_exact_shape(
        "(cd dashboard && npm run build) && (cd src && ls)",
        &ws,
    )
    .unwrap();
    assert!(crate::pretool::workspace_runs_whole(&shape));
    assert!(shape.read_files.is_empty());
}

/// Each command inside a group is screened on its own merits, so a group is
/// never a way to carry work the sandbox would not take written out flat.
#[test]
fn a_group_carrying_unmodeled_work_still_has_no_shape() {
    let ws = tree("group-unsafe");
    for command in [
        "(cd dashboard && rm -rf /) && ls",
        "{ rm -rf /; } && ls",
        "for d in dashboard src; do (cd \"$d\" && rm -rf /); done",
        "if [ -d dashboard ]; then (rm -rf /tmp); fi",
        // Command substitution, process substitution and redirection are read
        // no more loosely inside a group than outside one.
        "(cat $(ls)) && ls",
        "{ ls > /etc/hol-guard-probe; } && ls",
        "(diff <(ls) <(ls src)) && ls",
        "(`ls`) && ls",
        // A read outside the workspace is a grant the submitted bytes may not
        // make, so the grouped reading is not a plan for it.
        "(ls) && cat ~/.ssh/id_rsa",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}
