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

/// A group is never read more widely than the same command list written out
/// flat, so grouping is not a way to carry work past a screen. The sandbox
/// bounds what a contained run may do; the shape only says the run is
/// plannable, and the grouped reading never says that where the flat list
/// does not.
#[test]
fn a_group_is_never_read_more_widely_than_the_flat_list() {
    let ws = tree("group-parity");
    for (grouped, flat) in [
        (
            "(cd dashboard && rm -rf /) && ls",
            "cd dashboard && rm -rf / && ls",
        ),
        ("(ls) && cat ~/.ssh/id_rsa", "ls && cat ~/.ssh/id_rsa"),
        (
            "{ cd dashboard && npm run build; } && echo done",
            "cd dashboard && npm run build && echo done",
        ),
    ] {
        assert!(!shaped(grouped, &ws) || shaped(flat, &ws), "{grouped}");
    }
}

/// Command substitution, process substitution and a backtick are read no more
/// loosely inside a group than outside one, so a group carrying one has no
/// reading and keeps its review.
#[test]
fn a_group_hiding_a_substitution_has_no_shape() {
    let ws = tree("group-unsafe");
    for command in [
        "(cat $(ls)) && ls",
        "(diff <(ls) <(ls src)) && ls",
        "(`ls`) && ls",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}

/// The grouped reading itself is never taken for a group carrying an unquoted
/// expansion, a substitution or a redirect: the blanking the reading rests on
/// refuses that text, so those commands keep whatever the flat reading already
/// said about them and nothing the group hides is waved through. A quoted word
/// is read as a word, inside a group as outside one.
#[test]
fn a_group_carrying_an_expansion_or_a_redirect_has_no_reading() {
    for command in [
        "(cat $(ls)) && ls",
        "(diff <(ls) <(ls src)) && ls",
        "(`ls`) && ls",
        "(ls > /etc/hol-guard-probe) && ls",
        "{ ls > /etc/hol-guard-probe; } && ls",
        "(ls) > /etc/hol-guard-probe && ls",
    ] {
        assert!(
            crate::parser_segments::blanked_top_level_group_list(command).is_none(),
            "{command}"
        );
    }
}
