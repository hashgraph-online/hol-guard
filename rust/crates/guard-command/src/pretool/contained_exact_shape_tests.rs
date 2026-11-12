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
        // The loop and branch readings go through the decision's own rewrite
        // rather than the group blanking, so they are pinned here too.
        (
            "for d in dashboard src; do (cd \"$d\" && rm -rf /); done",
            "cd dashboard && rm -rf / && cd src && rm -rf /",
        ),
        (
            "if [ -d dashboard ]; then (rm -rf /tmp); fi",
            "[ -d dashboard ] && rm -rf /tmp",
        ),
        ("{ rm -rf /; } && ls", "rm -rf / && ls"),
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

/// The grouped reading names every command the group runs, so a destructive
/// command in a loop body, a branch body or a group keeps whatever screen it
/// has when it is written out flat. The reading blanks brackets and nothing
/// else.
#[test]
fn a_grouped_reading_still_names_every_command_the_group_runs() {
    for (command, named) in [
        ("(cd dashboard && rm -rf /) && ls", "rm -rf /"),
        ("{ cd dashboard && rm -rf /; } && ls", "rm -rf /"),
        ("(cat ~/.ssh/id_rsa) && ls", "cat ~/.ssh/id_rsa"),
    ] {
        let reading = crate::parser_segments::blanked_top_level_group_list(command)
            .unwrap_or_else(|| panic!("{command}"));
        assert!(reading.contains(named), "{command} -> {reading}");
        assert!(
            !reading.contains('(') && !reading.contains(')'),
            "{reading}"
        );
    }
}

/// A loop body subshell and a branch body subshell reach the sandbox through
/// the decision's own rewrite, so the reading of the rewritten list is what
/// screens them; neither keeps a bracket the screen would have to read.
#[test]
fn a_loop_or_branch_body_group_is_read_without_its_brackets() {
    let ws = tree("group-bodies");
    for command in [
        "for d in dashboard src; do (cd \"$d\" && ls); done",
        "if [ -d dashboard ]; then (cd dashboard && npm run build); fi",
    ] {
        assert!(shaped(command, &ws), "{command}");
    }
}

/// `git commit -m "$(cat <<'EOF' ... EOF)"` is how an agent hands a
/// multi-line message to Git. The sandbox runs the raw text, where the real
/// `cat` prints exactly the heredoc, so the shape is the one the message's
/// own words earn. Without it the chain keeps the review its unevaluated
/// substitution earned and ordinary committing stops.
#[test]
fn a_heredoc_commit_message_plans_as_the_message_it_passes() {
    let ws = tree("heredoc-message");
    for command in [
        "git commit -m \"$(cat <<'EOF'\nfeat(x): subject\n\nbody line\nEOF\n)\"",
        "git add README.md && git commit -m \"$(cat <<'EOF'\nAdd notes\n\nExplain the window.\nEOF\n)\"",
    ] {
        assert!(shaped(command, &ws), "{command}");
    }
    // Only the heredoc form reads as its value here. A substitution the
    // projection judges as a command of its own has no shape without the
    // verdict for that command, which this derivation never asks for.
    for command in [
        "git commit -m \"$(whoami)\"",
        "git commit -m \"$(cat notes.txt)\"",
        "git commit -m \"$(cat <<EOF\nsubject\nEOF\n)\"",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}

/// A commit that takes its message from a quoted heredoc on standard input
/// plans as the commit it runs. When Git's write proof cannot allow it, for
/// example because a global hooks path runs a hook, the decision sends it to
/// the sandbox, which must then be able to run it.
#[test]
fn a_commit_reading_its_message_from_a_heredoc_plans() {
    let ws = tree("heredoc-stdin-message");
    for command in [
        "git commit -q --allow-empty -F - <<'MSG'\nchore(report): record the retry window\nMSG",
        "git add -A && git commit -q -F - <<'MSG'\nfeat(report): add the lane\n\nBody.\nMSG",
    ] {
        assert!(shaped(command, &ws), "{command}");
    }
    for command in [
        "git commit -F - <<MSG\n$(whoami)\nMSG",
        "git apply <<'MSG'\ndiff --git a/x b/x\nMSG",
        "sh <<'MSG'\nrm -rf build\nMSG",
    ] {
        assert!(!shaped(command, &ws), "{command}");
    }
}
