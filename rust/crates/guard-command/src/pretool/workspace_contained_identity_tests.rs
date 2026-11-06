//! A double-quoted variable that only sets a `-c` commit identity names no
//! path, so it does not keep a Git command out of the workspace sandbox. Every
//! other expansion still does.
use super::identity_expansions_only;
use crate::pretool::workspace_contained_tests::{host, reason, workspace, CONTAINED};

/// Whether the command's first segment counts as identity-only. A command the
/// parser cannot model has no segment, and is not counted.
fn recognized(command: &str, name: &str) -> bool {
    let Ok(model) = crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }) else {
        return false;
    };
    model
        .segments
        .first()
        .is_some_and(|segment| identity_expansions_only(segment, name))
}

#[test]
fn quoted_identity_expansions_are_recognized() {
    for command in [
        "git -c user.name=\"${USER:-dev}\" -c user.email=\"dev@localhost\" commit -m x",
        "git -c user.name=\"$USER\" commit -m x",
        "git -c user.email=\"${EMAIL}\" -c user.name=\"${USER-dev}\" commit -m x",
        "git -c User.Name=\"${LOGNAME:-dev.user}\" commit -m x",
        "git -c \"user.name=$USER\" -c author.email=\"${EMAIL:-a@b.c}\" commit -m x",
    ] {
        assert!(recognized(command, "git"), "{command}");
    }
}

#[test]
fn other_expansions_are_not_identity_expansions() {
    for command in [
        // Keys that run a program, pick hooks or reach a path.
        "git -c core.fsmonitor=\"$HOME/mon\" commit -m x",
        "git -c core.hooksPath=\"${HOOKS:-hooks}\" commit -m x",
        "git -c core.sshCommand=\"$CMD\" commit -m x",
        "git -c alias.ci=\"!$CMD\" ci",
        "git -c credential.helper=\"$HELPER\" commit -m x",
        "git -c include.path=\"$HOME/.gitconfig\" commit -m x",
        // Unquoted: the value can split into more arguments.
        "git -c user.name=$USER commit -m x",
        // Command substitution, nested or assigning expansions.
        "git -c user.name=\"$(id)\" commit -m x",
        "git -c user.name=\"`id`\" commit -m x",
        "git -c user.name=\"${USER:-$(id)}\" commit -m x",
        "git -c user.name=\"${USER:=dev}\" commit -m x",
        "git -c user.name=\"${USER:-~/x}\" commit -m x",
        "git -c user.name=\"$1\" commit -m x",
        "git -c user.name=\"${#USER}\" commit -m x",
        // A `$` outside the identity value.
        "git -c user.name=\"$USER\" commit -m \"$MSG\"",
        "git -c user.name=\"$USER\" add \"$HOME/.ssh/id_rsa\"",
        "git -C \"$HOME\" -c user.name=dev commit -m x",
        // A `$` that does not expand, traded for one in a redirect.
        "git -c user.name='$x' commit -m y > \"$HOME/.bashrc\"",
        "git -c user.name=\"\\$x\" commit -m y > \"$HOME/.bashrc\"",
        "git -c user.name=\"$USER\" commit -m y > \"$HOME/.bashrc\"",
        // After the subcommand `-c` is no identity setting.
        "git commit -c \"$REF\"",
        "git commit -c user.name=\"$USER\"",
    ] {
        assert!(!recognized(command, "git"), "{command}");
    }
    let command = "sh -c user.name=\"$USER\"";
    assert!(!recognized(command, "sh"), "{command}");
}

#[test]
fn a_fresh_repository_committed_with_an_expanded_identity_runs_contained() {
    let fresh = workspace("identity-init", false);
    let command = concat!(
        "git init && git add tempconv.py test_tempconv.py && ",
        "git -c user.name=\"${USER:-dev}\" -c user.email=\"dev@localhost\" ",
        "commit -m \"Add Celsius/Fahrenheit converter CLI with tests\" && git log --oneline",
    );
    assert_eq!(reason("omp", command, &fresh, true) == CONTAINED, host());
    let ws = workspace("identity", true);
    let command = "git add -A && git -c user.name=\"$USER\" commit -m x";
    assert_eq!(reason("omp", command, &ws, true) == CONTAINED, host());
    for command in [
        "git add -A && git -c core.fsmonitor=\"$HOME/mon\" commit -m x",
        "git add -A && git -c user.name=$USER commit -m x",
        "git add -A && git -c user.name=\"$(id)\" commit -m x",
        "git add -A && git -c user.name=\"$USER\" commit -m \"$MSG\"",
        "git add -A && git -c user.name='$x' commit -m y > \"$HOME/.bashrc\"",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
}
