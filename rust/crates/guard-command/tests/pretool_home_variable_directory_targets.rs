//! A directory word spelled `$HOME` or `${HOME}` names what `~` names.
//!
//! Agents write home three ways and mean one directory. Guard already proves
//! the `~` spelling against the declared home, so the two variable spellings
//! are read as that spelling and reach the same answer -- a `git -C` route, a
//! `cd` prefix, and a worktree destination alike. The spellings that are not
//! home, and the quoting that keeps the word literal, keep their review.
use crate::pretool_home_layout_reads::{decide, decide_with_shell_home, layout, repository};

/// Every spelling of one directory word reaches one decision.
fn assert_same_decision(cwd: &std::path::Path, home: &std::path::Path, tilde: &str) {
    let expected = decide(cwd, home, tilde);
    for spelling in ["$HOME", "${HOME}"] {
        let command = tilde.replace('~', spelling);
        let result = decide(cwd, home, &command);
        assert_eq!(
            result.decision, expected.decision,
            "{command}: {} {} (`{tilde}` answered {} {})",
            result.decision, result.reason_code, expected.decision, expected.reason_code
        );
    }
}

#[test]
fn a_git_route_to_a_sibling_below_home_reads_the_same_in_every_spelling() {
    let layout = layout("home-variable-git-route");
    let cwd = layout.org.join("app-portal");
    let tilde = "git -C ~/Code/org/service-api log --oneline -3";
    assert_eq!(
        decide(&cwd, &layout.home, tilde).decision,
        "allow",
        "the tilde spelling is the decision the variable spellings match"
    );
    assert_same_decision(&cwd, &layout.home, tilde);
    assert_same_decision(
        &cwd,
        &layout.home,
        "git -C ~/Code/org/service-api status --short",
    );
}

#[test]
fn a_cd_prefix_spelled_with_the_variable_reads_the_same_as_the_tilde() {
    let layout = layout("home-variable-cd");
    let cwd = layout.org.join("app-portal");
    for tilde in [
        "cd ~/Code/org/service-api && git status --short",
        "cd ~/Code/org/service-api && git log --oneline -3",
    ] {
        assert_same_decision(&cwd, &layout.home, tilde);
    }
}

/// A worktree destination below home is the shape the report named: the
/// checkout is created where `~` would create it, so the spelling of the
/// destination does not change the answer.
#[test]
fn a_worktree_destination_spelled_with_the_variable_reads_the_same_as_the_tilde() {
    let layout = layout("home-variable-worktree-add");
    let cwd = layout.org.join("app-portal");
    for tilde in [
        "git worktree add ~/Code/org/app-portal-review feat/review",
        "git worktree add -b feat/review ~/Code/org/app-portal-branch",
    ] {
        assert_same_decision(&cwd, &layout.home, tilde);
    }
}

/// A `$` the shell never expands is a relative directory actually named
/// `$HOME`, which is not home at all, so the word keeps its review however
/// the tilde spelling is answered.
#[test]
fn a_quoted_or_escaped_dollar_is_not_read_as_home() {
    let layout = layout("home-variable-quoted");
    let cwd = layout.org.join("app-portal");
    for command in [
        "git -C '$HOME/Code/org/service-api' log --oneline -3",
        "git -C \\$HOME/Code/org/service-api log --oneline -3",
        "cd '$HOME/Code/org/service-api' && git status --short",
        "git worktree add '$HOME/Code/org/app-portal-review' feat/review",
    ] {
        let result = decide(&cwd, &layout.home, command);
        assert_ne!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// `$HOMEBREW_PREFIX` names another variable, and a word carrying a further
/// expansion is not a path the directory screens read, so neither becomes a
/// home word.
#[test]
fn another_variable_or_a_further_expansion_is_not_a_home_word() {
    let layout = layout("home-variable-other");
    let cwd = layout.org.join("app-portal");
    for command in [
        "git -C $HOMEBREW_PREFIX/Code/org/service-api log --oneline -3",
        "git -C $HOME/$PROJECT log --oneline -3",
        "git -C ${HOME%/*}/Code/org/service-api log --oneline -3",
    ] {
        let result = decide(&cwd, &layout.home, command);
        assert_ne!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// A route the tilde spelling is refused stays refused in every spelling.
#[test]
fn a_refused_route_below_home_stays_refused_in_every_spelling() {
    let layout = layout("home-variable-refused");
    let cwd = layout.org.join("app-portal");
    repository(&layout.home.join(".config-repo"));
    for command in [
        "git -C ~/.config-repo log --oneline -1",
        "git -C $HOME/.config-repo log --oneline -1",
        "git -C ${HOME}/.config-repo log --oneline -1",
        "git -C ~ status --short",
        "git -C $HOME status --short",
        "git -C ${HOME} status --short",
    ] {
        let result = decide(&cwd, &layout.home, command);
        assert_ne!(
            result.decision, "allow",
            "{command}: {}",
            result.reason_code
        );
    }
}

/// The shell expands `$HOME` from its own `HOME`, exactly as it expands `~`.
/// Where that is some other directory the route proof measured a checkout the
/// command would not reach, so both spellings keep their review.
#[test]
fn a_shell_home_elsewhere_keeps_both_spellings_reviewed() {
    let layout = layout("home-variable-shell-home");
    let cwd = layout.org.join("app-portal");
    for command in [
        "git -C ~/Code/org/service-api log --oneline -3",
        "git -C $HOME/Code/org/service-api log --oneline -3",
        "git -C ${HOME}/Code/org/service-api log --oneline -3",
    ] {
        for (shell_home_matches, allowed) in [(false, false), (true, true)] {
            let result = decide_with_shell_home(&cwd, &layout.home, command, shell_home_matches);
            assert_eq!(
                result.decision == "allow",
                allowed,
                "{command} with shell_home_matches={shell_home_matches}: {} {}",
                result.decision,
                result.reason_code
            );
        }
    }
}
