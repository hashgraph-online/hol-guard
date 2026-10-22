#![cfg(unix)]
//! A dependency link beside read-only peers stays quiet: the `ln` keeps its
//! standalone proof and nothing in the chain can write through the new link.

use crate::pretool_git_session_ops::{git, session, Session};
use std::path::Path;

fn action(session: &Session, command: &str, cwd: &Path) -> String {
    session.evaluate_at(command, cwd).minimum_action
}

#[test]
fn dependency_link_with_listing_peers_is_quiet_from_any_session_directory() {
    let session = session("link-chain-allow");
    let primary = session.primary.display();
    let worktree = session.worktree.display();
    let link = format!("ln -s {primary}/node_modules {worktree}/node_modules");
    for cwd in [&session.org, &session.primary, &session.worktree] {
        for command in [
            format!("{link} && ls -la {worktree}/ | grep node_module"),
            format!("{link}; ls -la {worktree}/ | grep node_module"),
            format!("{link} && ls {worktree}"),
            format!("ls {worktree}/ && {link}"),
        ] {
            assert_eq!(action(&session, &command, cwd), "allow", "{command}");
        }
    }
}

#[test]
fn dependency_link_chains_keep_every_boundary_of_the_single_link() {
    let session = session("link-chain-deny");
    let home = session.home.display();
    let primary = session.primary.display();
    let worktree = session.worktree.display();
    let unrelated = session.home.join("unrelated");
    std::fs::create_dir_all(unrelated.join("node_modules")).unwrap();
    git(
        &session.home,
        &unrelated,
        &["init", "--quiet", "-b", "main"],
    );
    let link = format!("ln -s {primary}/node_modules {worktree}/node_modules");
    let unrelated = unrelated.display();
    for command in [
        // Steps that write, replace, re-anchor or run something.
        format!("{link} && id"),
        format!("{link} && cp {primary}/tracked.txt {worktree}/node_modules/x"),
        format!("{link} && rm -rf {worktree}/node_modules"),
        format!("{link} && echo x > {worktree}/node_modules/pkg/index.js"),
        format!("{link} && cd {worktree} && ls"),
        format!("{link} && ln -s {primary}/node_modules {worktree}/node_modules/pkg/inner"),
        // A Git read that walks the working tree could resolve the fresh
        // link, and a listing can start a pager; only the current-branch
        // read joins the chain.
        format!("{link} && git -C {worktree} status"),
        format!("{link} && git -C {worktree} status --short"),
        format!("{link} && git -C {worktree} diff"),
        format!("{link} && git -C {worktree} grep -n x"),
        format!("{link} && git -C {worktree} ls-files"),
        format!("{link} && git -C {worktree} branch weekly-report"),
        format!("{link} && git -C {worktree} branch -a"),
        format!("{link} && git -C {worktree} tag --list"),
        // A search operand could read through the fresh link.
        format!("ln -s {primary}/node_modules {worktree}/cfg && grep -rn . {worktree}/cfg/"),
        format!("ln -s {primary}/node_modules {worktree}/cfg && grep -n x {worktree}/cfg/pkg/a.js"),
        format!("{link} && grep -Rn x {worktree}/"),
        format!("{link} && rg -n x {worktree}/node_modules"),
        // The link itself still has to be proven.
        format!("ln -s {home}/.ssh {worktree}/ssh-link && ls -la {worktree}/"),
        format!("ln -s {primary}/node_modules {worktree}/tracked.txt && ls -la {worktree}/"),
        format!("ln -sf {primary}/node_modules {worktree}/node_modules && ls {worktree}"),
        format!("ln -s {primary}/node_modules {unrelated}/node_modules && ls {unrelated}"),
        format!("ln -s {unrelated}/node_modules {worktree}/node_modules && ls {worktree}"),
    ] {
        for cwd in [&session.org, &session.primary] {
            assert_ne!(action(&session, &command, cwd), "allow", "{command}");
        }
    }
}

#[test]
fn a_directory_created_earlier_in_the_chain_is_not_a_proven_missing_root() {
    let session = session("mkdir-grep-deny");
    let worktree = session.worktree.display();
    for command in [
        format!("mkdir -p {worktree}/cfg && grep -rn x {worktree}/cfg"),
        format!("mkdir {worktree}/cfg && grep -n x {worktree}/cfg/a.json"),
    ] {
        for cwd in [&session.org, &session.worktree] {
            assert_ne!(action(&session, &command, cwd), "allow", "{command}");
        }
    }
}

#[test]
fn the_current_branch_read_beside_the_link_is_quiet() {
    let session = session("link-chain-branch");
    let primary = session.primary.display();
    let worktree = session.worktree.display();
    let link = format!("ln -s {primary}/node_modules {worktree}/node_modules");
    for cwd in [&session.org, &session.primary, &session.worktree] {
        for command in [
            format!("{link} && git -C {worktree} branch --show-current"),
            format!("git -C {worktree} branch --show-current && {link}"),
        ] {
            assert_eq!(action(&session, &command, cwd), "allow", "{command}");
        }
    }
}

/// The reported shape: a dependency directory shared with the relative
/// spelling an agent writes, then the branch the sibling checkout is on. The
/// link writes no Git configuration, so the Git read keeps its own proof
/// instead of falling to the execution-context floor.
#[test]
fn a_relative_dependency_link_leaves_a_branch_read_quiet() {
    let session = session("link-chain-relative");
    let worktree = session.worktree.display();
    let link = format!("ln -s ../org/app-portal/node_modules {worktree}/node_modules");
    let command = format!("{link} && git -C {worktree} branch --show-current");
    for cwd in [&session.org, &session.primary, &session.worktree] {
        assert_eq!(action(&session, &command, cwd), "allow", "{command}");
    }
}
