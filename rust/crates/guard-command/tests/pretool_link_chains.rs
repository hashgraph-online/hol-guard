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
        format!("{link} && git -C {worktree} status"),
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
