//! A one-time approval of `git push [-u] origin <branch>` and what it binds.
//!
//! git runs code from files an agent can edit, so this never decides on its
//! own what a push may run. It names the push and the agent's environment,
//! and the native push checks (`git_execution_safety_checks`) prove the rest
//! with the trusted Git itself; their answer is the state the approval binds.

use std::collections::BTreeMap;
use std::path::Path;

use guard_contracts::{
    write_canonical_json, GitExecutionSafetyCheckV1, GitExecutionSafetyRequestV1,
    GuardExecutionEnvironmentV1, GIT_EXECUTION_SAFETY_REQUEST_SCHEMA,
};
use serde_json::{json, Value};

use super::fs_path;
use super::reasons::{
    Proof, COMPOUND_COMMAND, GIT_HELPER_CONFIG, MUTABLE_LAUNCHER, UNPROVEN_LAUNCH,
};
use super::reuse_shape;
use crate::mcp_proxy_shlex::split_with;

const SHELL_PUNCTUATION: &str = ";&|<>";
const EXPANSIONS: [&str; 6] = ["`", "$(", "${", "\n", "\r", "#"];
const UPSTREAM_FLAGS: [&str; 2] = ["-u", "--set-upstream"];
/// Session variables an ssh agent sets; any other `SSH_*` name (a security
/// key provider, an askpass program) can change what ssh runs or loads.
const SSH_SESSION_ENVIRONMENT: [&str; 5] = [
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "SSH_CONNECTION",
    "SSH_CLIENT",
    "SSH_TTY",
];
const MAX_BRANCH: usize = 200;

/// The digest a one-time approval of `command` is bound to, or why it cannot be.
pub(super) fn push_state(
    command: &str,
    cwd: &str,
    execution_environment: Option<&Value>,
) -> Proof<String> {
    if cfg!(windows) || EXPANSIONS.iter().any(|marker| command.contains(marker)) {
        return Err(MUTABLE_LAUNCHER);
    }
    let words = split_with(command, SHELL_PUNCTUATION, "#").ok_or(MUTABLE_LAUNCHER)?;
    if !reuse_shape::is_simple(&words) {
        return Err(COMPOUND_COMMAND);
    }
    let branch = pushed_branch(&words)?;
    let environment: GuardExecutionEnvironmentV1 =
        serde_json::from_value(execution_environment.ok_or(UNPROVEN_LAUNCH)?.clone())
            .map_err(|_| UNPROVEN_LAUNCH)?;
    let home = environment.home.clone().ok_or(UNPROVEN_LAUNCH)?;
    let extra_ssh = environment.environment_names.iter().any(|name| {
        let key = name.to_ascii_uppercase();
        key.starts_with("SSH_") && !SSH_SESSION_ENVIRONMENT.contains(&key.as_str())
    });
    if extra_ssh {
        return Err(GIT_HELPER_CONFIG);
    }
    // The same Git and environment checks the native push proof makes.
    let git = guard_command::pretool::push_environment_git(
        &environment,
        Path::new(&home),
        Path::new(cwd),
    )
    .ok_or(GIT_HELPER_CONFIG)?;
    let repository = fs_path::resolve_strict(cwd).ok_or(UNPROVEN_LAUNCH)?;
    let mut probe_environment = BTreeMap::from([
        ("PATH".to_owned(), environment.path.clone()),
        ("HOME".to_owned(), home.clone()),
    ]);
    if let Some(xdg) = &environment.xdg_config_home {
        probe_environment.insert("XDG_CONFIG_HOME".to_owned(), xdg.clone());
    }
    let request = GitExecutionSafetyRequestV1 {
        schema: GIT_EXECUTION_SAFETY_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        check: GitExecutionSafetyCheckV1::PushOrigin,
        cwd: repository,
        home,
        account_home: crate::edge_git_push::account_home(),
        groups: crate::edge_git_push::groups().ok_or(UNPROVEN_LAUNCH)?,
        environment: probe_environment,
        git_binary: None,
        git_path: None,
        arguments: Vec::new(),
        branch: Some(branch.to_owned()),
        reference: None,
    };
    let state =
        crate::git_execution_safety_checks::push_once_state(&request).ok_or(MUTABLE_LAUNCHER)?;
    // The shell's resolved Git must be the one the probes ran.
    if state["git"]["path"].as_str() != git.to_str() {
        return Err(UNPROVEN_LAUNCH);
    }
    let bound = json!({
        "argv": words,
        "environment_digest": environment.environment_digest,
        "state": state,
    });
    let mut encoded = Vec::new();
    write_canonical_json(&bound, &mut encoded).map_err(|_| UNPROVEN_LAUNCH)?;
    Ok(fs_path::sha256_hex(&encoded))
}

/// The branch of `git push [-u] origin <branch>`: the one push shape the
/// native proof covers. Force, delete, glob, tag, mirror and option forms,
/// another remote, and `git -c`/`-C` are other actions than the reviewed one.
fn pushed_branch(words: &[String]) -> Proof<&str> {
    let [git, push, rest @ ..] = words else {
        return Err(MUTABLE_LAUNCHER);
    };
    if git != "git" || push != "push" {
        return Err(MUTABLE_LAUNCHER);
    }
    let rest = match rest.split_first() {
        Some((flag, tail)) if UPSTREAM_FLAGS.contains(&flag.as_str()) => tail,
        _ => rest,
    };
    let [remote, branch] = rest else {
        return Err(MUTABLE_LAUNCHER);
    };
    if remote != "origin" || !is_branch_name(branch) {
        return Err(MUTABLE_LAUNCHER);
    }
    Ok(branch)
}

fn is_branch_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_BRANCH
        && name != "HEAD"
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._/-".contains(character))
        && name.split('/').all(|part| {
            !part.is_empty()
                && !part.starts_with(['.', '-'])
                && !part.ends_with('.')
                && !part.ends_with(".lock")
        })
        && !name.contains("..")
}

#[cfg(all(test, unix))]
#[path = "git_push_tests.rs"]
mod tests;
