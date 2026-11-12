//! `codex-sandbox-check`: whether this process itself runs inside a macOS
//! sandbox that confines it as tightly as a contained profile requires.
//!
//! Guard leaves a contained call to Codex's own sandbox when its sink cannot
//! start inside that sandbox (`codex_hook_bridge_contain_sandbox`). The hook
//! only knows the sandbox Codex configured for the turn, and Codex can still
//! run one call outside it: an escalated call the user approves, a command
//! an exec-policy rule trusts, or an unsandboxed retry. None of that reaches
//! the hook, so the rewritten call starts with this check, which asks the
//! kernel about the process the shell runs in, and the shell runs the
//! original command only when the check passes.
//!
//! The check passes when the sandbox denies outbound network and denies
//! writes to the user's home, `/tmp`, the user's temporary directory and the
//! directory around the workspace, and, for any profile but the workspace
//! one, to the workspace too. `SHARED_TMP_CHECK`, which a project's pytest
//! asks for in Codex's default sandbox, also lets the sandbox write `/tmp`
//! and the user's temporary directory. Anything it cannot confirm fails it. Each
//! answer covers the named directory only, not a writable path nested below
//! it, so the hook also requires a turn with no extra writable roots and
//! never sends an escalated call here.

pub(crate) const CHECK_COMMAND: &str = "codex-sandbox-check";
/// The one contained profile that lets a call write in the workspace.
pub(crate) const WORKSPACE_PROFILE: &str = "workspace-contained-v1";
/// The read-only profile for a project's own pytest run.
pub(crate) const PYTEST_PROFILE: &str = "pytest-readonly-v2";
/// What a pytest run in Codex's default workspace-write sandbox must hold:
/// no network and no writes to the home directory or the workspace's
/// parent. The workspace, `/tmp` and `$TMPDIR` may be writable.
pub(crate) const SHARED_TMP_CHECK: &str = "codex-workspace-write-shared-tmp";
/// The shell's exit status for a command that was not run.
pub(crate) const REFUSED: i32 = 126;

const MESSAGE: &str = "Guard did not run this command: Codex started it outside a sandbox that keeps it off the network and inside the workspace. Run it again without asking Codex for more access.";

/// `codex-sandbox-check --profile <profile> --workspace <dir>`.
pub(crate) fn run(args: &[String]) -> i32 {
    let confirmed = match args {
        [profile_flag, profile, workspace_flag, workspace]
            if profile_flag == "--profile" && workspace_flag == "--workspace" =>
        {
            confined(profile, workspace)
        }
        _ => false,
    };
    if confirmed {
        return 0;
    }
    eprintln!("{MESSAGE}");
    REFUSED
}

/// Whether the sandbox around this process holds `profile` for `workspace`.
fn confined(profile: &str, workspace: &str) -> bool {
    let Ok(workspace) = std::fs::canonicalize(workspace) else {
        return false;
    };
    let Some(outside) = outside_paths(&workspace) else {
        return false;
    };
    let mut denied = outside;
    if profile == WORKSPACE_PROFILE {
        // A workspace that is the home directory, or holds a temporary
        // directory, is the one place the workspace profile writes.
        denied.retain(|directory| !directory.starts_with(&workspace));
    } else if profile == SHARED_TMP_CHECK {
        let shared = temp_paths();
        denied
            .retain(|directory| !directory.starts_with(&workspace) && !shared.contains(directory));
    } else {
        denied.push(workspace);
    }
    // A shared-tmp workspace inside a temporary directory still has the
    // home directory to deny; a check with nothing left to ask fails.
    !denied.is_empty()
        && seatbelt::denies_network()
        && denied
            .iter()
            .all(|directory| seatbelt::denies_write(directory))
}

/// The directories a contained call never writes: the home directory from
/// both the account database and `$HOME`, `/tmp`, the per-user temporary
/// directory from both the system and `$TMPDIR`, and the workspace's parent.
fn outside_paths(workspace: &std::path::Path) -> Option<Vec<std::path::PathBuf>> {
    let mut paths = vec![workspace.parent()?.to_path_buf()];
    let named = [
        seatbelt::account_home(),
        std::env::var_os("HOME").map(Into::into),
        Some("/tmp".into()),
        seatbelt::user_temp_dir(),
        std::env::var_os("TMPDIR").map(Into::into),
    ];
    for path in named.into_iter().flatten() {
        // A named directory that does not exist is skipped: the kernel
        // answers only for existing paths. The workspace's parent and `/tmp`
        // always exist.
        if let Ok(resolved) = std::fs::canonicalize(&path) {
            paths.push(resolved);
        }
    }
    (paths.len() >= 3).then_some(paths)
}

/// `/tmp` and the per-user temporary directory from both the system and
/// `$TMPDIR`, resolved: the directories Codex's default sandbox shares.
fn temp_paths() -> Vec<std::path::PathBuf> {
    let named = [
        Some("/tmp".into()),
        seatbelt::user_temp_dir(),
        std::env::var_os("TMPDIR").map(Into::into),
    ];
    named
        .into_iter()
        .flatten()
        .filter_map(|path: std::path::PathBuf| std::fs::canonicalize(path).ok())
        .collect()
}

#[cfg(target_os = "macos")]
mod seatbelt {
    pub(super) use guard_seatbelt::{account_home, denies_network, denies_write, user_temp_dir};
}

/// Only macOS is known to refuse Guard's sink inside Codex's sandbox, so
/// the hook never asks for this check elsewhere, and it never passes there.
#[cfg(not(target_os = "macos"))]
mod seatbelt {
    use std::path::{Path, PathBuf};

    pub(super) fn denies_network() -> bool {
        false
    }

    pub(super) fn denies_write(_path: &Path) -> bool {
        false
    }

    pub(super) fn account_home() -> Option<PathBuf> {
        None
    }

    pub(super) fn user_temp_dir() -> Option<PathBuf> {
        None
    }
}

#[cfg(test)]
#[path = "codex_sandbox_check_tests.rs"]
mod tests;
