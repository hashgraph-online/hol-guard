//! Commands with leading settings (`PORT=4173 vitest run`).
//!
//! A setting that is not inert keeps a command from settling below review on
//! the host, because Guard judged the command without it, and the read-only
//! profiles run only the bare program. The workspace sandbox runs the exact
//! text instead: its launcher re-derives the shape from those bytes, settings
//! included, and the sandbox bounds whatever a setting changes (no network,
//! no home, credentials denied). Settings that can swap the program, its
//! loader or its credentials never reach this path.
use super::{host_eligible, mark_contained, workspace_admissible, PathContext};
use guard_contracts::{GuardExecutionEnvironmentV1, PreToolResultV1};
use std::path::Path;

/// Move `projected`, the contained verdict for `command` without its
/// settings, to the workspace sandbox when its launcher admits `command` as
/// written. Returns whether it did.
pub(in crate::pretool) fn carry_settings(
    projected: &mut PreToolResultV1,
    command: &str,
    context: PathContext<'_>,
    execution_environment: Option<&GuardExecutionEnvironmentV1>,
    harness: &str,
    event: &str,
) -> bool {
    let contained = projected.minimum_action == "sandbox-required"
        && projected.reason_code.starts_with("native_")
        && projected.reason_code.ends_with("_containment_required");
    if !contained || projected.action.sensitive_target || !host_eligible(harness, event) {
        return false;
    }
    let home = context.home_dir.map(Path::new);
    let Some(workspace) = context
        .cwd
        .and_then(|cwd| workspace_admissible(Path::new(cwd), home))
    else {
        return false;
    };
    let admitted =
        super::super::workspace_git_environment::session_git_variables(execution_environment)
            .and_then(|variables| {
                super::super::workspace_git_config::workspace_write_denials(
                    &workspace, home, &variables,
                )
            })
            .is_some()
            && exact_shape(command, &workspace);
    if admitted {
        mark_contained(projected);
    }
    admitted
}

#[cfg(unix)]
fn exact_shape(command: &str, workspace: &Path) -> bool {
    crate::restricted_pytest::workspace_exact_shape(command, workspace).is_some()
}

#[cfg(not(unix))]
fn exact_shape(_command: &str, _workspace: &Path) -> bool {
    false
}
