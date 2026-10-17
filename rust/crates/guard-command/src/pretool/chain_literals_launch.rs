//! Whether a sandbox verdict for a projected command launches as judged:
//! the launcher re-derives the shape from the raw text, so a projection's
//! sandbox verdict holds only when that raw text runs the same shape.

use crate::pretool::PathContext;
use guard_contracts::PreToolResultV1;

pub(super) fn reviewed(mut projected: PreToolResultV1) -> PreToolResultV1 {
    projected.minimum_action = "review".into();
    projected.policy_action = "review".into();
    projected.decision = "deny".into();
    projected.explicitly_benign = false;
    projected.reason_code = "native_command_review_required".into();
    projected.reason = "HOL Guard requires review because protected execution cannot run this command as it was judged.".into();
    projected
}

pub(super) fn launches_as_judged(
    projected: &PreToolResultV1,
    command: &str,
    context: PathContext<'_>,
) -> bool {
    projected.reason_code == crate::pretool::workspace_contained::REASON
        && crate::pretool::workspace_contained::admitted_workspace(context)
            .is_some_and(|workspace| launcher_shape(command, &workspace))
}

#[cfg(unix)]
fn launcher_shape(command: &str, workspace: &std::path::Path) -> bool {
    crate::restricted_pytest::workspace_exact_shape(command, workspace).is_some()
}

#[cfg(not(unix))]
fn launcher_shape(_command: &str, _workspace: &std::path::Path) -> bool {
    false
}
