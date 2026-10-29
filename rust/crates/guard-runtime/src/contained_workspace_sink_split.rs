//! Receipts for chains that run part of the command outside the sandbox.
//!
//! The command crate splits two shapes around a step Guard runs directly: the
//! Git steps that follow contained checks, and a `git worktree add` whose
//! checkout the checks then run in. Both stay with `guard
//! execute-contained-test`, which re-proves the host step; the native sink
//! runs a command whole and must never take either.
use serde_json::Value;

/// The reason a chain carries whose trailing Git steps run after the
/// contained checks. It must match the command crate's text exactly; that
/// shape stays with `guard execute-contained-test`.
pub(crate) const PUBLISH_REASON: &str = concat!(
    "HOL Guard runs the checks in this command in a protected workspace sandbox ",
    "(no network, no home access, no PTY or Docker socket), then runs the Git ",
    "steps that follow directly, outside the sandbox, once it proves them again. ",
    "Every program the checks start, including children of an interpreter, runs ",
    "contained and can write only the workspace, $TMPDIR and a private ",
    "scratch $HOME.",
);

/// Whether a receipt's `reason` names a chain whose host step this sink
/// cannot run.
pub(crate) fn host_split(reason: Option<&Value>) -> bool {
    let reason = reason.and_then(Value::as_str);
    reason == Some(PUBLISH_REASON)
        || reason == Some(guard_command::pretool::CONTAINED_WORKTREE_ADD_REASON)
}
