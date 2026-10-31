//! Decisions for a call that only reads: a path with nothing behind it, and
//! the record of work the harness already started.

use super::extract::GenericSignals;
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1};

pub(super) const MISSING_PATH: &str = "native_missing_path";

/// Why a call that names a missing path did not run. It names the path when
/// the path prints safely, and says where a relative one is read from:
/// agents that ran commands in another folder retry the same relative path.
/// Otherwise it keeps `fallback`.
pub(super) fn missing_path_reason(fallback: &str, action: &str, path: Option<&str>) -> String {
    let Some(path) = path.filter(|path| {
        !path.is_empty()
            && path.chars().count() <= 512
            && !path.contains(|c: char| c.is_control() || c == '`')
    }) else {
        return fallback.to_owned();
    };
    format!(
        "HOL Guard did not run this {action} because `{path}` does not exist.{} Check the path, for example by listing its parent directory, and try again with the correct one.",
        if path.starts_with(['/', '~']) {
            ""
        } else {
            " A relative path is read from the session folder, not from the folder of an earlier command."
        }
    )
}

pub(super) const MISSING_WORKTREE_READ_REASON: &str = "The Rust authority proved this read names a path with nothing behind it inside a linked worktree this repository registers, so it reads nothing and the tool reports the missing path itself.";

pub(super) const MISSING_READ_FALLBACK: &str = "HOL Guard did not run this read because the path does not exist. Check the path, for example by listing its parent directory, and try again with the correct one.";

pub(super) const HARNESS_RESULT_READ_REASON: &str = "The Rust authority proved this call only collects the result of work the harness already started: it carries nothing but the identifiers of that work, and the call that started it was judged on its own.";

/// What a read-only call proved about itself.
pub(super) enum ReadDecision {
    /// A missing path inside a linked worktree this repository registers.
    MissingInRegisteredWorktree,
    /// A missing path anywhere else.
    MissingPath,
    /// The output of work the harness already started.
    HarnessResult,
}

/// Classify a call that reads. `None` leaves the decision to the evaluator.
pub(super) fn classify(
    harness: &str,
    event: &str,
    action_type: PreToolActionTypeV1,
    operation: PreToolOperationV1,
    signals: &GenericSignals,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> Option<ReadDecision> {
    if action_type == PreToolActionTypeV1::FileRead
        && event == "PreToolUse"
        && matches!(signals.tool_name.as_deref(), Some("Read" | "read"))
        && !signals.sensitive_target
        && signals.url_values.is_empty()
        && signals.command.is_none()
        && signals.path_values.len() == 1
        && super::super::safe_reads::missing_read_target(
            &signals.path_values[0],
            home_dir,
            cwd,
            harness == "omp",
        )
    {
        // The agent was sent to work in this linked worktree and named the
        // file before creating it. Nothing is there to read, so the read
        // discloses nothing and the tool reports the missing path itself.
        if super::super::git_routes::missing_path_in_registered_worktree(
            &signals.path_values[0],
            home_dir,
            cwd,
        ) {
            return Some(ReadDecision::MissingInRegisteredWorktree);
        }
        // Nothing exists to read, so stopping the call costs nothing. Saying
        // why lets the agent fix the path instead of waiting on an approval.
        return Some(ReadDecision::MissingPath);
    }
    // Collecting the result of work the harness already started carries the
    // identifiers of that work and nothing else, so it reaches nothing outside
    // the harness's own records. A name alone would not prove that: the name
    // is model-supplied, and a target can hide under a key the extractor does
    // not read, so the call's own arguments have to be retrieval arguments.
    // The call that started the work carried its own proof; asking again for
    // its output stops the agent without protecting anything.
    if action_type == PreToolActionTypeV1::Harness
        && operation == PreToolOperationV1::Read
        && signals.retrieval_arguments_only
        && !signals.sensitive_target
        && !signals.content_sensitive
        && !signals.request_body_or_method
        && !signals.business_action_present
        && !signals.env_reference
        && signals.command.is_none()
        && !signals.package_present
        && !signals.prompt_present
        && signals.path_values.is_empty()
        && signals.url_values.is_empty()
    {
        return Some(ReadDecision::HarnessResult);
    }
    None
}
