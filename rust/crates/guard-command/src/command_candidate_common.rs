//! Rust port of `runtime/command_candidate_common.py`.
//!
//! `command_has_exact_plain_shell_shape` — the shared structural guard for
//! proof-eligible candidates. On the native path `redirects` and
//! `embedded_commands` are absent from `CanonicalCommandV1` and are always
//! empty (`canonical_command.rs::from_v1` documents the invariant), so the
//! Python `not command.redirects` / `not command.embedded_commands` clauses
//! reduce to tautologies and are omitted. The command-level `wrapper_chain`
//! check is retained (the field exists on the wire).

use crate::canonical_command::CanonicalCommand;

/// `command_has_exact_plain_shell_shape` (command_candidate_common.py:8).
pub fn command_has_exact_plain_shell_shape(command: &CanonicalCommand) -> bool {
    if command.segments.is_empty() {
        return false;
    }
    command.confidence == "exact"
        && command.uncertainty_reason.is_none()
        && command.dialect == "posix"
        && command.transport == "shell_string"
        && command.wrapper_chain.is_empty()
        // `not command.redirects` / `not command.embedded_commands` — always
        // empty on the native path (see `canonical_command.rs::from_v1`).
        && command.segments.iter().all(|segment| {
            segment.execution_context.starts_with("top:")
                && segment.wrapper_chain.is_empty()
                && segment.environment_names.is_empty()
                && !segment.path_overridden
        })
}
