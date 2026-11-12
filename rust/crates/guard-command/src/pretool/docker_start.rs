//! Starting containers that already exist.
//!
//! `docker start <container>...` and `docker container start` only run an
//! existing container again. Its image, mounts, privileges, environment,
//! devices and network were fixed when it was created, and creating one
//! (`run`, `create`, `compose up`) keeps its review, so starting it grants no
//! host access the container did not already have. Every operand must be a
//! plain container name or ID, and no option is admitted.
//!
//! Still reviewed:
//! - `start -a`/`--attach` and `-i`, which stream the application's output
//!   like `docker logs`, and checkpoint or detach-key options;
//! - `stop` and `restart`, which interrupt a running service; `stop` has its
//!   own `container-stop` permission in the container-runtime catalog;
//! - `kill`, `rm`, `pause`, `update`, `exec` and every other subcommand;
//! - global options and `DOCKER_*` environment prefixes, which the listing
//!   proof in `docker_reads` already rejects before this module runs.

const START_REASON: &str = "native_exact_safe_container_start";

/// The operands after `start` or `container start`, if `words` (the
/// arguments after `docker`) is that subcommand.
fn start_operands<'a>(words: &'a [&'a str]) -> Option<&'a [&'a str]> {
    match words {
        ["start", rest @ ..] | ["container", "start", rest @ ..] => Some(rest),
        _ => None,
    }
}

/// Whether `words` is the `start` subcommand at all, however its operands are
/// spelled. A caller that must keep container starts out of a proof asks this
/// rather than [`safe_start_arguments`], which answers only for the starts
/// this module admits.
pub(super) fn start_shaped(words: &[&str]) -> bool {
    start_operands(words).is_some()
}

/// Docker arguments that only start named existing containers.
pub(super) fn safe_start_arguments(words: &[&str]) -> bool {
    start_operands(words).is_some_and(|operands| {
        !operands.is_empty() && operands.iter().all(|operand| container_reference(operand))
    })
}

/// A container name or ID as Docker accepts it: `[A-Za-z0-9][A-Za-z0-9_.-]*`.
fn container_reference(word: &str) -> bool {
    word.len() <= 128
        && word
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// The allow reason for an exact-safe command that starts a container, so
/// the audit trail does not call it a read.
pub(crate) fn proven_reason_code(model: &crate::CanonicalCommandV1) -> Option<&'static str> {
    model
        .segments
        .iter()
        .any(|segment| {
            segment
                .executable
                .as_deref()
                .is_some_and(|executable| super::executable_basename(executable) == "docker")
                && start_operands(
                    &segment
                        .arguments
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                )
                .is_some()
        })
        .then_some(START_REASON)
}

#[cfg(test)]
#[path = "docker_start_tests.rs"]
mod tests;
