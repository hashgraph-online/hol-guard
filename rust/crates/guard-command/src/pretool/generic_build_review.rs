//! Reason text for package-tool commands that build or test the project.
//!
//! `cargo test` names a package tool, so it takes the package review: it can
//! download crates and runs their build scripts. The decision stays the same;
//! only the reason changes, since install advice (`--ignore-scripts`, frozen
//! lockfiles) does not apply to a build or a test run.

use crate::{CanonicalCommandV1, CommandSegmentV1};

/// The package-review reason for a command whose every package step builds,
/// checks, tests or runs the project. `blocked_request_mode` keys on its
/// opening words to leave out the install hint.
pub(crate) const BUILD_REVIEW_REASON: &str = "HOL Guard requires review before this build or test command can execute, because it can download dependencies and run their build scripts.";

/// Cargo subcommands (and their aliases) that compile the workspace, which
/// can fetch dependencies and runs their `build.rs` scripts. `cargo fix` is
/// left out: it also rewrites source files, which this reason does not name.
const CARGO_BUILD_SUBCOMMANDS: &[&str] = &[
    "b", "bench", "build", "c", "check", "clippy", "d", "doc", "miri", "nextest", "r", "run",
    "rustc", "rustdoc", "t", "test",
];

/// Global cargo options that take the next argument as their value.
const CARGO_VALUE_OPTIONS: &[&str] = &["--color", "--config", "-C", "-Z"];

/// Whether every package-tool step in `model` is a cargo build or test.
pub(super) fn build_or_test_command(
    model: &CanonicalCommandV1,
    is_package_tool: fn(&str) -> bool,
) -> bool {
    let mut package_steps = model
        .segments
        .iter()
        .filter(|segment| segment.executable.as_deref().is_some_and(is_package_tool))
        .peekable();
    package_steps.peek().is_some() && package_steps.all(cargo_build_step)
}

fn cargo_build_step(segment: &CommandSegmentV1) -> bool {
    let Some(executable) = segment.executable.as_deref() else {
        return false;
    };
    let name = executable.rsplit(['/', '\\']).next().unwrap_or(executable);
    let name = name.strip_suffix(".exe").unwrap_or(name);
    if name != "cargo" {
        return false;
    }
    let mut arguments = segment.arguments.iter();
    while let Some(argument) = arguments.next() {
        if CARGO_VALUE_OPTIONS.contains(&argument.as_str()) {
            arguments.next();
        } else if !argument.starts_with(['-', '+']) {
            return CARGO_BUILD_SUBCOMMANDS.contains(&argument.as_str());
        }
    }
    false
}

#[cfg(test)]
#[path = "generic_build_review_tests.rs"]
mod tests;
