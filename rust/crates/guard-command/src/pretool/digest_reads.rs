//! Digest printers: `shasum`, the `*sum` family and BSD `md5`.
//!
//! An agent checks a build artifact by printing its digest, so
//! `shasum -a 256 dist/app.whl` and `sha256sum target/release/app` are
//! ordinary read-only work. Each program opens its operands, prints one
//! fixed-width line per file and writes nothing, so the operands are screened
//! exactly as `wc` operands are, and a digest tells less about a file than the
//! bytes `od` already prints.
//!
//! The check forms stay reviewed: `-c` makes the operand a list of other files
//! to open, which is a different reach from the paths the proof screened.

use super::safe_reads::{command_read_target, verified_path_context};

/// The programs this screen knows. `cksum` and `b2sum` belong with the SHA
/// family: same operand grammar, same single line of output.
pub(in crate::pretool) fn digest_program(basename: &str) -> bool {
    matches!(
        basename,
        "shasum"
            | "md5"
            | "md5sum"
            | "sha1sum"
            | "sha224sum"
            | "sha256sum"
            | "sha384sum"
            | "sha512sum"
            | "b2sum"
            | "cksum"
    )
}

pub(in crate::pretool) fn safe_digest_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    safe_digest_with_targets(arguments, piped_input, context, true)
}

pub(in crate::pretool) fn safe_digest_stdin_arguments(arguments: &[String]) -> bool {
    safe_digest_with_targets(arguments, true, super::PathContext::default(), false)
}

/// An algorithm name selects the digest, not a file: `-a 256` for `shasum`,
/// `-a sha256` for `cksum`. It is a short word of letters and digits, and
/// naming an unknown one only makes the program exit.
fn algorithm_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 12
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn safe_digest_with_targets(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
    allow_targets: bool,
) -> bool {
    let mut operands = false;
    let mut separator = false;
    let mut algorithm = false;
    let mut saw_target = false;
    for argument in arguments {
        if algorithm {
            algorithm = false;
            if !algorithm_name(argument) {
                return false;
            }
            continue;
        }
        if !operands && argument == "--" {
            operands = true;
            separator = true;
            continue;
        }
        if !operands && argument.starts_with('-') && argument != "-" {
            if !printing_option(argument, &mut algorithm) {
                return false;
            }
            continue;
        }
        operands = true;
        if argument == "-" {
            if !piped_input {
                return false;
            }
        } else if !allow_targets
            || (argument.starts_with('-') && !separator)
            || !verified_path_context(context.home_dir, context.cwd)
            || !command_read_target(argument, context, false)
        {
            return false;
        }
        saw_target = true;
    }
    !algorithm && (saw_target || piped_input)
}

/// Options that only choose how the digest is printed. `-c`, and the options
/// that qualify it, name a list of files to open instead, so they are absent.
/// So is BSD `md5 -p`, which copies standard input to standard output before
/// the digest: that is a second stream the operand proof says nothing about.
fn printing_option(argument: &str, algorithm: &mut bool) -> bool {
    if let Some(value) = argument.strip_prefix("--algorithm=") {
        return algorithm_name(value);
    }
    if matches!(argument, "-a" | "--algorithm") {
        *algorithm = true;
        return true;
    }
    if let Some(value) = argument.strip_prefix("-a") {
        return algorithm_name(value);
    }
    if matches!(
        argument,
        "--binary" | "--text" | "--tag" | "--untagged" | "--zero"
    ) {
        return true;
    }
    argument.strip_prefix('-').is_some_and(|flags| {
        !flags.is_empty()
            && flags
                .bytes()
                .all(|flag| matches!(flag, b'b' | b't' | b'U' | b'q' | b'r' | b'z' | b'0'))
    })
}
