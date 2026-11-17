//! Digest printers: `shasum`, the `*sum` family, BSD `md5` and `openssl dgst`.
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

/// `openssl dgst -sha256 dist/app.whl` prints the same one line per file the
/// `*sum` family prints, and `openssl sha256 dist/app.whl` is its older
/// spelling. Only the digest names and the printing switches are admitted.
/// Everything else `dgst` takes reaches further: `-sign`, `-verify`,
/// `-prverify`, `-hmac`, `-mac` and `-passin` bring in a key or a secret,
/// `-out` and `-writerand` write a file, `-rand` opens more files, and
/// `-engine` and `-provider` load a shared library.
pub(in crate::pretool) fn safe_openssl_digest_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    // An inherited OpenSSL configuration can load a provider or engine
    // library before the digest runs, whatever the arguments say.
    if !context.openssl_config_absent {
        return false;
    }
    let Some((command, rest)) = arguments.split_first() else {
        return false;
    };
    let mut digest_chosen = openssl_digest_name(command);
    if command != "dgst" && !digest_chosen {
        return false;
    }
    let mut operands = false;
    let mut separator = false;
    let mut saw_target = false;
    for argument in rest {
        if !operands && argument == "--" {
            operands = true;
            separator = true;
            continue;
        }
        if !operands && argument.starts_with('-') && argument != "-" {
            let switch = &argument[1..];
            if openssl_digest_name(switch) && !digest_chosen {
                digest_chosen = true;
            } else if !matches!(switch, "r" | "c" | "hex" | "binary") {
                return false;
            }
            continue;
        }
        operands = true;
        if argument == "-"
            || (argument.starts_with('-') && !separator)
            || !digest_target(argument, context)
        {
            return false;
        }
        saw_target = true;
    }
    saw_target || piped_input
}

/// The digests OpenSSL names on its own command line. A name outside this
/// list is one of the options above, or a typo that only makes it exit.
fn openssl_digest_name(name: &str) -> bool {
    matches!(
        name,
        "md5"
            | "sha1"
            | "sha224"
            | "sha256"
            | "sha384"
            | "sha512"
            | "sha512-224"
            | "sha512-256"
            | "sha3-224"
            | "sha3-256"
            | "sha3-384"
            | "sha3-512"
            | "blake2b512"
            | "blake2s256"
            | "ripemd160"
            | "sm3"
    )
}

fn digest_target(argument: &str, context: super::PathContext<'_>) -> bool {
    verified_path_context(context.home_dir, context.cwd)
        && command_read_target(argument, context, false)
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
            || !digest_target(argument, context)
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
