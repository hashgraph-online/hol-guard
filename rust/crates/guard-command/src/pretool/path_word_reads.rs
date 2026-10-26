//! Path-word commands: the ones that rewrite or resolve a path operand.
//!
//! `dirname` and `basename` are pure string transforms. Coreutils never stats
//! the operand for either: `dirname /a/b/c` prints `/a/b` whether or not any
//! part of it exists, so the operand carries no read and the output is a
//! substring of text the caller already wrote. Neither command has an option
//! that opens, writes or executes anything, so only the option spelling and a
//! bounded single-line operand need proving.
//!
//! `readlink` and `realpath` do resolve the operand against the filesystem and
//! report whether it exists and where a symbolic link points. That is the same
//! answer `ls` gives for a path, so their operands take the same read proof an
//! `ls` operand takes, directories included. The options that take a path of
//! their own (`--relative-to`, `--relative-base`) are not admitted: they would
//! name a second location that this proof never screened.

const MAX_OPERANDS: usize = 16;

/// A path word is printed back, never opened: bounded, single-line text that
/// the shell hands over as it was written. A word carrying a command
/// substitution runs something this proof never screened before the rewrite
/// ever happens, so it is not a path word at all.
fn bounded_path_word(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.contains(['\n', '\r', '\0'])
        && crate::sfrs_path_word_lookups::path_word_runs_nothing(value)
}

/// `dirname` and `basename`, which rewrite the operand without reading it.
pub(super) fn safe_path_word_arguments(tool: &str, arguments: &[String]) -> bool {
    let mut operands = 0usize;
    let mut after_options = false;
    let mut values = arguments.iter();
    while let Some(argument) = values.next() {
        let option = argument.as_str();
        if after_options || !option.starts_with('-') || option == "-" {
            if !bounded_path_word(option) {
                return false;
            }
            operands += 1;
        } else if option == "--" {
            after_options = true;
        } else if tool == "basename" && option == "-s" {
            // The suffix is stripped from the printed name, never opened.
            if !values
                .next()
                .is_some_and(|suffix| bounded_path_word(suffix))
            {
                return false;
            }
        } else if let Some(long) = option.strip_prefix("--") {
            let allowed = match long.split_once('=') {
                Some(("suffix", suffix)) => tool == "basename" && bounded_path_word(suffix),
                Some(_) => false,
                None => long == "zero" || (tool == "basename" && long == "multiple"),
            };
            if !allowed {
                return false;
            }
        } else if !option[1..]
            .bytes()
            .all(|flag| flag == b'z' || (tool == "basename" && flag == b'a'))
        {
            return false;
        }
    }
    operands > 0 && operands <= MAX_OPERANDS
}

/// `readlink` and `realpath`, which resolve the operand and report what the
/// filesystem holds, so every operand takes the ordinary read proof.
pub(super) fn safe_resolved_path_arguments(
    tool: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let mut operands = Vec::new();
    let mut after_options = false;
    for argument in arguments {
        let option = argument.as_str();
        if after_options || !option.starts_with('-') || option == "-" {
            operands.push(option);
        } else if option == "--" {
            after_options = true;
        } else if let Some(long) = option.strip_prefix("--") {
            if long.contains('=') || !resolved_long_option(tool, long) {
                return false;
            }
        } else if !option[1..]
            .bytes()
            .all(|flag| resolved_short_flag(tool, flag))
        {
            return false;
        }
    }
    !operands.is_empty()
        && operands.len() <= MAX_OPERANDS
        && operands
            .iter()
            .all(|operand| super::safe_reads::command_read_target(operand, context, true))
}

/// Long options that only change how the resolved path is printed.
fn resolved_long_option(tool: &str, long: &str) -> bool {
    match tool {
        "readlink" => matches!(
            long,
            "canonicalize"
                | "canonicalize-existing"
                | "canonicalize-missing"
                | "no-newline"
                | "quiet"
                | "silent"
                | "verbose"
                | "zero"
        ),
        _ => matches!(
            long,
            "canonicalize-existing"
                | "canonicalize-missing"
                | "logical"
                | "physical"
                | "quiet"
                | "strip"
                | "no-symlinks"
                | "zero"
        ),
    }
}

/// Short flags that only change how the resolved path is printed.
fn resolved_short_flag(tool: &str, flag: u8) -> bool {
    match tool {
        "readlink" => b"efmnqsvz".contains(&flag),
        _ => b"LPemqsz".contains(&flag),
    }
}
