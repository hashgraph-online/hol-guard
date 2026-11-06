//! `base64` and `base32` over one bounded file, writing only to stdout.
//!
//! The two carry the same option line, so one screen reads both.
//!
//! Encoding or decoding a file reveals its contents exactly like `cat`, so the
//! operand goes through the same bounded, sensitive-path-aware read proof. The
//! output-file option is never admitted.

use super::safe_reads::command_read_target;
use super::search::SECRET_EXTENSIONS;

fn readable(value: &str, context: super::PathContext<'_>) -> bool {
    let extension = std::path::Path::new(value)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !SECRET_EXTENSIONS.contains(&extension.as_str()) && command_read_target(value, context, false)
}

/// The line length `-w`/`--wrap` and BSD `-b`/`--break` carry. It is a count
/// of characters per output line, so a bounded run of digits is the whole of
/// it and nothing it names can be opened.
pub(super) fn safe_wrap_count(value: &str) -> bool {
    !value.is_empty() && value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub(super) fn safe_base64_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let mut target_seen = false;
    let mut pending_input = false;
    let mut pending_wrap = false;
    let mut after_options = false;
    for argument in arguments {
        if pending_wrap {
            pending_wrap = false;
            if !safe_wrap_count(argument) {
                return false;
            }
            continue;
        }
        if pending_input {
            pending_input = false;
            if target_seen || !readable(argument, context) {
                return false;
            }
            target_seen = true;
            continue;
        }
        if !after_options && argument == "--" {
            after_options = true;
            continue;
        }
        if !after_options && argument.starts_with('-') && argument != "-" {
            match argument.as_str() {
                "-i" | "--input" => pending_input = true,
                "-d" | "-D" | "--decode" | "--ignore-garbage" => {}
                "-w" | "-b" => pending_wrap = true,
                other => {
                    let wrap = other
                        .strip_prefix("--wrap=")
                        .or_else(|| other.strip_prefix("--break="))
                        .or_else(|| other.strip_prefix("-w"))
                        .or_else(|| other.strip_prefix("-b"));
                    if !wrap.is_some_and(safe_wrap_count) {
                        return false;
                    }
                }
            }
            continue;
        }
        if target_seen || argument == "-" || !readable(argument, context) {
            return false;
        }
        target_seen = true;
    }
    target_seen && !pending_input && !pending_wrap
}
