//! Disk-usage, filesystem and file-comparison reads proven without review.
//!
//! `du` and `df` report sizes from metadata and never open a file. `df` only
//! asks which filesystem holds each operand, so a plain path is enough. `du`
//! walks its operands and prints the name of every directory below them (every
//! file too with `-a`), so unless `-s` or a zero depth limits the output to the
//! operands, each operand gets the same tree screen as `ls -R`. Following
//! symbolic links (`-L`) is not admitted, and neither is any option that reads
//! operand or pattern lists from a file (`--files0-from`, `-X`).
//!
//! An operand that does not exist makes `du` print only an error, exactly as
//! `ls` does, so it gets the same absent-path proof as an `ls` operand: a
//! sibling checkout's missing `node_modules` is no more revealing than listing
//! that checkout.
//!
//! `diff` reads the content of both operands. Two files each need the
//! ordinary read proof, or the absent chain-local temporary file proof. A
//! directory operand makes `diff` read the files inside it, so both operands
//! then need the recursive content-search screen.
//!
//! `file` reads the first bytes of each operand and prints a type label, never
//! the content, so each operand gets the ordinary read proof (a directory is
//! just labelled `directory`) or the absent-path proof. Options that load magic
//! or name lists from another path (`-m`, `-f`), compile magic (`-C`), touch
//! access times (`-p`), open devices (`-s`), run decompressors (`-z`) or take
//! a value are not admitted.
//!
//! `stat` prints the metadata of each operand and never opens it. A format
//! option (`-f`/`-t` on BSD, `-c`/`--format`/`--printf` on GNU) only shapes
//! that text. Every operand gets the ordinary read proof, or the absent
//! chain-local temporary file proof, so a credential path stays reviewed.
use super::{safe_reads, search};

const MAX_OPERANDS: usize = 16;

pub(super) fn safe_du_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let mut names_descendants = true;
    let mut operands = Vec::new();
    let mut values = arguments.iter();
    while let Some(argument) = values.next() {
        let option = argument.as_str();
        if option == "-d" || option == "--max-depth" {
            match values.next() {
                Some(depth) if digits(depth) => names_descendants &= !zero(depth),
                _ => return false,
            }
        } else if let Some(depth) = option.strip_prefix("-d").filter(|depth| digits(depth)) {
            names_descendants &= !zero(depth);
        } else if let Some(long) = option.strip_prefix("--") {
            match long.split_once('=') {
                Some(("max-depth", depth)) if digits(depth) => {
                    names_descendants &= !zero(depth);
                }
                Some(("exclude", pattern)) if !pattern.is_empty() => {}
                None if long == "all" => names_descendants = true,
                None if long == "summarize" => names_descendants = false,
                None if matches!(
                    long,
                    "human-readable"
                        | "total"
                        | "apparent-sizes"
                        | "si"
                        | "one-file-system"
                        | "bytes"
                ) => {}
                _ => return false,
            }
        } else if let Some(flags) = option.strip_prefix('-').filter(|flags| !flags.is_empty()) {
            if !flags.bytes().all(|flag| b"abchkmsxAHP".contains(&flag)) {
                return false;
            }
            if flags.contains('s') {
                names_descendants = false;
            }
        } else if option == "-" {
            return false;
        } else {
            operands.push(option);
        }
    }
    if operands.is_empty() {
        operands.push(".");
    }
    operands.len() <= MAX_OPERANDS
        && operands.iter().all(|operand| {
            let present = if names_descendants {
                search::safe_recursive_target(operand, context)
            } else {
                safe_reads::bounded_read_target(operand, context.home_dir, context.cwd, true)
            };
            present || super::listing_reads::absent_listing_operand(operand, context)
        })
}

pub(super) fn safe_df_arguments(arguments: &[String]) -> bool {
    let mut operands = 0_usize;
    for argument in arguments {
        let option = argument.as_str();
        if let Some(long) = option.strip_prefix("--") {
            if !matches!(
                long,
                "human-readable" | "si" | "portability" | "local" | "inodes" | "total" | "all"
            ) {
                return false;
            }
        } else if let Some(flags) = option.strip_prefix('-') {
            if flags.is_empty() || !flags.bytes().all(|flag| b"aHhiklmP".contains(&flag)) {
                return false;
            }
        } else if plain_path(option) {
            operands += 1;
        } else {
            return false;
        }
    }
    operands <= MAX_OPERANDS
}

pub(super) fn safe_diff_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let mut operands = Vec::new();
    let mut after_options = false;
    let mut values = arguments.iter();
    while let Some(argument) = values.next() {
        let option = argument.as_str();
        if after_options || !option.starts_with('-') || option == "-" {
            operands.push(option);
        } else if option == "--" {
            after_options = true;
        } else if option == "-U" {
            if !values.next().is_some_and(|lines| digits(lines)) {
                return false;
            }
        } else if !diff_option(option) {
            return false;
        }
    }
    let [left, right] = operands.as_slice() else {
        return false;
    };
    if *left == "-" || *right == "-" {
        return false;
    }
    // A chain may diff a temporary copy it makes first, which is absent when
    // the hook runs; reading it can only report a missing file.
    [left, right].iter().all(|operand| {
        safe_reads::bounded_read_target(operand, context.home_dir, context.cwd, false)
            || super::chain_temporary::absent_temporary_read_target(
                operand,
                context.home_dir,
                context.cwd,
            )
    }) || [left, right]
        .iter()
        .all(|operand| search::safe_recursive_target_through_links(operand, context))
}

/// Output-format and comparison options. Options that read another file
/// (`--from-file`, `-X`, `-S`) or name a program are not on the list.
fn diff_option(option: &str) -> bool {
    if let Some(long) = option.strip_prefix("--") {
        return match long.split_once('=') {
            Some(("unified", lines)) => digits(lines),
            Some(("color", mode)) => matches!(mode, "never" | "auto" | "always"),
            Some(("exclude", pattern)) => !pattern.is_empty(),
            Some(_) => false,
            None => matches!(
                long,
                "unified"
                    | "brief"
                    | "recursive"
                    | "new-file"
                    | "ignore-all-space"
                    | "ignore-space-change"
                    | "ignore-blank-lines"
                    | "ignore-case"
                    | "text"
                    | "report-identical-files"
                    | "strip-trailing-cr"
                    | "side-by-side"
                    | "suppress-common-lines"
                    | "minimal"
                    | "color"
                    | "expand-tabs"
                    | "initial-tab"
                    | "show-c-function"
            ),
        };
    }
    option.strip_prefix("-U").is_some_and(digits)
        || option[1..]
            .bytes()
            .all(|flag| b"uqrNbwBiastpyEZ".contains(&flag))
}

pub(super) fn safe_stat_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let mut operands = Vec::new();
    // GNU stat can interpret BSD formatting flags as bare file options.
    let mut format_operands = Vec::new();
    let mut after_options = false;
    let mut values = arguments.iter();
    while let Some(argument) = values.next() {
        let option = argument.as_str();
        if after_options || !option.starts_with('-') || option == "-" {
            operands.push(option);
        } else if option == "--" {
            after_options = true;
        } else if option == "-c"
            || (matches!(option, "-f" | "-t")
                && cfg!(any(
                    target_os = "macos",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly"
                )))
        {
            // BSD stat takes a format operand for -f/-t, GNU stat does not.
            let Some(format) = values.next().filter(|format| stat_format(format)) else {
                return false;
            };
            if option != "-c" {
                format_operands.push(format.as_str());
            }
        } else if matches!(option, "-f" | "-t") {
            // GNU stat: -f prints filesystem data, -t is terse. The *next*
            // argument is a file operand and must pass its own path proof.
        } else if let Some(long) = option.strip_prefix("--") {
            let allowed = match long.split_once('=') {
                Some(("format" | "printf", format)) => stat_format(format),
                Some(_) => false,
                None => matches!(long, "dereference" | "terse"),
            };
            if !allowed {
                return false;
            }
        } else if !option[1..].bytes().all(|flag| b"FLlnqrsx".contains(&flag)) {
            return false;
        }
    }
    !operands.is_empty()
        && operands.len() <= MAX_OPERANDS
        && operands.iter().any(|operand| !inert_format(operand))
        && operands
            .iter()
            .chain(format_operands.iter())
            .all(|operand| {
                inert_format(operand)
                    || safe_reads::bounded_read_target(operand, context.home_dir, context.cwd, true)
                    || super::chain_temporary::absent_temporary_read_target(
                        operand,
                        context.home_dir,
                        context.cwd,
                    )
            })
}

/// A format such as `"%N %Sm"` that GNU stat would take as a file name. Read
/// that way it is a metadata lookup of one name in the working directory,
/// never a content read. It names no other directory, no home path and no
/// glob, and the `%` keeps it from naming an ordinary file such as `.env` or
/// a key the working directory holds.
fn inert_format(value: &str) -> bool {
    stat_format(value)
        && value.contains('%')
        && !value.starts_with(['~', '-'])
        && !value.contains(['/', '\\', '*', '?', '[', '$', '`'])
}

/// An output format is printed, never run: bounded, single-line text.
fn stat_format(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.contains(['\n', '\r', '\0'])
}

pub(super) fn safe_file_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    let mut operands = Vec::new();
    let mut after_options = false;
    for argument in arguments {
        let option = argument.as_str();
        if after_options || !option.starts_with('-') {
            operands.push(option);
        } else if option == "--" {
            after_options = true;
        } else if let Some(long) = option.strip_prefix("--") {
            if !matches!(
                long,
                "brief"
                    | "mime"
                    | "mime-type"
                    | "mime-encoding"
                    | "keep-going"
                    | "dereference"
                    | "no-dereference"
                    | "no-pad"
                    | "no-buffer"
                    | "raw"
                    | "print0"
                    | "extension"
                    | "apple"
                    | "version"
            ) {
                return false;
            }
        } else if option == "-"
            || !option[1..]
                .bytes()
                .all(|flag| b"bhiIkLNnrv0E".contains(&flag))
        {
            return false;
        }
    }
    !operands.is_empty()
        && operands.len() <= MAX_OPERANDS
        && operands.iter().all(|operand| {
            *operand != "-"
                && (safe_reads::bounded_read_target(operand, context.home_dir, context.cwd, true)
                    || super::listing_reads::absent_listing_operand(operand, context))
        })
}

fn zero(depth: &str) -> bool {
    depth.bytes().all(|byte| byte == b'0')
}

fn digits(value: &str) -> bool {
    !value.is_empty() && value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// `df` reads no file content, so an operand only has to be a literal path.
fn plain_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '{', '}', '[', ']',
        ])
}

#[cfg(all(test, target_os = "linux"))]
mod stat_operand_regression_tests {
    use super::*;

    #[test]
    fn gnu_short_flags_do_not_hide_the_next_file_operand() {
        let root = env!("CARGO_MANIFEST_DIR");
        let context = super::super::PathContext {
            home_dir: Some(root),
            cwd: Some(root),
            ..Default::default()
        };
        for flag in ["-f", "-t"] {
            let operands = vec![
                flag.to_owned(),
                "/etc/shadow".to_owned(),
                "Cargo.toml".to_owned(),
            ];
            assert!(
                !safe_stat_arguments(&operands, context),
                "{flag} must prove every file"
            );
        }
    }
}
