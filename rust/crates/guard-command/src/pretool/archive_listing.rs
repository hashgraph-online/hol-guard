//! Listing a zip archive and reading a file's extended attributes.
//!
//! `unzip -l`, `unzip -v` and `zipinfo` print an archive's member table and
//! never extract: Info-ZIP's listing modes take precedence over every option
//! that would write, so the archive is only read. `unzip -z` prints the
//! archive comment the same way. The bare `unzip` form, and any other option,
//! keeps the command under review because it extracts into the working tree.
//!
//! `xattr` without `-w`, `-d` or `-c` prints the names, and with `-p` the
//! values, of one file's extended attributes. On macOS it is a native binary.
//! Elsewhere the `xattr` on `PATH` is usually the Python tool, so the proof
//! there also asks for a Python environment nothing can inject code through.
//!
//! The archive and attribute operands go through the same bounded,
//! sensitive-path-aware read proof `cat` uses. When the archive name opens
//! nothing or no zip archive, `unzip` retries it with `.zip` and `.ZIP`
//! appended, so those names are proven too, for each file a wildcard expands
//! to as well.
//!
//! `tar -t` is deliberately absent. GNU tar reads further options from the
//! `TAR_OPTIONS` environment variable, including `--checkpoint-action=exec`,
//! and that variable cannot be seen here.

use super::safe_reads;

const MAX_OPERANDS: usize = 16;

/// The characters with which the shell turns one word into several.
const EXPANDING: [char; 5] = ['*', '?', '[', '{', '}'];

/// The `unzip` options a listing may carry. `-l`, `-v` and `-z` choose a mode
/// that only prints; `-q` quiets it.
const UNZIP_LISTING_FLAGS: &[u8] = b"lvzq";

/// The `zipinfo` options. `-M` is deliberately absent: it pages the listing
/// and waits on the terminal.
const ZIPINFO_FLAGS: &[u8] = b"12smlvhtTzC";

/// The `xattr` options that only read. `-r` is deliberately absent so that a
/// directory operand names that one directory, never the tree below it.
const XATTR_READING_FLAGS: &[u8] = b"lsvx";

pub(super) fn safe_unzip_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    // `unzip -Z` is `zipinfo` when `-Z` comes first.
    if let Some(("-Z", rest)) = arguments
        .split_first()
        .map(|(first, rest)| (first.as_str(), rest))
    {
        return safe_zipinfo_arguments(rest, context);
    }
    let Some((options, operands)) = split_options(arguments, UNZIP_LISTING_FLAGS) else {
        return false;
    };
    options
        .iter()
        .any(|option| option.contains(['l', 'v', 'z']))
        && archive_operands(operands, context)
}

pub(super) fn safe_zipinfo_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    split_options(arguments, ZIPINFO_FLAGS)
        .is_some_and(|(_, operands)| archive_operands(operands, context))
}

pub(super) fn safe_xattr_arguments(arguments: &[String], context: super::PathContext<'_>) -> bool {
    if !cfg!(target_os = "macos") && !context.python_environment_inert {
        return false;
    }
    let mut operands = Vec::new();
    let mut after_options = false;
    let mut printing = false;
    for argument in arguments {
        let option = argument.as_str();
        if after_options || !option.starts_with('-') || option == "-" {
            operands.push(option);
        } else if option == "--" {
            after_options = true;
        } else {
            let flags = &option.as_bytes()[1..];
            if flags.contains(&b'p') {
                printing = true;
            }
            if !flags
                .iter()
                .all(|flag| *flag == b'p' || XATTR_READING_FLAGS.contains(flag))
            {
                return false;
            }
        }
    }
    // Every word, the attribute name included, stays one literal word: a
    // wildcard or brace could expand into further files or into `-w`.
    operands.iter().all(|operand| !operand.contains(EXPANDING))
        && printing_name_removed(&mut operands, printing)
        && !operands.is_empty()
        && operands.len() <= MAX_OPERANDS
        && operands.iter().all(|operand| {
            *operand != "-" && safe_reads::command_read_target(operand, context, true)
        })
}

/// `-p` takes the attribute name as the first word that is not an option.
fn printing_name_removed(operands: &mut Vec<&str>, printing: bool) -> bool {
    if printing {
        if operands.is_empty() {
            return false;
        }
        operands.remove(0);
    }
    true
}

/// The leading option words, each a cluster of `flags`, and the words after
/// them. Info-ZIP also reads options after the archive name, so a later word
/// that looks like an option fails the screen rather than become a member.
fn split_options<'a>(
    arguments: &'a [String],
    flags: &[u8],
) -> Option<(&'a [String], &'a [String])> {
    let split = arguments
        .iter()
        .position(|argument| !argument.starts_with('-'))
        .unwrap_or(arguments.len());
    let (options, operands) = arguments.split_at(split);
    let options_valid = options.iter().all(|option| {
        option.len() > 1
            && option.as_bytes()[1..]
                .iter()
                .all(|flag| flags.contains(flag))
    });
    let operands_plain = operands.iter().all(|operand| !operand.starts_with('-'));
    (options_valid && operands_plain).then_some((options, operands))
}

/// One archive the read proof admits, then at most a few member names. A
/// member name is a pattern `unzip` matches inside the archive and opens
/// nothing on disk; shell wildcards and braces in one are refused so that
/// the shell cannot turn a file name in the working directory, or a brace
/// alternative, into an option.
///
/// When the archive name opens nothing, or opens something that is not a zip
/// archive, Info-ZIP retries it with `.zip` and then `.ZIP` appended, so each
/// of those names has to pass the read proof too. A wildcard in the archive
/// name is kept only below a directory (`dist/*.whl`), where every name it
/// expands to starts with that directory and none can read as an option.
fn archive_operands(operands: &[String], context: super::PathContext<'_>) -> bool {
    let Some((archive, members)) = operands.split_first() else {
        return false;
    };
    let wildcard_below_directory = archive
        .find(['*', '?', '['])
        .is_none_or(|at| archive[..at].contains('/'));
    members.len() < MAX_OPERANDS
        && members
            .iter()
            .all(|member| !member.is_empty() && !member.contains(EXPANDING))
        && !archive.contains(['{', '}'])
        && wildcard_below_directory
        && archive_names(archive, context).is_some_and(|names| {
            names.iter().all(|name| {
                RETRY_SUFFIXES.iter().all(|suffix| {
                    safe_reads::command_read_target(&format!("{name}{suffix}"), context, false)
                })
            })
        })
}

/// The names Info-ZIP may open for an archive operand: the name itself, then
/// with `.zip` and then `.ZIP` appended. It retries both when the name opens
/// nothing and when it opens a file that is not a zip archive.
const RETRY_SUFFIXES: [&str; 3] = ["", ".zip", ".ZIP"];

/// The archive names `unzip` receives for `archive`. A wildcard counts only
/// when the shell expands it to files the glob proof admits, so every retry
/// name is spelled out and proven. A wildcard that matches nothing reaches
/// Info-ZIP unchanged, which then matches it against the directory itself,
/// suffixed names included, so that form keeps its review.
fn archive_names(archive: &str, context: super::PathContext<'_>) -> Option<Vec<String>> {
    if archive.contains(['*', '?', '[']) {
        safe_reads::glob_file_matches(archive, context)
    } else {
        Some(vec![archive.to_owned()])
    }
}
