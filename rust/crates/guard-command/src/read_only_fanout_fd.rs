//! Syntax of read-only `fd` fan-out: `fd [OPTIONS] [PATTERN] [PATH...] -x CHILD`.
//!
//! `fd -t f -e ts -x cat` is the same walk-and-read `find src -type f -name
//! '*.ts' -exec cat {} +` performs, written in the tool agents reach for more
//! often. The parser marked every `fd` exec mode uncertain, so the whole
//! family -- counting lines, grepping a file set, listing what a search found
//! -- stopped on a review card while its `find` spelling went through.
//!
//! This module reads the shape only. Admission still rests on
//! [`crate::pretool`]'s fan-out proof: workspace-contained roots, regular
//! files only, a source extension for a child that reads contents, and the
//! child's own read-only proof with one file operand appended.
//!
//! The reading is deliberately narrow, because fd's options decide where the
//! walk goes:
//!
//! - every option has to be one of the names below. An unknown option keeps
//!   the uncertain model rather than being guessed at, which is what stops
//!   `--search-path`, `--base-directory` and anything added to a later fd
//!   from silently moving the root;
//! - `--follow`/`-L` is absent, so a symlink is listed as a symlink and
//!   `--type f` keeps it out of the result;
//! - an option and its value are separate words or joined by `=`. A short
//!   cluster such as `-tf` or `-Hx` is not read here;
//! - the child carries no `{}`, `{/}` or other placeholder and no `;`
//!   terminator, so fd appends the file name last and the command the proof
//!   judges is the command that runs.

use super::{
    child_listed, child_reads_contents, source_extension, without_stderr_merge, MAX_ROOTS,
};

/// Options that take a value and cannot move the walk outside the roots.
///
/// `--search-path`, `--base-directory` and `--ignore-file` are absent: the
/// first two name another root, and the third reads a file the command never
/// shows. `--path-separator` is absent too: fd rewrites the separator in the
/// path it hands the child as well as in what it prints, so a value such as
/// `/../` turns a path inside a root into one above it.
const VALUE_OPTIONS: [&str; 19] = [
    "-e",
    "--extension",
    "-t",
    "--type",
    "-d",
    "--max-depth",
    "--min-depth",
    "--exact-depth",
    "-E",
    "--exclude",
    "-S",
    "--size",
    "--changed-within",
    "--changed-before",
    "--changed-after",
    "--max-results",
    "-j",
    "--threads",
    "--color",
];

/// Options that take no value and only narrow or re-spell the result.
///
/// `--list-details`/`-l` is absent because it runs its own `ls`, and
/// `--follow`/`-L` because it walks through symlinks.
const FLAG_OPTIONS: [&str; 16] = [
    "-H",
    "--hidden",
    "-I",
    "--no-ignore",
    "--no-ignore-vcs",
    "--no-ignore-parent",
    "-u",
    "--unrestricted",
    "-s",
    "--case-sensitive",
    "-i",
    "--ignore-case",
    "-g",
    "--glob",
    "--regex",
    "-F",
];

/// The walk a proven `fd` exec runs, in the terms the fan-out proof reads.
pub(crate) struct FdShape<'a> {
    pub roots: Vec<&'a str>,
    pub regular_files_only: bool,
    pub extensions: Vec<&'a str>,
}

pub(crate) struct FdExec<'a> {
    pub shape: FdShape<'a>,
    pub child: &'a [String],
}

/// `fd ... -x CHILD` or `fd ... -X CHILD`, with a child from the read-only
/// list and nothing between the walk and the command it runs.
pub(crate) fn fd_exec(arguments: &[String]) -> Option<FdExec<'_>> {
    let arguments = without_stderr_merge(arguments);
    // A pathname glob is one word here and several, or different ones, by the
    // time fd is called: `fd -t f -e ts . * -x cat` walks whatever the shell
    // found beside the working directory, not the roots this reader saw. The
    // shape is refused rather than guessed at, which costs a pattern written
    // as a glob its reading and keeps the walk the proof judged.
    if arguments
        .iter()
        .any(|argument| argument.contains(['*', '?', '[']))
    {
        return None;
    }
    let mut positionals: Vec<&str> = Vec::new();
    let mut types: Vec<&str> = Vec::new();
    let mut extensions: Vec<&str> = Vec::new();
    let mut index = 0;
    let mut child: Option<&[String]> = None;
    while let Some(word) = arguments.get(index).map(String::as_str) {
        index += 1;
        if word == "--" {
            return None;
        }
        if matches!(word, "-x" | "-X" | "--exec" | "--exec-batch") {
            child = Some(&arguments[index..]);
            break;
        }
        if !word.starts_with('-') || word == "-" {
            positionals.push(word);
            continue;
        }
        let (name, inline) = match word.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (word, None),
        };
        if FLAG_OPTIONS.contains(&name) {
            // `--glob=...` is not a spelling fd accepts for a flag.
            if inline.is_some() {
                return None;
            }
            continue;
        }
        if !VALUE_OPTIONS.contains(&name) {
            return None;
        }
        let value = match inline {
            Some(value) => value,
            None => {
                let value = arguments.get(index).map(String::as_str)?;
                index += 1;
                value
            }
        };
        match name {
            "-t" | "--type" => types.push(value),
            "-e" | "--extension" => extensions.push(value),
            _ => {}
        }
    }
    let child = child?;
    if child.is_empty()
        || child
            .iter()
            .any(|word| word.contains(['{', '}']) || matches!(word.as_str(), ";" | r"\;" | "+"))
        || !child_listed(child)
    {
        return None;
    }
    // fd reads the first positional as the pattern and the rest as roots; with
    // none, or only a pattern, it walks the working directory.
    let roots = match positionals.len() {
        0 | 1 => vec!["."],
        _ => positionals[1..].to_vec(),
    };
    if roots.len() > MAX_ROOTS {
        return None;
    }
    // Several `--type` values are a union, so every one of them has to be the
    // regular-file type for the result to hold regular files only.
    let regular_files_only =
        !types.is_empty() && types.iter().all(|value| matches!(*value, "f" | "file"));
    Some(FdExec {
        shape: FdShape {
            roots,
            regular_files_only,
            extensions,
        },
        child,
    })
}

/// Whether the walk itself is bounded, leaving only the roots to place.
///
/// This is the part of the fan-out proof that reads from the line alone, and
/// the parser asks the same question before it stops calling an `fd` exec a
/// nested command executor: a shape that fails here has to stay uncertain,
/// because nothing further along would look at it again.
pub(crate) fn producer_shape_proven(exec: &FdExec<'_>) -> bool {
    exec.shape.regular_files_only
        && exec.shape.roots.iter().all(|root| root_bounded(root))
        && (!child_reads_contents(exec.child) || source_extensions_only(&exec.shape.extensions))
}

/// Whether a root is one the line alone shows to stay below the working
/// directory.
///
/// Where the walk actually lands is a question only the working directory
/// answers, and [`crate::pretool`]'s fan-out proof asks it. This is the half
/// the text settles: an absolute path, a home-relative one and a `..`
/// component each name a tree the working directory does not hold, and the
/// parser reads this answer too, so a root it cannot place keeps the
/// uncertain model instead of resting on a proof that runs later.
fn root_bounded(root: &str) -> bool {
    let normalized = root.replace('\\', "/");
    !normalized.starts_with('/')
        && !normalized.starts_with('~')
        && !normalized.split('/').any(|part| part == "..")
        // `C:` and `\\server`, which name a tree of their own on Windows.
        && !normalized.contains(':')
}

/// Whether every `--extension` value names a source file.
///
/// fd reads several `--extension` values as a union, so one credential
/// extension beside a source one widens the walk back to the files a content
/// reader may not have.
fn source_extensions_only(extensions: &[&str]) -> bool {
    !extensions.is_empty()
        && extensions
            .iter()
            .all(|extension| source_extension(extension))
}

#[cfg(test)]
#[path = "read_only_fanout_fd_tests.rs"]
mod tests;
