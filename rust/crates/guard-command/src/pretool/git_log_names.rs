//! `git log` that lists commits and file names, filtered by glob pathspecs.
//!
//! A pathspec after `--` only chooses which commits and names the log
//! prints. Without a patch option the log prints no file content, and the
//! unfiltered log already names every tracked path, so a glob such as
//! `'src/*'` or `'*migration*'` reveals nothing more even though it could
//! match a credential file name. A literal credential path, a magic pathspec,
//! a path outside the repository or any option that prints content or runs
//! a signature program keeps the read reviewed.

use std::path::Path;

/// Options that print commit metadata, names or counts and never content.
const LISTING_OPTIONS: [&str; 26] = [
    "--oneline",
    "--name-only",
    "--name-status",
    "--stat",
    "--shortstat",
    "--numstat",
    "--summary",
    "--no-merges",
    "--merges",
    "--first-parent",
    "--reverse",
    "--all",
    "--graph",
    "--decorate",
    "--no-decorate",
    "--abbrev-commit",
    "--no-abbrev-commit",
    "--no-patch",
    "-s",
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
    "--topo-order",
    "--date-order",
    "--relative-date",
    "--left-right",
];

/// Options whose attached value only filters or formats the listing.
const LISTING_VALUE_OPTIONS: [&str; 12] = [
    "--diff-filter=",
    "--max-count=",
    "--since=",
    "--until=",
    "--after=",
    "--before=",
    "--author=",
    "--committer=",
    "--grep=",
    "--date=",
    "--decorate=",
    "--abbrev=",
];

/// Index in `arguments` of the first pathspec after `--` when the whole
/// argument list is such a names-only `git log`, or `None`.
pub(super) fn pathspec_start(
    arguments: &[String],
    context: super::super::PathContext<'_>,
) -> Option<usize> {
    let inspected = crate::command_compatibility::git_inspection_arguments(arguments, context)?;
    let offset = arguments.len() - inspected.len();
    let (subcommand, rest) = inspected.split_first()?;
    if subcommand != "log" {
        return None;
    }
    let separator = rest.iter().position(|argument| argument == "--")?;
    let (options, pathspecs) = (&rest[..separator], &rest[separator + 1..]);
    (!pathspecs.is_empty()
        && options.iter().all(|argument| listing_argument(argument))
        && pathspecs.iter().all(|pathspec| listed_pathspec(pathspec)))
    .then_some(offset + 1 + separator + 1)
}

/// A revision, or an option that keeps the log to metadata and names.
fn listing_argument(argument: &str) -> bool {
    if !argument.starts_with('-') {
        return true;
    }
    if LISTING_OPTIONS.contains(&argument) || count_option(argument) {
        return true;
    }
    if let Some(format) = argument
        .strip_prefix("--format=")
        .or_else(|| argument.strip_prefix("--pretty="))
    {
        return listing_format(format);
    }
    LISTING_VALUE_OPTIONS
        .iter()
        .any(|prefix| argument.starts_with(prefix))
}

/// A built-in format name, or an explicit format without `%G` placeholders,
/// which verify signatures and so run the configured signing program. Any
/// other name resolves through a `pretty.<name>` alias Guard did not read.
fn listing_format(format: &str) -> bool {
    const BUILT_IN: &[&str] = &[
        "oneline",
        "short",
        "medium",
        "full",
        "fuller",
        "reference",
        "email",
        "raw",
        "mboxrd",
    ];
    if BUILT_IN.contains(&format) {
        return true;
    }
    let explicit = format
        .strip_prefix("format:")
        .or_else(|| format.strip_prefix("tformat:"))
        .or_else(|| format.contains('%').then_some(format));
    explicit.is_some_and(|format| !format.contains("%G"))
}

/// `-3` or `-n3`.
fn count_option(argument: &str) -> bool {
    let digits = argument
        .strip_prefix("-n")
        .or_else(|| argument.strip_prefix('-'))
        .unwrap_or_default();
    !digits.is_empty() && digits.bytes().all(|digit| digit.is_ascii_digit())
}

/// A repository-relative pathspec whose only concern is that, as a glob, it
/// might match a credential file name.
fn listed_pathspec(pathspec: &str) -> bool {
    let normalized = super::super::normalized_haystack(pathspec);
    let relative = normalized.strip_prefix("./").unwrap_or(&normalized);
    !relative.is_empty()
        && !relative.starts_with([':', '/', '~', '-'])
        && !relative.split('/').any(|part| part == "..")
        && !super::super::sensitive_path_argument(pathspec)
        && !guard_secure_fs::credential_named_path(Path::new(relative))
}

#[cfg(test)]
#[path = "git_log_names_tests.rs"]
mod tests;
