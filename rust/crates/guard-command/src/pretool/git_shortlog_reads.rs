//! `git shortlog`, which counts the commits history already holds.
//!
//! It writes no ref, object or file and reads no file's contents. It still
//! runs under the repository's configuration and prints through
//! `pager.shortlog`, so the configuration probe clears it before the read is
//! proven, and options outside these lists keep their review.

/// `shortlog` flags that take no value. `-w` carries an optional inline
/// width instead, which [`read_form`] checks.
const SHORTLOG_FLAGS: [&str; 10] = [
    "-n",
    "--numbered",
    "-s",
    "--summary",
    "-e",
    "--email",
    "-c",
    "--committer",
    "--all",
    "--no-merges",
];

/// `shortlog` options whose value names a grouping or a commit range.
///
/// `--format` and `--pretty` are not here. A pretty format expands `%G`,
/// which verifies signatures through the configured program, so a shortlog
/// that carries one keeps its review the way every other history read with
/// one does. `--group` reaches the same expansion through
/// `--group=format:<format>`, so [`shortlog_value`] admits only the groupings
/// that name a field of the commit itself.
///
/// The four date bounds narrow the same history the command already counts.
/// Git reads their value with its own date parser, which resolves a date or
/// a relative phrase and never opens a file, so the value cannot name one.
/// `--after` is git's spelling of `--since` and `--before` of `--until`.
const SHORTLOG_VALUES: [&str; 6] = [
    "--group",
    "--max-count",
    "--since",
    "--after",
    "--until",
    "--before",
];

/// Whether the value one of those options carries is a proven read.
fn shortlog_value(name: &str, value: &str) -> bool {
    match name {
        "--group" => {
            matches!(value, "author" | "committer")
                || value.strip_prefix("trailer:").is_some_and(trailer_token)
        }
        "--max-count" => !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "--since" | "--after" | "--until" | "--before" => date_bound(value),
        _ => false,
    }
}

/// Whether a date bound is written the way git's date parser reads one: a
/// calendar date, a clock time, a zone offset or a relative phrase such as
/// `2.weeks` or `3 days ago`. The punctuation a date uses is admitted and
/// nothing else, so a value carrying a format expansion, a shell operator or
/// an option of its own is not a date and keeps its review.
fn date_bound(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('-')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b' ' | b'-' | b'/' | b':' | b'.' | b',' | b'+')
        })
}

/// Whether a `trailer:` grouping names a trailer the way a commit message
/// writes one: the key before the colon, which is a header name.
fn trailer_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Whether the width a `-w` spelling carries inline is a plain comma-separated
/// count. An empty rest means the bare flag.
fn inline_width(rest: &str) -> bool {
    rest.is_empty()
        || rest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b',')
}

pub(super) fn read_form(rest: &[String]) -> bool {
    let mut arguments = rest.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            return arguments.all(|operand| !operand.is_empty());
        }
        if !argument.starts_with('-') {
            if argument.is_empty() {
                return false;
            }
            continue;
        }
        if SHORTLOG_FLAGS.contains(&argument.as_str()) {
            continue;
        }
        if let Some(width) = argument.strip_prefix("-w") {
            if inline_width(width) {
                continue;
            }
            return false;
        }
        if super::git_listing_reads::short_bundle(argument, "nsec") {
            continue;
        }
        // `-20` is `--max-count=20` written the way git's revision parser
        // reads it, and git itself refuses the spelling unless every
        // character after the dash is a digit. `-n` is this verb's
        // `--numbered`, so only the bare count is read here.
        if let Some(count) = argument.strip_prefix('-') {
            if shortlog_value("--max-count", count) {
                continue;
            }
        }
        if let Some((name, value)) = argument.split_once('=') {
            if SHORTLOG_VALUES.contains(&name) && shortlog_value(name, value) {
                continue;
            }
            return false;
        }
        if SHORTLOG_VALUES.contains(&argument.as_str()) {
            let Some(value) = arguments.next() else {
                return false;
            };
            if shortlog_value(argument, value) {
                continue;
            }
            return false;
        }
        return false;
    }
    true
}

#[cfg(test)]
#[path = "git_shortlog_reads_tests.rs"]
mod tests;
