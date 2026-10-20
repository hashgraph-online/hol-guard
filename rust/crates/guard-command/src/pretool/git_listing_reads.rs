//! `git shortlog` and `git check-ignore`, the two listings that only print.
//!
//! `shortlog` counts the commits history already holds and `check-ignore`
//! answers which ignore rule a path matches. Neither writes a ref, an object
//! or a file. Both still run under the repository's configuration, so the
//! configuration probe clears them before the read is proven, and options
//! outside these lists keep their review.

/// `shortlog` flags that take no value. `-w` carries an optional inline
/// width instead, which [`shortlog_read_form`] checks.
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
const SHORTLOG_VALUES: [&str; 2] = ["--group", "--max-count"];

/// Whether the value one of those options carries is a proven read.
fn shortlog_value(name: &str, value: &str) -> bool {
    match name {
        "--group" => {
            matches!(value, "author" | "committer")
                || value.strip_prefix("trailer:").is_some_and(trailer_token)
        }
        "--max-count" => !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        _ => false,
    }
}

/// Whether a `trailer:` grouping names a trailer the way a commit message
/// writes one: the key before the colon, which is a header name.
fn trailer_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// `check-ignore` flags. All of them change what is printed and nothing else.
const CHECK_IGNORE_FLAGS: [&str; 6] = ["-q", "--quiet", "-v", "--verbose", "-z", "--no-index"];

/// Whether the listing reads the index, which can start `core.fsmonitor`.
/// `check-ignore` consults the index unless `--no-index` is given; a shortlog
/// reads commits and never the index.
pub(crate) fn reads_index(subcommand: &str, rest: &[String]) -> bool {
    subcommand == "check-ignore" && !options(rest).any(|argument| argument == "--no-index")
}

/// Whether the listing prints the rule that matched and the file it came
/// from, which `check-ignore` does in its verbose form. That file is
/// `core.excludesFile` as often as it is the repository's own `.gitignore`.
pub(crate) fn prints_rule_source(subcommand: &str, rest: &[String]) -> bool {
    subcommand == "check-ignore"
        && options(rest).any(|argument| {
            matches!(argument, "-v" | "--verbose")
                || (short_bundle(argument, "qvz") && argument.contains('v'))
        })
}

/// The words before `--`, which are the only ones Git reads as options.
fn options(rest: &[String]) -> impl Iterator<Item = &str> {
    rest.iter()
        .take_while(|argument| *argument != "--")
        .map(String::as_str)
}

/// Whether `subcommand rest...` is a proven listing read.
pub(crate) fn read_form(subcommand: &str, rest: &[String]) -> bool {
    match subcommand {
        "shortlog" => shortlog_read_form(rest),
        "check-ignore" => check_ignore_read_form(rest),
        _ => false,
    }
}

/// Whether a one-dash spelling is a bundle of single-letter flags. Git's
/// option parser reads `-sn` as `-s -n`, so a bundle prints exactly what the
/// same letters spelled apart print, and the read grammar has to admit both.
/// `-w` carries an optional inline width, so it is matched before this and
/// never appears in a bundle here.
fn short_bundle(argument: &str, letters: &str) -> bool {
    match argument.strip_prefix('-') {
        Some(rest) if rest.len() > 1 && !rest.starts_with('-') => {
            rest.chars().all(|letter| letters.contains(letter))
        }
        _ => false,
    }
}

/// Whether the width a `-w` spelling carries inline is a plain comma-separated
/// count. An empty rest means the bare flag.
fn inline_width(rest: &str) -> bool {
    rest.is_empty()
        || rest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b',')
}

fn shortlog_read_form(rest: &[String]) -> bool {
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
        if short_bundle(argument, "nsec") {
            continue;
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

fn check_ignore_read_form(rest: &[String]) -> bool {
    let mut names = 0_usize;
    let mut arguments = rest.iter();
    let mut stdin = false;
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            let operands = arguments.as_slice();
            return operands.iter().all(|operand| !operand.is_empty())
                && (names + operands.len() > 0 || stdin);
        }
        if !argument.starts_with('-') {
            if argument.is_empty() {
                return false;
            }
            names += 1;
            continue;
        }
        if CHECK_IGNORE_FLAGS.contains(&argument.as_str()) || short_bundle(argument, "qvz") {
            continue;
        }
        // `--stdin` takes the paths from the pipe the command already has,
        // and the command prints which rule matched each of them.
        if argument == "--stdin" {
            stdin = true;
            continue;
        }
        return false;
    }
    names > 0 || stdin
}
