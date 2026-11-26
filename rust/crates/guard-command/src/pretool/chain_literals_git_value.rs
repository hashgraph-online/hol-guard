//! `git show --stat $(git log -1 --format=%h -- README.md)` or
//! `git diff $(git merge-base HEAD origin/main) --stat` hand one Git command
//! the commit another one looks up. The lookup prints a commit hash or
//! nothing, so it is a value producer like `date`: its value is written as a
//! fixed hexadecimal stand-in and the outer command is judged on its words.
//!
//! Only lookups whose output is a hash are recognised:
//!
//! - `git rev-parse` with `--verify` or `--short`, which print one hash or
//!   fail, or a bare `git rev-parse` of one revision. A bare `rev-parse`
//!   prints back an operand it cannot resolve, so it prints a hash or that
//!   word, never nothing (see [`echoed`]). Without `--verify` the operand
//!   must be `HEAD` or `@`, or spelled as a ref name (`origin/main`,
//!   `FETCH_HEAD`, `v1.2~1`), with any `~` / `^` steps: a ref name has no
//!   component that starts with `.`, so `git rev-parse .env` stays opaque.
//!   A quoted `'REV^{commit}'` or `'REV^{}'` peels the same revision.
//! - `git log -1` with `--format` or `--pretty` set to `%h` or `%H`. The
//!   inner command is judged on its own first, and that refuses a
//!   configuration that adds text, such as `log.showSignature`.
//! - `git merge-base A B`, which prints the one best common ancestor.
//!
//! A lookup can print nothing (a path with no history, an unknown branch),
//! and the shell then drops the word. A missing word changes what most
//! programs read: `grep -r TODO $(...)` would search the working directory.
//! For a Git command a missing revision means `HEAD` or the working tree, the
//! same kind of read or write, so the stand-in is used only inside a command
//! that runs `git`, and only where the lookup is a word of its own or one end
//! of a range: text glued to it could turn into an option or a file name.
//! A bare `rev-parse` that cannot resolve its operand prints the operand
//! instead, so the command is also judged with that word in the lookup's
//! place.

use crate::shell_structure::ShellCommandSubstitution;

/// Stand-in for the commit hash a lookup prints.
pub(super) const COMMIT_VALUE: &str = "0123456789abcdef0123456789abcdef01234567";

const MAX_BODY_CHARS: usize = 160;

/// The stand-in for `body` when it is a Git lookup that prints only a hash.
pub(super) fn stand_in(body: &str) -> Option<&'static str> {
    if body.len() > MAX_BODY_CHARS {
        return None;
    }
    let words: Vec<&str> = body.split(' ').filter(|word| !word.is_empty()).collect();
    if let ["git", "rev-parse", operand] = words.as_slice() {
        if let Some(revision) = peeled(operand) {
            return (revision.chars().all(body_character)
                && (head_relative(revision) || named(revision)))
            .then_some(COMMIT_VALUE);
        }
    }
    if !body.chars().all(body_character) {
        return None;
    }
    let printed = match words.as_slice() {
        ["git", "rev-parse", arguments @ ..] => rev_parse(arguments),
        ["git", "log", arguments @ ..] => log(arguments),
        ["git", "merge-base", first, second] => revision(first) && revision(second),
        _ => false,
    };
    printed.then_some(COMMIT_VALUE)
}

/// The word a bare `git rev-parse` lookup prints when it cannot resolve its
/// operand: the operand itself. `None` for a lookup that prints a hash or
/// nothing.
pub(super) fn echoed(body: &str) -> Option<&str> {
    stand_in(body)?;
    match body
        .split(' ')
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()[..]
    {
        ["git", "rev-parse", operand] => Some(operand),
        _ => None,
    }
}

/// Whether the substitution at `start` is an argument of a command that
/// runs `git`. `chars` is the heredoc-masked command; quotes are followed so
/// an operator inside a quoted word does not start a command, and an earlier
/// substitution in `spans` is stepped over as one word.
pub(super) fn in_git_command(
    chars: &[char],
    spans: &[ShellCommandSubstitution],
    start: usize,
) -> bool {
    command_before(chars, spans, start)
        .is_some_and(|segment| segment.trim_start().starts_with("git "))
}

/// The text of the command that holds the substitution at `start`, from the
/// operator that began it up to the substitution, or `None` inside single
/// quotes, where the text is not a substitution at all.
pub(super) fn command_before(
    chars: &[char],
    spans: &[ShellCommandSubstitution],
    start: usize,
) -> Option<String> {
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut begins = 0usize;
    for (at, &character) in chars.iter().enumerate().take(start) {
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            ';' | '&' | '|' | '\n' | '(' | ')' | '`' if !single && !double => begins = at + 1,
            _ => {}
        }
    }
    // Inside double quotes the substitution is still the command's argument;
    // inside single quotes it is not a substitution at all.
    if single {
        return None;
    }
    Some(chars[begins..start].iter().collect())
}

/// Whether the substitution is a word of its own, so that an empty lookup
/// removes a revision and nothing else. Glued text would change meaning:
/// `$(...)--output=x` becomes an option and `HEAD:.$(...)env` names `.env`.
/// A whole double-quoted word (`"$(...)"`) becomes an empty argument, and a
/// range end (`$(...)..HEAD`, `main..$(...)`) stays a range.
pub(super) fn standalone(chars: &[char], substitution: &ShellCommandSubstitution) -> bool {
    let (start, end) = (substitution.start, substitution.end);
    let opened = start
        .checked_sub(1)
        .filter(|&quote| chars[quote] == '"' && !inside_double_quotes(&chars[..quote]));
    let (word_start, word_end, ranged) = match opened {
        // The whole quoted word: the quote must close right after it.
        Some(quote) if chars.get(end) == Some(&'"') => (quote, end + 1, false),
        // Part of a longer quoted word: the value is spliced into that word.
        _ if inside_double_quotes(&chars[..start]) => return false,
        _ => (start, end, true),
    };
    let boundary = |character: Option<&char>, operators: &[char]| {
        character.is_none_or(|character| {
            character.is_ascii_whitespace() || operators.contains(character)
        })
    };
    let range = |from: usize| ranged && chars.get(from..from + 2) == Some(&['.', '.'][..]);
    let before = word_start.checked_sub(1).and_then(|at| chars.get(at));
    let after_range = word_start >= 2 && range(word_start - 2);
    (boundary(before, &[';', '|', '&', '(']) || after_range)
        && (boundary(chars.get(word_end), &[';', '|', '&', ')']) || range(word_end))
}

fn body_character(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || matches!(
            character,
            ' ' | '-' | '_' | '.' | '/' | ':' | '=' | '%' | '~' | '^' | '@'
        )
}

/// `--verify`, `--short[=N]` and `-q` around exactly one revision, or one
/// `HEAD`-relative revision alone.
fn rev_parse(arguments: &[&str]) -> bool {
    let mut single = false;
    let mut operands = Vec::new();
    for argument in arguments {
        match *argument {
            "--verify" | "--short" => single = true,
            "-q" | "--quiet" => {}
            short if short.strip_prefix("--short=").is_some_and(digits) => single = true,
            operand if !operand.starts_with('-') => operands.push(operand),
            _ => return false,
        }
    }
    match operands.as_slice() {
        [operand] if single => revision(operand),
        [operand] if arguments.len() == 1 => head_relative(operand) || named(operand),
        [operand] => head_relative(operand),
        _ => false,
    }
}

/// `-1` and one hash format, revisions, and paths after `--`.
fn log(arguments: &[&str]) -> bool {
    let (mut count, mut format, mut paths) = (false, false, false);
    for argument in arguments {
        if paths {
            if argument.starts_with('-') {
                return false;
            }
            continue;
        }
        match *argument {
            "--" => paths = true,
            "-1" | "-n1" | "--max-count=1" if !count => count = true,
            "--first-parent" | "--no-merges" => {}
            option if hash_format(option) && !format => format = true,
            abbrev if abbrev.strip_prefix("--abbrev=").is_some_and(digits) => {}
            operand if revision(operand) => {}
            _ => return false,
        }
    }
    count && format
}

fn hash_format(option: &str) -> bool {
    let Some(value) = option
        .strip_prefix("--format=")
        .or_else(|| option.strip_prefix("--pretty="))
    else {
        return false;
    };
    let value = value
        .strip_prefix("format:")
        .or_else(|| value.strip_prefix("tformat:"))
        .unwrap_or(value);
    matches!(value, "%h" | "%H")
}

/// A revision spelled with ref characters: no option, no absolute path, no
/// range.
fn revision(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with('-')
        && !word.starts_with('/')
        && !word.contains("..")
        && !word.contains('=')
        && !word.contains('%')
}

/// `HEAD` or `@`, then any `~N` / `^N` steps.
fn head_relative(word: &str) -> bool {
    let Some(rest) = word.strip_prefix("HEAD").or_else(|| word.strip_prefix('@')) else {
        return false;
    };
    steps(rest)
}

/// A branch, tag or remote-tracking ref (`origin/main`, `FETCH_HEAD`,
/// `v1.2`), then any `~N` / `^N` steps. Git refuses a ref name with a
/// component that is empty, starts with `.` or ends in `.lock`, so the word
/// names no dotfile, home path or absolute path.
fn named(word: &str) -> bool {
    let (name, rest) = word.split_at(word.find(['~', '^']).unwrap_or(word.len()));
    steps(rest)
        && revision(name)
        && !name.contains([':', '@'])
        && name
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

/// The revision a quoted `'REV^{commit}'` or `'REV^{}'` peels to a commit.
/// The quotes keep the braces from the shell; the word printed back when the
/// lookup misses is the same text without them.
fn peeled(word: &str) -> Option<&str> {
    let quoted = ['\'', '"']
        .into_iter()
        .find_map(|quote| word.strip_prefix(quote)?.strip_suffix(quote))?;
    quoted
        .strip_suffix("^{commit}")
        .or_else(|| quoted.strip_suffix("^{}"))
}

/// Nothing but `~N` / `^N` steps.
fn steps(mut rest: &str) -> bool {
    while let Some(after) = rest.strip_prefix(['~', '^']) {
        rest = after.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    rest.is_empty()
}

fn digits(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|c| c.is_ascii_digit())
}

/// Whether the end of `prefix` sits inside double quotes.
fn inside_double_quotes(prefix: &[char]) -> bool {
    let (mut single, mut double, mut escaped) = (false, false, false);
    for &character in prefix {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            _ => {}
        }
    }
    double
}

#[cfg(test)]
#[path = "chain_literals_git_value_tests.rs"]
mod tests;
