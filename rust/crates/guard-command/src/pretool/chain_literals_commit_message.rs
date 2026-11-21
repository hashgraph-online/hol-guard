//! A commit message read from a quoted heredoc, whatever characters it uses.
//!
//! `git commit -m "$(cat <<'EOF' ... EOF)"` is how agents write a multi-line
//! commit message. The projection writes the message in place of the
//! substitution, so it refuses a message holding a character that would end
//! the double-quoted word, reopen the shell or read as a glob to the screens
//! downstream, and anything outside ASCII. Ordinary messages hold all of
//! those: a function name in backticks, `a[key]`, `"\n"`, an em dash. Such a
//! commit went to review although the shell never reads its message as
//! anything but data.
//!
//! Git only ever reads the value of `-m` or `--message` as the message, never
//! as a path, a pattern or an option. In that one place the projection keeps
//! the message and writes each character it may not carry as `_`, so no
//! character in the projected command can be read as syntax and the command
//! judged runs the same program with the same options. Every other use of a
//! heredoc value keeps the refusal.

use crate::shell_structure::ShellCommandSubstitution;

/// What a character the projection may not carry becomes in a message.
pub(super) const STAND_IN: char = '_';

/// Whether `substitution` is the whole value of `git commit`'s `-m` or
/// `--message`: its command begins `git commit`, every word after that but
/// the last is a flag known to take no value, and the last one, set apart by
/// a blank, is `-m` or `--message`. A flag that takes a value, a repeated
/// `-m` or `--` would make Git read the substitution as that value or as a
/// path, so each refuses.
///
/// `chars` is the heredoc-masked command. Quotes are followed so an operator
/// inside a quoted word does not start a command. An earlier substitution in
/// the same command refuses, since its value is not a word read here.
pub(super) fn message_slot(
    chars: &[char],
    spans: &[ShellCommandSubstitution],
    substitution: &ShellCommandSubstitution,
) -> bool {
    let Some(opens) = substitution.start.checked_sub(1) else {
        return false;
    };
    if chars.get(opens) != Some(&'"')
        || !opens
            .checked_sub(1)
            .and_then(|before| chars.get(before))
            .is_some_and(|before| *before == ' ' || *before == '\t')
    {
        return false;
    }
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut begins = 0usize;
    for (at, &character) in chars.iter().enumerate().take(opens) {
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
    if single
        || double
        || escaped
        || spans
            .iter()
            .any(|span| span.start < opens && span.end > begins)
    {
        return false;
    }
    let segment: String = chars[begins..opens].iter().collect();
    let words: Vec<&str> = segment.split_whitespace().collect();
    let [git, commit, flags @ ..] = words.as_slice() else {
        return false;
    };
    let [before @ .., last] = flags else {
        return false;
    };
    *git == "git"
        && *commit == "commit"
        && (*last == "-m" || *last == "--message")
        && before.iter().all(|flag| valueless_flag(flag))
}

/// `git commit` options that never take the next word as their value.
const VALUELESS_LONG: [&str; 16] = [
    "--all",
    "--allow-empty",
    "--allow-empty-message",
    "--amend",
    "--edit",
    "--gpg-sign",
    "--no-edit",
    "--no-gpg-sign",
    "--no-post-rewrite",
    "--no-signoff",
    "--no-verify",
    "--quiet",
    "--reset-author",
    "--signoff",
    "--verbose",
    "--verify",
];

/// A flag known to take no value, such as `-a`, `-as`, `-S` or `--amend`.
/// Short flags may be grouped; `-S` stands alone, since a letter after it is
/// its key.
fn valueless_flag(word: &str) -> bool {
    if VALUELESS_LONG.contains(&word) || word == "-S" {
        return true;
    }
    word.strip_prefix('-').is_some_and(|letters| {
        !letters.is_empty()
            && letters
                .bytes()
                .all(|letter| matches!(letter, b'a' | b'e' | b'n' | b'q' | b's' | b'v'))
    })
}

/// The message as the projection writes it: each character `carried`
/// refuses becomes `_`.
pub(super) fn projected(body: &str, carried: impl Fn(char) -> bool) -> String {
    body.chars()
        .map(|character| {
            if carried(character) {
                character
            } else {
                STAND_IN
            }
        })
        .collect()
}
