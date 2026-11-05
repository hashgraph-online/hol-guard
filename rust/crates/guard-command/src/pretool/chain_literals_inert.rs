//! `cd "$(mktemp -d)" && node ../src/cli.js list` or `echo "$(date +%F)"`
//! substitute a command whose only effect is the value it prints. The
//! canonical parser models no substitution, so the whole chain could not be
//! evaluated. When every substitution is such a value producer, and each one
//! is allowed as its own command, the value is written as a fixed stand-in
//! and the rest of the chain is judged on its literal words.
//!
//! A stand-in never names more than the real value could: a temporary path
//! becomes an absolute path under a root that does not exist, so it is never
//! inside the workspace, a temporary root or a writable target, and a date
//! becomes a plain name with no path, glob or option meaning. Literal text
//! around a substitution stays in place for the sensitive-path screens.
//! Anything else returns `None`, so the substitution stays opaque.
//!
//! That holds while the value is read as a whole word. A word that also
//! carries a pattern character is not projected at all: the stand-in's own
//! spelling decides what the pattern matches, so a proof that walks the
//! projected pattern would answer for a different set of files than the
//! shell's. `rg TODO -g "$(date +%Y)*"` projects to a pattern matching
//! nothing while the real one matches every name beginning with the year,
//! `2026-prod.env` among them.
//!
//! One substitution is read as a value rather than approximated by a
//! stand-in: `"$(cat <<'EOF' ... EOF)"`, the shape an agent writes to hand a
//! multi-line commit message to `git commit -m`. A quoted delimiter makes the
//! body literal data and a bare `cat` prints it unchanged, so the message
//! itself is written into the projection and the screens downstream read the
//! words the shell passes. It is recognised only as a whole double-quoted
//! word, where the value is neither split nor matched, and only when the body
//! spells nothing that could reopen the shell.
//!
//! A line break between commands separates them as `;` does. A heredoc body
//! is not shell text: one with a quoted delimiter (`<<'EOF'`, `<<"EOF"`) is
//! literal data, so the backticks and `$(` of a script it carries are never
//! substitutions, while one with an unquoted delimiter would expand them, so
//! any substitution there keeps the command opaque. So does a heredoc that
//! never closes or that the shared heredoc parser cannot read (`<<\EOF`).

use super::MAX_COMMAND_CHARS;
use crate::shell_structure::{
    extract_command_substitution_spans, extract_heredocs, mask_heredoc_bodies,
    ShellCommandSubstitution,
};

/// Absent root of the temporary-path stand-in.
const TEMPORARY_ROOT: &str = "/hol-guard-substituted";
/// Stand-in for the fresh path `mktemp` prints.
pub(super) const TEMPORARY_VALUE: &str = "/hol-guard-substituted/temporary-path";
/// Stand-in for the digits and separators a bounded `date` format prints.
pub(super) const DATE_VALUE: &str = "hol-guard-substituted-date";

const MAX_SUBSTITUTIONS: usize = 8;
const MAX_BODY_CHARS: usize = 128;
/// The longest heredoc a `cat` substitution may print. A commit message runs
/// to a few paragraphs; anything longer is not the form this models.
const MAX_HEREDOC_VALUE_CHARS: usize = 4096;

/// Conversions that print only digits, `-` or `:`, never a space, a letter
/// or a path separator.
const DATE_CONVERSIONS: &str = "FHMSTYdjmsuwy";

/// The command with every command substitution replaced by its stand-in;
/// `None` when any substitution is not a known value producer, `allowed`
/// refuses its text as a command of its own, or a temporary path could be
/// steered (`TMPDIR`) or climbed out of (`..`).
pub(crate) fn project(command: &str, allowed: impl Fn(&str) -> bool) -> Option<String> {
    if !command.is_ascii()
        || command.len() > MAX_COMMAND_CHARS
        || command
            .bytes()
            .any(|b| b.is_ascii_control() && !matches!(b, b'\t' | b'\n'))
    {
        return None;
    }
    let (substitutions, masked) = substitution_spans(command)?;
    if substitutions.is_empty() || substitutions.len() > MAX_SUBSTITUTIONS {
        return None;
    }
    let chars: Vec<char> = command.chars().collect();
    let masked: Vec<char> = masked.chars().collect();
    // Each substitution's own text, replaced by a character that is neither a
    // pattern nor a word break. The word around a substitution is read from
    // this: what the substitution prints is one value, so a `[` the inner
    // command spells is never a pattern the shell expands around it.
    let mut patterned = masked.clone();
    for substitution in &substitutions {
        for character in patterned
            .iter_mut()
            .take(substitution.body_end.min(masked.len()))
            .skip(substitution.body_start.min(masked.len()))
        {
            *character = 'x';
        }
    }
    let mut out = String::with_capacity(command.len());
    // The projection's shell text, heredoc bodies still blanked.
    let mut shell = String::with_capacity(command.len());
    let mut cursor = 0usize;
    let mut judged: Vec<String> = Vec::new();
    let mut temporary = false;
    for substitution in &substitutions {
        let (open, close) = match substitution.kind {
            "dollar" => ("$(", ")"),
            _ => ("`", "`"),
        };
        if substitution.start < cursor || patterned_word(&patterned, substitution) {
            return None;
        }
        let (value, judged_text) = match heredoc_value(&chars, substitution) {
            // The heredoc is the whole of what the `cat` reads, so judging
            // the bare `cat` is judging the command the shell runs.
            Some(value) => (value, "cat".to_owned()),
            None => {
                let text: String = chars
                    .get(substitution.start..substitution.end)?
                    .iter()
                    .collect();
                let inner = text
                    .strip_prefix(open)
                    .and_then(|rest| rest.strip_suffix(close))?;
                if inner.trim() != substitution.body {
                    return None;
                }
                (
                    stand_in(&substitution.body)?.to_owned(),
                    substitution.body.clone(),
                )
            }
        };
        if !judged.contains(&judged_text) {
            judged.push(judged_text);
        }
        temporary |= value == TEMPORARY_VALUE;
        out.extend(&chars[cursor..substitution.start]);
        out.push_str(&value);
        shell.extend(&masked[cursor..substitution.start]);
        cursor = substitution.end;
    }
    out.extend(&chars[cursor..]);
    shell.extend(&masked[cursor..]);
    // A substitution the scan did not delimit is still in the text.
    if shell.contains("$(") || shell.contains('`') {
        return None;
    }
    if temporary
        && (command.contains("..")
            || command.contains("TMPDIR")
            || std::fs::symlink_metadata(TEMPORARY_ROOT).is_ok())
    {
        return None;
    }
    judged
        .iter()
        .all(|text| allowed(text.as_str()))
        .then_some(out)
}

/// The literal text a `$(cat <<'EOF' ... EOF)` prints, when that is the whole
/// of the substitution and it stands alone inside double quotes.
///
/// A heredoc with a quoted delimiter is literal data, and a bare `cat` prints
/// what it reads unchanged, so the value is known here exactly rather than
/// approximated. The text is therefore written in place of the substitution as
/// it is, not as a stand-in: every screen downstream then reads the words the
/// shell itself would pass.
///
/// That holds only inside the double quotes. There the value is one word and
/// nothing in it is split, matched or expanded, so its characters reach the
/// program as they are written. Unquoted, the same value would be split on
/// whitespace and matched as a pattern, so the form is not recognised there.
///
/// The outer heredoc scan steps over a command substitution whole, so the
/// heredoc inside one is read from the substitution's own text. Everything
/// outside that heredoc has to be the word `cat` and whitespace, which leaves
/// nowhere for a second `<<`, a redirect or another command to hide.
fn heredoc_value(chars: &[char], substitution: &ShellCommandSubstitution) -> Option<String> {
    if substitution.kind != "dollar" || !double_quoted_word(chars, substitution) {
        return None;
    }
    let inner: String = chars
        .get(substitution.body_start..substitution.body_end)?
        .iter()
        .collect();
    let length = inner.chars().count();
    let heredocs = extract_heredocs(&inner);
    let [heredoc] = &heredocs[..] else {
        return None;
    };
    // A body that runs to the end never met its delimiter, so the text the
    // `cat` reads is not the text here.
    if !heredoc.quoted || heredoc.strip_tabs || heredoc.body_end >= length {
        return None;
    }
    let inner: Vec<char> = inner.chars().collect();
    // `cat`, then the operator, then nothing but the body and its delimiter.
    if text_between(&inner, 0, heredoc.operator_start)?.trim() != "cat"
        || !text_between(&inner, heredoc.declaration_end, heredoc.body_start)?
            .chars()
            .all(char::is_whitespace)
        || !text_between(&inner, heredoc.end, length)?
            .chars()
            .all(char::is_whitespace)
    {
        return None;
    }
    let body = &heredoc.body;
    if body.chars().count() > MAX_HEREDOC_VALUE_CHARS
        || !body.chars().all(|character| {
            (character == '\n' || character == ' ' || character.is_ascii_graphic())
                && !matches!(
                    character,
                    '"' | '\'' | '`' | '$' | '\\' | '*' | '?' | '[' | ']' | '{' | '}' | '~'
                )
        })
    {
        return None;
    }
    // A substitution drops every line break at the end of what it read.
    Some(body.trim_end_matches('\n').to_owned())
}

/// Whether the substitution is the whole of one double-quoted word, so its
/// value stands where the substitution stood and the shell neither splits
/// nor globs it.
fn double_quoted_word(chars: &[char], substitution: &ShellCommandSubstitution) -> bool {
    let Some(opens) = substitution.start.checked_sub(1) else {
        return false;
    };
    // Which quote opens the word is the shell's own state, not the character
    // in front of the substitution. `" "$(...)" "` puts a `"` there too, but
    // that one closes a quoted space and leaves the substitution unquoted, so
    // its value would be spliced in as code rather than as one word.
    let (mut single, mut double, mut escaped, mut opened_at) = (false, false, false, None);
    for (at, &character) in chars[..substitution.start].iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => {
                double = !double;
                opened_at = double.then_some(at);
            }
            _ => {}
        }
    }
    if !double || opened_at != Some(opens) || chars.get(substitution.end) != Some(&'"') {
        return false;
    }
    let before = opens
        .checked_sub(1)
        .map(|at| chars[at])
        .is_none_or(|character| character.is_ascii_whitespace());
    let after = chars
        .get(substitution.end + 1)
        .is_none_or(|character| character.is_ascii_whitespace());
    before && after
}

/// The text between two character offsets, or `None` when either is out of
/// range or they are the wrong way round.
fn text_between(chars: &[char], from: usize, to: usize) -> Option<String> {
    (from <= to)
        .then(|| chars.get(from..to))
        .flatten()
        .map(|slice| slice.iter().collect())
}

/// The command substitutions the shell runs in `command`, read with every
/// heredoc body blanked, and that blanked text, which keeps each character's
/// index. `None` when a heredoc never closes, a `<<` is not a heredoc the
/// shared parser reads, or a body with an unquoted delimiter would expand a
/// substitution.
pub(super) fn substitution_spans(command: &str) -> Option<(Vec<ShellCommandSubstitution>, String)> {
    let heredocs = extract_heredocs(command);
    let masked = mask_heredoc_bodies(command, &heredocs);
    let operators = crate::shell_structure::heredoc_operators(&masked);
    let length = command.chars().count();
    let unsafe_body = heredocs.iter().any(|heredoc| {
        heredoc.body_end >= length
            || (!heredoc.quoted && (heredoc.body.contains("$(") || heredoc.body.contains('`')))
    });
    if operators != heredocs.len() || unsafe_body {
        return None;
    }
    Some((extract_command_substitution_spans(&masked), masked))
}

/// Whether the shell word holding `substitution` also carries a pattern
/// character.
///
/// The stand-in stands for the value, not for the set of names the value
/// would match. A proof that walks the projected pattern walks the stand-in's
/// spelling, so it answers for files the shell would never reach and misses
/// the ones it would. Word boundaries here are whitespace: quoting does not
/// matter, because the patterns that reach a tool as an argument (`rg -g`,
/// `find -name`) are the quoted ones.
fn patterned_word(chars: &[char], substitution: &ShellCommandSubstitution) -> bool {
    let start = chars[..substitution.start.min(chars.len())]
        .iter()
        .rposition(|c| c.is_ascii_whitespace())
        .map_or(0, |at| at + 1);
    let end = chars
        .get(substitution.end..)
        .and_then(|rest| rest.iter().position(|c| c.is_ascii_whitespace()))
        .map_or(chars.len(), |at| substitution.end + at);
    chars[start..end]
        .iter()
        .any(|c| matches!(c, '*' | '?' | '[' | '{'))
}

/// The stand-in for a substitution body that is one simple value-producing
/// command with literal arguments.
fn stand_in(body: &str) -> Option<&'static str> {
    if body.len() > MAX_BODY_CHARS
        || !body.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '+' | '%' | '_' | ':' | '.' | '-')
        })
    {
        return None;
    }
    let words: Vec<&str> = body.split(' ').filter(|word| !word.is_empty()).collect();
    match words.split_first()? {
        (&"mktemp", arguments) => temporary_arguments(arguments).then_some(TEMPORARY_VALUE),
        (&"date", arguments) => date_arguments(arguments).then_some(DATE_VALUE),
        _ => None,
    }
}

/// `-d`, `-q` and `-t` in any grouping and at most one template naming a
/// unique leaf: no directory, no `-p` / `--tmpdir`, no dry-run `-u`.
fn temporary_arguments(arguments: &[&str]) -> bool {
    let mut template = false;
    for argument in arguments {
        if let Some(flags) = argument.strip_prefix('-') {
            if flags.is_empty() || !flags.chars().all(|c| matches!(c, 'd' | 'q' | 't')) {
                return false;
            }
        } else if template
            || !argument.ends_with("XXX")
            || !argument
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return false;
        } else {
            template = true;
        }
    }
    true
}

/// Optional `-u` and exactly one `+FORMAT` that starts with a conversion,
/// so the value never starts with `-`, and whose literal text is digits and
/// separators, so it can never spell a name such as `.env`.
fn date_arguments(arguments: &[&str]) -> bool {
    let mut format = None;
    for argument in arguments {
        if *argument == "-u" {
            continue;
        }
        match argument.strip_prefix('+') {
            Some(text) if format.is_none() => format = Some(text),
            _ => return false,
        }
    }
    let Some(format) = format.filter(|format| format.starts_with('%')) else {
        return false;
    };
    let mut chars = format.chars();
    while let Some(c) = chars.next() {
        let printed = match c {
            '%' => chars
                .next()
                .is_some_and(|conversion| DATE_CONVERSIONS.contains(conversion)),
            c => c.is_ascii_digit() || matches!(c, '-' | '_' | ':' | '.' | 'T' | 'Z'),
        };
        if !printed {
            return false;
        }
    }
    true
}

#[path = "chain_literals_temp_cd.rs"]
pub(crate) mod temp_cd;

#[cfg(test)]
#[path = "chain_literals_inert_tests.rs"]
mod tests;
