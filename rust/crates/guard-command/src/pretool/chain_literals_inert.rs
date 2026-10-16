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

/// Conversions that print only digits, `-` or `:`, never a space, a letter
/// or a path separator.
const DATE_CONVERSIONS: &str = "FHMSTYdjmsuwy";

/// The command with every command substitution replaced by its stand-in;
/// `None` when any substitution is not a known value producer, `allowed`
/// refuses its text as a command of its own, or a temporary path could be
/// steered (`TMPDIR`) or climbed out of (`..`).
pub(super) fn project(command: &str, allowed: impl Fn(&str) -> bool) -> Option<String> {
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
    let mut out = String::with_capacity(command.len());
    // The projection's shell text, heredoc bodies still blanked.
    let mut shell = String::with_capacity(command.len());
    let mut cursor = 0usize;
    let mut judged: Vec<&str> = Vec::new();
    let mut temporary = false;
    for substitution in &substitutions {
        let (open, close) = match substitution.kind {
            "dollar" => ("$(", ")"),
            _ => ("`", "`"),
        };
        if substitution.start < cursor || patterned_word(&chars, substitution) {
            return None;
        }
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
        let value = stand_in(&substitution.body)?;
        if !judged.contains(&substitution.body.as_str()) {
            judged.push(&substitution.body);
        }
        temporary |= value == TEMPORARY_VALUE;
        out.extend(&chars[cursor..substitution.start]);
        out.push_str(value);
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
    judged.into_iter().all(allowed).then_some(out)
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
