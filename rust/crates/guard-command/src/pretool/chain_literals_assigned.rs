//! A value an assignment keeps: `head=$(git rev-parse HEAD); git log -1 "$head"`.
//!
//! An agent names a value once and reuses it, exactly as it names a literal
//! (see the module above). The projection read a substitution only where its
//! value lands: an argument of a Git command, a printed label, a temporary
//! directory. As the value of an assignment it landed nowhere it knew, so the
//! whole chain could not be evaluated and blocked with no approval left to
//! give, even when every program it runs is allowed on its own.
//!
//! One standalone assignment is read at a time. Its substitution is judged as
//! a command of its own, and written in place of the assignment, where it
//! runs as the same single pipeline, so rules that read the chain in order
//! still see it there. Each
//! later `$NAME` or `${NAME}` is then written as the substitution itself, so
//! the slot it fills is judged by the same rules as the substitution written
//! there directly, or, as the argument of an `echo`, as the printed stand-in
//! (the value is what the judged command already printed). A use no slot
//! reads keeps the chain opaque, as before.
//!
//! Writing the substitution at the use runs it later than the shell does, so
//! the read is refused when anything between the assignment and the last such
//! use could change what it runs or reads: a `cd`, an alias, a function, an
//! assignment to a name the shell or a program reads for itself. The command
//! the value comes from is judged where it runs: on its own, or behind the
//! commands that came before it when one of those steers.
//!
//! The read is refused, and the chain keeps its old reading, when:
//!
//! - the assignment is not a whole list item of its own, run after the start
//!   of the text, `;`, a line break or `&&`, and followed by one of those;
//! - anything ahead of it groups or loops, so it may run more than once or
//!   not at all (`(`, `{`, a loop or conditional keyword);
//! - the name is one the shell or a program reads for itself, or names a
//!   credential, or with capitals, one a program reads to choose what it
//!   runs (see [`plain_name`]);
//! - the substitution expands anything but a literal an earlier assignment
//!   bound (written out as the literal projection writes it, bare when the
//!   shell reads it the same way bare), nests a
//!   substitution, reads a heredoc, spans lines or holds an unquoted pattern
//!   character (`*`, `?`, `[`);
//! - the name appears anywhere except as `$NAME` or `${NAME}` after the
//!   assignment and while it holds: assigned again, modified, sliced, escaped,
//!   inside another substitution or a heredoc body;
//! - the text has a comment or `$'...'` quoting, whose quotes this scan does
//!   not read as the shell does.

use super::{display, line_number, ShellCommandSubstitution};

#[path = "chain_literals_assigned_scan.rs"]
mod scan;
use scan::{
    assignment_name, command_begins, commented_or_dollar_quoted, echoed, expands, expansion,
    list_end, listed, occurrences, one_pipeline, operator_after, operator_before, plain_ahead,
    plain_quotes_dropped, single_quoted, steers, words,
};

/// Parts of a name a program reads from its environment to choose another
/// program, a file, a directory, a library or the options it runs with:
/// `LESS`, `MANPAGER`, `PERL5OPT`, `FZF_DEFAULT_COMMAND`, `SSL_CERT_FILE`,
/// `MALLOC_CONF`, Windows' `USERPROFILE` and `COMSPEC`.
const STEERING_MARKERS: &str =
    "APPDATA ASKPASS COMMAND COMSPEC CONFIG CURL DIR EDITOR EXEC FILE GCM GPG HOME HOOK INIT LESS \
    LIB LV MALLOC MORE OPT PAGER PATH PRELOAD PROFILE PROG SHELL SOCK SSL STARTUP SYSTEMROOT";

/// A name a chain may set for its own later words. A lowercase name is one
/// no program reads from its environment, so [`super::super::ordinary_name`]
/// decides it. A name with capitals may already be exported, and then the
/// assignment reaches every program the chain starts, so it must also carry
/// no part of a name programs read to choose what they run.
pub(crate) fn plain_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    super::super::ordinary_name(name)
        && (!name.bytes().any(|byte| byte.is_ascii_uppercase())
            || !STEERING_MARKERS
                .split_ascii_whitespace()
                .any(|marker| upper.contains(marker)))
}

/// The longest substitution read as an assigned value.
const MAX_BODY_CHARS: usize = 256;

/// One assignment read out of a chain.
pub(super) struct Inlined {
    /// The chain with the assigned command in place of the assignment, each
    /// later expansion of its name written as the substitution or, after
    /// `echo`, as a printed stand-in.
    pub(super) text: String,
    /// The command the value comes from, as the shell runs it.
    pub(super) judged: String,
}

/// The first standalone assignment of a substitution that can be read out of
/// `command`; `None` when none can.
pub(super) fn inline_one(command: &str) -> Option<Inlined> {
    let (spans, masked) = super::substitution_spans(command)?;
    let chars: Vec<char> = command.chars().collect();
    let masked: Vec<char> = masked.chars().collect();
    if chars.len() != masked.len() || commented_or_dollar_quoted(&masked, &spans) {
        return None;
    }
    spans
        .iter()
        .find_map(|span| inline_span(&chars, &masked, &spans, span))
}

struct Assignment {
    name: String,
    /// The substitution's text, each literal an earlier assignment bound
    /// written out.
    body: String,
    /// The substitution's text as written, left for the literal projection
    /// to fill in where the command runs.
    raw: String,
    name_start: usize,
    value_end: usize,
    /// The operator ahead of the assignment, when it is `&&`, `;` or a line
    /// break: its first character and whether it is `&&`.
    before: Option<(usize, bool)>,
}

fn inline_span(
    chars: &[char],
    masked: &[char],
    spans: &[ShellCommandSubstitution],
    span: &ShellCommandSubstitution,
) -> Option<Inlined> {
    let assignment = assignment(chars, masked, spans, span)?;
    let scope_end = if assignment.before.is_some_and(|(_, and)| and) {
        list_end(masked, spans, assignment.value_end)
    } else {
        masked.len()
    };
    let substitution = format!("$({})", assignment.body);
    let begins = command_begins(masked, spans);
    let literal = single_quoted(masked, spans);
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut last_inlined = assignment.value_end;
    for at in occurrences(chars, &assignment.name) {
        if at == assignment.name_start {
            continue;
        }
        if at <= assignment.value_end
            || at >= scope_end
            || spans.iter().any(|span| span.start <= at && at < span.end)
            || literal[at]
        {
            return None;
        }
        let (start, end) = expansion(chars, at, assignment.name.len())?;
        if echoed(masked, spans, begins[start], start) {
            edits.push((start, end, display::DISPLAY_VALUE.to_owned()));
        } else {
            edits.push((start, end, substitution.clone()));
            last_inlined = last_inlined.max(end);
        }
    }
    // A name the masked text does not show is in a heredoc body.
    if occurrences(masked, &assignment.name).len() != occurrences(chars, &assignment.name).len() {
        return None;
    }
    if steers(masked, spans, assignment.value_end, last_inlined) {
        return None;
    }
    // A capitalised name may already be exported, and then the assignment
    // reaches every program the rest of the chain starts. The rewrite drops
    // it, so it holds only when none of them could read it.
    if assignment
        .name
        .bytes()
        .any(|byte| byte.is_ascii_uppercase())
        && !exported_name_unread(masked, spans, assignment.value_end)
    {
        return None;
    }
    let judged = if steers(masked, spans, 0, assignment.name_start) {
        if spans
            .iter()
            .any(|other| other.start < assignment.name_start)
        {
            return None;
        }
        let prefix: String = chars[..assignment.name_start].iter().collect();
        format!("{prefix}{}", assignment.body)
    } else {
        assignment.body.clone()
    };
    // The assigned command stays where it ran, so every rule that reads the
    // chain in order, Git's read floor among them, still sees it there. It is
    // written as typed: the literal projection then fills in the literals it
    // reads and drops their assignments, as it does for any other command.
    edits.push((
        assignment.name_start,
        assignment.value_end,
        assignment.raw.clone(),
    ));
    edits.sort_unstable_by_key(|edit| edit.0);
    let mut text = String::with_capacity(chars.len());
    let mut cursor = 0;
    for (start, end, replacement) in edits {
        text.extend(&chars[cursor..start]);
        text.push_str(&replacement);
        cursor = end;
    }
    text.extend(&chars[cursor..]);
    Some(Inlined {
        text: text.trim().to_owned(),
        judged,
    })
}

/// The standalone assignment `span` is the whole value of.
fn assignment(
    chars: &[char],
    masked: &[char],
    spans: &[ShellCommandSubstitution],
    span: &ShellCommandSubstitution,
) -> Option<Assignment> {
    let raw = span.body.as_str();
    if span.kind != "dollar"
        || raw.is_empty()
        || !raw.is_ascii()
        || raw.contains(['\n', '\r'])
        || raw.contains("<<")
        || raw.chars().any(|c| c.is_control())
    {
        return None;
    }
    let body = if expands(raw) {
        // Only a literal an earlier assignment bound, as in
        // `repo=example-org/widgets; t=$(gh pr view 7 --repo "$repo")`.
        if spans.iter().any(|other| other.start < span.start) {
            return None;
        }
        let prefix: String = chars[..span.start].iter().collect();
        let prefix = &prefix[..prefix.rfind([';', '&', '\n'])? + 1];
        resolved(prefix, raw)?
    } else {
        raw.to_owned()
    };
    let body = body.as_str();
    if body.len() > MAX_BODY_CHARS || !one_pipeline(body) || changes_shell(body) {
        return None;
    }
    // A temporary path or a date already has a stand-in the chain reads.
    if super::stand_in(body).is_some_and(|value| {
        value != super::git_value::COMMIT_VALUE && value != line_number::LINE_VALUE
    }) {
        return None;
    }
    let quoted = span.start > 0 && masked[span.start - 1] == '"';
    let (head_end, value_end) = if quoted {
        (masked.get(span.end) == Some(&'"')).then_some((span.start - 1, span.end + 1))?
    } else {
        (span.start, span.end)
    };
    if head_end == 0 || masked[head_end - 1] != '=' {
        return None;
    }
    let name_end = head_end - 1;
    let name_start = masked[..name_end]
        .iter()
        .rposition(|c| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map_or(0, |at| at + 1);
    let name: String = masked[name_start..name_end].iter().collect();
    if name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) || !plain_name(&name) {
        return None;
    }
    if !plain_ahead(masked, spans, name_start) {
        return None;
    }
    let before = operator_before(masked, name_start)?;
    operator_after(masked, value_end)?;
    Some(Assignment {
        name,
        body: body.to_owned(),
        raw: raw.to_owned(),
        name_start,
        value_end,
        before,
    })
}

/// `body` with each expansion of a literal bound in `prefix`, the chain up
/// to and including the operator ahead of the assignment, written out as the
/// literal projection would write it there; `None` when anything else would
/// still expand.
fn resolved(prefix: &str, body: &str) -> Option<String> {
    let unchanged = format!("{prefix} true");
    let written = super::super::substitute(&unchanged).unwrap_or(unchanged);
    let written = written.strip_suffix(" true")?;
    let joined = super::super::substitute(&format!("{prefix} {body}"))?;
    let value = joined.strip_prefix(written)?.strip_prefix(' ')?;
    (!expands(value)).then(|| plain_quotes_dropped(value))
}

/// Whether a substitution's body, run in the parent shell where it is
/// written in place of its assignment, could change that shell: a stage
/// that starts with a steering word such as `cd` or `export`, a group, or an
/// assignment. Inside `$(...)` each stays in the substitution's own subshell.
fn changes_shell(body: &str) -> bool {
    let chars: Vec<char> = body.chars().collect();
    let begins = command_begins(&chars, &[]);
    let mut starts = begins.clone();
    starts.dedup();
    starts.iter().any(|&start| {
        let end = begins
            .iter()
            .rposition(|&begin| begin == start)
            .map_or(start, |at| at + 1);
        words(&chars, &[], start, end).is_none_or(|words| {
            words.first().is_some_and(|word| {
                let word = word.replace(['"', '\'', '\\'], "");
                listed(scan::STEERING_WORDS, &word)
                    || matches!(word.as_str(), "(" | ")" | "{" | "}")
                    || word
                        .split_once('=')
                        .is_some_and(|(name, _)| assignment_name(name))
            })
        })
    })
}

/// Programs that start no other program, so a name an earlier step of the
/// chain exported cannot reach code they run.
const ENVIRONMENT_BLIND: &str = "[ cat echo head ls printf tail test true wc";

/// Whether every command from `start` to the end of the text ignores an
/// exported capitalised name: one of [`ENVIRONMENT_BLIND`], or a Git read
/// that starts no hook or helper. Removing such an assignment from the chain
/// then changes nothing a later program reads.
fn exported_name_unread(masked: &[char], spans: &[ShellCommandSubstitution], start: usize) -> bool {
    body_unread(masked, spans, start, 0)
}

/// The most substitutions inside substitutions [`body_unread`] follows.
const MAX_NESTING: usize = 4;

fn body_unread(
    masked: &[char],
    spans: &[ShellCommandSubstitution],
    start: usize,
    depth: usize,
) -> bool {
    if start >= masked.len() {
        return true;
    }
    // A later substitution runs its program in a subshell that inherits the
    // exported name, wherever it sits: a word, an argument or a redirect, so
    // its own commands answer to the same test.
    let later_bodies_unread = spans.iter().filter(|span| span.start >= start).all(|span| {
        let Some(body) = masked.get(span.body_start..span.body_end) else {
            return false;
        };
        let text: String = body.iter().collect();
        let inner = crate::shell_structure::extract_command_substitution_spans(&text);
        depth < MAX_NESTING && body_unread(body, &inner, 0, depth + 1)
    });
    if !later_bodies_unread {
        return false;
    }
    // `${NAME}` is no group, so braces do not end a command here; a group
    // opened with `{` is its own first word and refused below.
    let begins = list_begins(masked, spans);
    let mut starts: Vec<usize> = begins[start..].to_vec();
    starts.dedup();
    starts.iter().all(|&begin| {
        let end = begins
            .iter()
            .rposition(|&other| other == begin)
            .map_or(begin, |at| at + 1);
        let Some(words) = words(masked, spans, begin.max(start), end) else {
            return false;
        };
        let words: Vec<String> = words
            .iter()
            .map(|word| word.replace(['"', '\'', '\\'], ""))
            .skip_while(|word| {
                word.split_once('=')
                    .is_some_and(|(name, _)| assignment_name(name))
            })
            .collect();
        match words.split_first() {
            None => true,
            Some((program, arguments)) if program == "git" => {
                crate::command_compatibility::git_read_starts_no_user_program(arguments)
            }
            Some((program, _)) => listed(ENVIRONMENT_BLIND, program),
        }
    })
}

/// [`command_begins`] without braces: where each command starts, split only
/// at list, pipeline and subshell operators.
fn list_begins(masked: &[char], spans: &[ShellCommandSubstitution]) -> Vec<usize> {
    let (mut single, mut double, mut escaped) = (false, false, false);
    let mut begin = 0;
    let mut begins = Vec::with_capacity(masked.len());
    for (at, &character) in masked.iter().enumerate() {
        begins.push(begin);
        if spans.iter().any(|span| span.start <= at && at < span.end) {
            continue;
        }
        if escaped {
            escaped = false;
        } else if single {
            single = character != '\'';
        } else {
            match character {
                '\\' => escaped = true,
                '\'' if !double => single = true,
                '"' => double = !double,
                ';' | '&' | '|' | '\n' | '(' | ')' if !double => begin = at + 1,
                _ => {}
            }
        }
    }
    begins
}

#[cfg(test)]
#[path = "chain_literals_assigned_tests.rs"]
mod tests;
