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
//! a command of its own, and the assignment is taken out of the chain. Each
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
//!   credential (see [`super::super::ordinary_name`]);
//! - the substitution expands a variable, nests a substitution, reads a
//!   heredoc or spans lines;
//! - the name appears anywhere except as `$NAME` or `${NAME}` after the
//!   assignment and while it holds: assigned again, modified, sliced, escaped,
//!   inside another substitution or a heredoc body;
//! - the text has a comment or `$'...'` quoting, whose quotes this scan does
//!   not read as the shell does.

use super::{display, line_number, ShellCommandSubstitution};

#[path = "chain_literals_assigned_scan.rs"]
mod scan;
use scan::{
    command_begins, commented_or_dollar_quoted, echoed, expands, expansion, list_end, occurrences,
    operator_after, operator_before, plain_ahead, single_quoted, steers,
};

/// The longest substitution read as an assigned value.
const MAX_BODY_CHARS: usize = 256;

/// One assignment read out of a chain.
pub(super) struct Inlined {
    /// The chain without the assignment, each later expansion of its name
    /// written as the substitution or, after `echo`, as a printed stand-in.
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

struct Assignment<'a> {
    name: String,
    body: &'a str,
    name_start: usize,
    value_end: usize,
    /// The operator ahead of the assignment, when it is `&&`, `;` or a line
    /// break: its first character and whether it is `&&`.
    before: Option<(usize, bool)>,
    /// One past the operator after the assignment and its blanks.
    after: Option<usize>,
}

fn inline_span(
    chars: &[char],
    masked: &[char],
    spans: &[ShellCommandSubstitution],
    span: &ShellCommandSubstitution,
) -> Option<Inlined> {
    let assignment = assignment(masked, spans, span)?;
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
        assignment.body.to_owned()
    };
    let removal = match (assignment.before, assignment.after) {
        (Some((operator, true)), _) | (Some((operator, false)), None) => {
            (operator, assignment.value_end)
        }
        (_, Some(after)) => (assignment.name_start, after),
        (None, None) => (assignment.name_start, assignment.value_end),
    };
    edits.push((removal.0, removal.1, String::new()));
    edits.sort_unstable_by_key(|edit| edit.0);
    let mut text = String::with_capacity(chars.len());
    let mut cursor = 0;
    for (start, end, replacement) in edits {
        text.extend(&chars[cursor..start]);
        text.push_str(&replacement);
        cursor = end;
    }
    text.extend(&chars[cursor..]);
    let text = text.trim().to_owned();
    Some(Inlined {
        text: if text.is_empty() {
            "true".to_owned()
        } else {
            text
        },
        judged,
    })
}

/// The standalone assignment `span` is the whole value of.
fn assignment<'a>(
    masked: &[char],
    spans: &[ShellCommandSubstitution],
    span: &'a ShellCommandSubstitution,
) -> Option<Assignment<'a>> {
    let body = span.body.as_str();
    if span.kind != "dollar"
        || body.is_empty()
        || body.len() > MAX_BODY_CHARS
        || !body.is_ascii()
        || body.contains(['\n', '\r'])
        || expands(body)
        || body.contains("<<")
        || body.chars().any(|c| c.is_control())
    {
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
    if name.is_empty()
        || name.starts_with(|c: char| c.is_ascii_digit())
        || !super::super::ordinary_name(&name)
    {
        return None;
    }
    if !plain_ahead(masked, spans, name_start) {
        return None;
    }
    let before = operator_before(masked, name_start)?;
    let after = operator_after(masked, value_end)?;
    Some(Assignment {
        name,
        body,
        name_start,
        value_end,
        before,
        after,
    })
}

#[cfg(test)]
#[path = "chain_literals_assigned_tests.rs"]
mod tests;
