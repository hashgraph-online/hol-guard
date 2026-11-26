//! Assignments the projection no longer needs.
//!
//! Once every use of `f` in `cd src && f=lib/a.ts; sed -n 1,5p $f` is written
//! as the file it names, the assignment itself changes nothing the judged
//! commands see. Kept in the projected text it reads as a step of its own,
//! which the read proofs do not model. It is removed with the list operator
//! that joined it, so the commands around it still run in the same order and
//! under the same conditions: a literal assignment to an ordinary name always
//! succeeds, so `f=v && b` runs `b` exactly when `b` alone would run.

use super::{
    lex::{Stage, Token},
    names_variable,
};

/// Where a list's items and words sit in the command text.
pub(super) struct Layout {
    items: Vec<Item>,
    words: Vec<(usize, usize)>,
}

impl Layout {
    /// `None` when an item has no words to place.
    pub(super) fn of(list: &[(Vec<Stage>, Token)]) -> Option<Self> {
        let items = list
            .iter()
            .map(|(stages, separator)| {
                Some((
                    stages.first()?.first()?.0,
                    stages.last()?.last()?.1,
                    *separator,
                ))
            })
            .collect::<Option<Vec<Item>>>()?;
        let words = list
            .iter()
            .flat_map(|(stages, _)| stages.iter().flatten().copied())
            .collect();
        Some(Self { items, words })
    }

    /// Adds to `edits` the deletions [`removals`] finds, judged against the
    /// words as `edits` already rewrote them, and puts `edits` in order.
    pub(super) fn drop_unused(
        &self,
        chars: &[char],
        candidates: &[(usize, Vec<String>)],
        edits: &mut Vec<(usize, usize, String)>,
    ) {
        let texts: Vec<String> = self
            .words
            .iter()
            .map(|&(start, end)| {
                edits
                    .iter()
                    .find(|edit| edit.0 == start && edit.1 == end)
                    .map_or_else(|| chars[start..end].iter().collect(), |edit| edit.2.clone())
            })
            .collect();
        for (start, end) in removals(&self.items, candidates, &texts) {
            edits.push((start, end, String::new()));
        }
        edits.sort_unstable_by_key(|edit| edit.0);
    }
}

/// One list item: its first and last character, and the operator after it.
pub(super) type Item = (usize, usize, Token);

/// The character ranges to delete: each item in `candidates` (an item that
/// only assigns literal values to ordinary names) whose names no other word
/// still mentions, with the operator that joins it to the list.
pub(super) fn removals(
    items: &[Item],
    candidates: &[(usize, Vec<String>)],
    words: &[String],
) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    // The last item kept, and the operator that now follows it.
    let mut kept: Option<(usize, Token)> = None;
    for (position, &(start, end, separator)) in items.iter().enumerate() {
        let next = items.get(position + 1).map(|item| item.0);
        let unused = candidates.iter().any(|(at, names)| {
            *at == position
                && names
                    .iter()
                    .all(|name| words.iter().filter(|word| mentions(word, name)).count() == 1)
        });
        let range = match (unused, separator, kept, next) {
            (false, ..) => None,
            // `f=v && b` and `a && f=v && b` run `b` as `b` and `a && b` do.
            (true, Token::And, _, Some(next)) => Some((start, next)),
            // `f=v; b` and `a; f=v; b`.
            (true, _, None | Some((_, Token::Sequence)), Some(next)) => Some((start, next)),
            // `a; f=v` and `a && f=v; b`: the list ends with `a`.
            (true, _, Some((before, _)), _) => {
                kept = kept.map(|(end, _)| (end, Token::Sequence));
                Some((before, end))
            }
            (true, ..) => None,
        };
        match range {
            Some(range) => ranges.push(range),
            None => kept = Some((end, separator)),
        }
    }
    merge(ranges)
}

/// Whether `word` names `name`, as a bare word or an expansion.
fn mentions(word: &str, name: &str) -> bool {
    let ident = |c: char| c == '_' || c.is_ascii_alphanumeric();
    names_variable(word, |candidate| candidate == name)
        || word.match_indices('$').any(|(index, _)| {
            let rest = &word[index + 1..];
            let rest = rest.strip_prefix('{').unwrap_or(rest);
            rest.strip_prefix(name)
                .is_some_and(|after| !after.starts_with(ident))
        })
}

fn merge(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}
