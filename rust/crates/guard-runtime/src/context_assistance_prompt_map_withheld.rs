//! Where the prompt's named definitions, and the definitions holding text it
//! quotes, are in files Guard keeps out of the context for what they hold,
//! such as a line its secret check takes for a credential. The map gives each
//! one's lines and name, never the file's text, so the agent opens those
//! lines itself instead of searching for them.
use super::super::sections::written_name;
use super::{file, named_definitions, Asked, Entry, File, Rendered, Sought, HEADER};
use crate::context_assistance_prompt_words::unwrapped;
use std::time::Instant;

const WITHHELD_TITLE: &str = "Definitions this request names or quotes, in files Guard keeps out \
of this context (open these lines yourself):";
/// The most of the note's text: it comes after the map's own budget.
const MAX_WITHHELD_CHARS: usize = 600;

/// `mapped` with the lines of each named definition the files in `withheld`
/// hold and of each definition holding a quoted phrase, or `mapped` as it is
/// when they hold none or `until` passes.
pub(super) fn added(
    mapped: Option<Rendered>,
    withheld: &[(String, String)],
    sought: &[Sought],
    asked: &Asked,
    until: Instant,
) -> Option<Rendered> {
    let names: Vec<(&str, bool)> = (sought.iter())
        .filter(|item| item.name && !item.phrase)
        .map(|item| (item.text.as_str(), true))
        .collect();
    let phrases: Vec<&str> = (sought.iter())
        .filter(|item| item.phrase)
        .map(|item| item.text.as_str())
        .collect();
    if withheld.is_empty() || (names.is_empty() && phrases.is_empty()) {
        return mapped;
    }
    let mut files: Vec<File> = Vec::with_capacity(withheld.len());
    for (path, text) in withheld {
        if Instant::now() >= until {
            return mapped;
        }
        files.push(file(path, text));
    }
    if Instant::now() >= until {
        return mapped;
    }
    // Only a definition the prompt names: with none found, the picker falls
    // back to a named file's unfinished functions, which may be unrelated.
    // Spelled as the prompt writes it: `getLexer` is not `get_lexer`, though
    // both read as the same word. Each file is picked on its own, so one that
    // spells the name another way cannot stand in for one that spells it so.
    let named = |file: &File, at: usize| {
        let own = written_name(file.opening(at));
        own.is_some_and(|own| asked.spellings.contains(&own))
            || asked.spellings.contains(&file.qualified(at))
    };
    let mut entries: Vec<Entry> = Vec::new();
    for file in &files {
        if Instant::now() >= until {
            return mapped;
        }
        let mut found: Vec<usize> = Vec::new();
        if !names.is_empty() {
            let picks = named_definitions(std::slice::from_ref(file), &names, asked, false);
            let picks = picks.into_iter();
            found.extend(
                (picks.filter(|pick| !pick.base && named(file, pick.at))).map(|pick| pick.at),
            );
        }
        // A quote only a withheld file holds: without its place, the map
        // falls back to the quote's words, which point somewhere else.
        for phrase in &phrases {
            // The first match inside a definition: a module docstring that
            // repeats the sentence holds no definition to open.
            let lines = quote_lines(&file.lines, phrase);
            found.extend(lines.into_iter().find_map(|line| holding(file, line)));
        }
        for at in found {
            let section = &file.sections[at];
            let range = format!("{}:{}-{}", file.path, section.start, section.end);
            let entry = format!("{range} {}", file.qualified(at));
            if !entries.iter().any(|known| known.text == entry) {
                entries.push(Entry::plain(entry));
            }
        }
    }
    let mut list: Vec<String> = Vec::new();
    let mut chars = WITHHELD_TITLE.chars().count();
    for entry in entries {
        chars += 1 + entry.text.chars().count();
        if chars > MAX_WITHHELD_CHARS {
            break;
        }
        list.push(entry.text);
    }
    if list.is_empty() {
        return mapped;
    }
    let note = format!("\n\n{WITHHELD_TITLE}\n{}", list.join("\n"));
    Some(match mapped {
        Some(Rendered { text, shown }) => Rendered {
            text: text + &note,
            shown,
        },
        None => Rendered {
            text: format!("{HEADER}{note}"),
            shown: Vec::new(),
        },
    })
}

/// The lines, from 1 and in order, where `phrase` starts in `lines`: on one
/// line, or wrapped over several as the walk's quote check reads them. The
/// walk lowercases both, so the phrase arrives lowercased.
fn quote_lines(lines: &[&str], phrase: &str) -> Vec<usize> {
    let lower: Vec<String> = lines.iter().map(|line| line.to_lowercase()).collect();
    let mut found: Vec<usize> = (lower.iter().enumerate())
        .filter(|(_, line)| line.contains(phrase))
        .map(|(at, _)| at + 1)
        .collect();
    let mut joined = String::new();
    let mut starts: Vec<(usize, usize)> = Vec::new();
    for (at, line) in lower.iter().enumerate() {
        let piece = unwrapped(line);
        if !piece.is_empty() {
            starts.push((joined.len(), at));
            joined.push_str(&piece);
        }
    }
    for (offset, _) in joined.match_indices(phrase) {
        if let Some((_, at)) = starts.iter().rev().find(|(start, _)| *start <= offset) {
            found.push(at + 1);
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

/// The smallest definition holding `line`.
fn holding(file: &File, line: usize) -> Option<usize> {
    (file.sections.iter().enumerate())
        .filter(|(_, section)| section.start <= line && line <= section.end)
        .min_by_key(|(_, section)| section.end - section.start)
        .map(|(at, _)| at)
}

#[cfg(test)]
#[path = "context_assistance_prompt_map_withheld_tests.rs"]
mod tests;
