//! Where the prompt's named definitions are in files Guard keeps out of the
//! context for what they hold, such as a line its secret check takes for a
//! credential. The map gives each one's lines and name, never the file's
//! text, so the agent opens those lines itself instead of searching for them.
use super::super::sections::written_name;
use super::{file, named_definitions, Asked, Entry, File, Rendered, Sought, HEADER};
use std::time::Instant;

const WITHHELD_TITLE: &str = "Definitions this request names, in files Guard keeps out of this \
context (open these lines yourself):";
/// The most of the note's text: it comes after the map's own budget.
const MAX_WITHHELD_CHARS: usize = 600;

/// `mapped` with the lines of each named definition the files in `withheld`
/// hold, or `mapped` as it is when they hold none or `until` passes.
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
    if withheld.is_empty() || names.is_empty() {
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
        let picks = named_definitions(std::slice::from_ref(file), &names, asked, false);
        for pick in picks {
            if pick.base || !named(file, pick.at) {
                continue;
            }
            let section = &file.sections[pick.at];
            let range = format!("{}:{}-{}", file.path, section.start, section.end);
            entries.push(Entry::plain(format!("{range} {}", file.qualified(pick.at))));
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

#[cfg(test)]
#[path = "context_assistance_prompt_map_withheld_tests.rs"]
mod tests;
