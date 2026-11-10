//! Where the prompt's named definitions are in files Guard keeps out of the
//! context for what they hold, such as a line its secret check takes for a
//! credential. The map gives each one's lines and name, never the file's
//! text, so the agent opens those lines itself instead of searching for them.
use super::{file, named_definitions, Asked, Entry, Rendered, Sought, HEADER};

const WITHHELD_TITLE: &str = "Definitions this request names, in files Guard keeps out of this \
context (open these lines yourself):";

/// `mapped` with the lines of each named definition the files in `withheld`
/// hold, or `mapped` as it is when they hold none.
pub(super) fn added(
    mapped: Option<Rendered>,
    withheld: &[(String, String)],
    sought: &[Sought],
    asked: &Asked,
) -> Option<Rendered> {
    let names: Vec<(&str, bool)> = (sought.iter())
        .filter(|item| item.name && !item.phrase)
        .map(|item| (item.text.as_str(), true))
        .collect();
    if withheld.is_empty() || names.is_empty() {
        return mapped;
    }
    let files: Vec<_> = (withheld.iter())
        .map(|(path, text)| file(path, text))
        .collect();
    let entries: Vec<Entry> = named_definitions(&files, &names, asked, false)
        .into_iter()
        .filter(|pick| !pick.base)
        .map(|pick| {
            let file = &files[pick.file];
            let section = &file.sections[pick.at];
            let range = format!("{}:{}-{}", file.path, section.start, section.end);
            Entry::plain(format!("{range} {}", file.qualified(pick.at)))
        })
        .collect();
    if entries.is_empty() {
        return mapped;
    }
    let list: Vec<String> = entries.into_iter().map(|entry| entry.text).collect();
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
