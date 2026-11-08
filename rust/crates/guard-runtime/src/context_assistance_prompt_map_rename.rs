//! For a rename, every line naming the old name in the files read, and
//! whether those files are all the project files that hold it, so the agent
//! need not search the project again before editing.
use super::{File, Sought, CHECK_EVERY};
use crate::context_assistance_prompt_words::term_form;
use std::time::Instant;

/// Names listed for one prompt: the old name, and at most one more.
const MAX_NAMES: usize = 2;
const MAX_FILES: usize = 16;
const MAX_FILE_LINES: usize = 12;
/// Kept well inside the map's own size, so the list is never cut short
/// while it says it is whole.
const MAX_CHARS: usize = 1_200;

/// For a rename, a block per name the prompt writes as code that a file
/// read holds: its title, and per file the lines naming it. Empty for any
/// other prompt, or once `until` passes.
pub(super) fn blocks(
    files: &[File],
    sought: &[Sought],
    everywhere: bool,
    until: Instant,
) -> Vec<(String, Vec<String>)> {
    if !everywhere {
        return Vec::new();
    }
    (sought.iter())
        .filter(|item| item.name && !item.phrase)
        .filter_map(|item| every_line(files, item, until))
        .take(MAX_NAMES)
        .collect()
}

/// The files read that hold `item` with `_` and `-` dropped, as the walk
/// counted them, each with the lines naming it whole. The list says it is
/// complete only when the walk read every project file, found no file
/// holding it beyond these, and the list fits.
fn every_line(files: &[File], item: &Sought, until: Instant) -> Option<(String, Vec<String>)> {
    let mut written = None;
    let mut holding = 0;
    let mut entries = Vec::new();
    let mut whole = true;
    for file in files {
        let mut lines = Vec::new();
        let mut held = false;
        for (number, line) in file.lines.iter().enumerate() {
            if number % CHECK_EVERY == 0 && Instant::now() >= until {
                return None;
            }
            let lower = line.to_lowercase();
            if !lower.replace(['_', '-'], "").contains(item.text.as_str()) {
                continue;
            }
            held = true;
            let named = line
                .split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '-')))
                .find(|word| term_form(word) == item.text);
            if let Some(word) = named {
                if written.is_none() {
                    written = Some(word.to_owned());
                }
                lines.push((number + 1).to_string());
            }
        }
        holding += usize::from(held);
        if lines.is_empty() {
            continue;
        }
        whole &= lines.len() <= MAX_FILE_LINES;
        lines.truncate(MAX_FILE_LINES);
        entries.push(format!("{}: lines {}", file.path, lines.join(", ")));
    }
    let name = written?;
    whole &= entries.len() <= MAX_FILES
        && entries.iter().map(String::len).sum::<usize>() <= MAX_CHARS
        && item.spelled == Some(holding);
    entries.truncate(MAX_FILES);
    let title = if whole {
        format!("Every line naming `{name}`; no other project file holds it:")
    } else {
        format!("Lines naming `{name}` in the files read; other files may hold it too:")
    };
    Some((title, entries))
}
