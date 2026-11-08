//! For a rename, every line naming the old name in the files read, and
//! whether those files are all the project files that hold it, so the agent
//! need not search the project again before editing. For a stubbed-out
//! function, the other lines naming it, with their text: the module state,
//! imports and platform versions its body has to use.
use super::seen::Span;
use super::{File, Pick, Sought, CHECK_EVERY};
use crate::context_assistance_prompt_words::term_form;
use std::time::Instant;

/// Names listed for one prompt: the old name, and at most one more.
const MAX_NAMES: usize = 2;
const MAX_FILES: usize = 16;
const MAX_FILE_LINES: usize = 12;
/// Kept well inside the map's own size, so the list is never cut short
/// while it says it is whole.
const MAX_CHARS: usize = 1_200;
/// Lines listed with their text for a stub, and how much of each.
const MAX_STUB_LINES: usize = 24;
const MAX_STUB_CHARS: usize = 2_000;
const MAX_LINE_CHARS: usize = 160;
/// What a body left to be written holds.
const STUB_MARKS: [&str; 4] = [
    "NotImplementedError",
    "todo!(",
    "unimplemented!(",
    "not implemented",
];

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

/// In `file`, whether any line holds `term` with `_` and `-` dropped, and
/// the lines naming it whole with the first spelling written; `None` once
/// `until` passes.
fn naming(file: &File, term: &str, until: Instant) -> Option<(bool, Vec<usize>, Option<String>)> {
    let mut held = false;
    let mut lines = Vec::new();
    let mut written = None;
    for (number, line) in file.lines.iter().enumerate() {
        if number % CHECK_EVERY == 0 && Instant::now() >= until {
            return None;
        }
        if !line.to_lowercase().replace(['_', '-'], "").contains(term) {
            continue;
        }
        held = true;
        let named = line
            .split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '-')))
            .find(|word| term_form(word) == term);
        if let Some(word) = named {
            if written.is_none() {
                written = Some(word.to_owned());
            }
            lines.push(number + 1);
        }
    }
    Some((held, lines, written))
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
        let (held, mut lines, spelling) = naming(file, &item.text, until)?;
        written = written.or(spelling);
        holding += usize::from(held);
        if lines.is_empty() {
            continue;
        }
        whole &= lines.len() <= MAX_FILE_LINES;
        lines.truncate(MAX_FILE_LINES);
        let lines: Vec<String> = lines.iter().map(usize::to_string).collect();
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

/// For the first chosen definition whose body is left to be written, the
/// other lines in the files read naming it, with their text, leaving out
/// the code the map already shows.
pub(super) fn stub(
    files: &[File],
    chosen: &[Pick],
    shown: &[Span],
    until: Instant,
) -> Option<(String, Vec<String>)> {
    let (file, section) = chosen.iter().find_map(|pick| {
        let file = &files[pick.file];
        let section = &file.sections[pick.at];
        let body = file
            .lines
            .get(section.start - 1..section.end.min(file.lines.len()))?;
        let empty = body
            .iter()
            .any(|line| STUB_MARKS.iter().any(|mark| line.contains(mark)));
        (pick.whole && empty).then_some((file, section))
    })?;
    let name = section.name.as_deref()?;
    // Spelled as its definition writes it.
    let opening = file
        .lines
        .get(section.start - 1)
        .copied()
        .unwrap_or_default();
    let written = (opening.split(|c: char| !(c.is_alphanumeric() || c == '_')))
        .find(|word| term_form(word) == name)
        .map(str::to_owned);
    let inside = |path: &str, number: usize| {
        (path == file.path && (section.start..=section.end).contains(&number))
            || (shown.iter())
                .any(|span| span.path == path && (span.start..=span.end).contains(&(number as u64)))
    };
    let mut entries = Vec::new();
    let mut length = 0;
    let mut whole = true;
    'files: for other in files {
        let (_, lines, _) = naming(other, name, until)?;
        for number in lines.into_iter().filter(|&n| !inside(other.path, n)) {
            let text: String = other.lines[number - 1]
                .trim()
                .chars()
                .take(MAX_LINE_CHARS)
                .collect();
            let entry = format!("{}:{number}: {text}", other.path);
            if entries.len() == MAX_STUB_LINES || length + entry.len() > MAX_STUB_CHARS {
                whole = false;
                break 'files;
            }
            length += entry.len();
            entries.push(entry);
        }
    }
    if entries.is_empty() {
        return None;
    }
    let name = written.as_deref().unwrap_or(name);
    let title = if whole {
        format!("Other lines naming `{name}` in the files read:")
    } else {
        format!("First other lines naming `{name}` in the files read:")
    };
    Some((title, entries))
}
