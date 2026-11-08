//! For a rename, every line naming the old name in the files read, with its
//! text, and whether those files are all the project files that hold it, so
//! the agent need not search or open them again before editing. For a stubbed-out
//! function, the other lines naming it, with their text: the module state,
//! imports and platform versions its body has to use.
use super::{Asked, File, Pick, Sought, Span, CHECK_EVERY};
use crate::context_assistance_prompt_words::term_form;
use std::time::Instant;

/// Names listed for one prompt: the old name, and at most one more.
const MAX_NAMES: usize = 2;
/// Lines listed with their text for a rename, and their length.
const MAX_RENAME_LINES: usize = 40;
const MAX_RENAME_CHARS: usize = 3_600;
/// Lines listed with their text for a stub, and their length.
const MAX_STUB_LINES: usize = 24;
const MAX_STUB_CHARS: usize = 2_000;
/// How much of each line is listed.
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
    asked: &Asked,
    until: Instant,
) -> Vec<(String, Vec<String>)> {
    if !asked.everywhere {
        return Vec::new();
    }
    (sought.iter())
        .filter(|item| item.name && !item.phrase)
        .filter_map(|item| {
            // `_batched` is renamed, not `batched` beside it: the lines
            // naming it as the prompt spells it, when any file does.
            let spelled = (asked.spellings.iter()).find(|word| term_form(word) == item.text);
            (spelled.and_then(|word| every_line(files, item, Some(word.as_str()), until)))
                .or_else(|| every_line(files, item, None, until))
        })
        .take(MAX_NAMES)
        .collect()
}

/// In `file`, whether any line holds `term` with `_` and `-` dropped, and
/// the lines naming it whole, or `exact` where given, with the first
/// spelling written; `None` once `until` passes.
fn naming(
    file: &File,
    term: &str,
    exact: Option<&str>,
    until: Instant,
) -> Option<(bool, Vec<usize>, Option<String>)> {
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
            .find(|word| exact.map_or_else(|| term_form(word) == term, |exact| *word == exact));
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
/// counted them, and each line naming it whole, with its text, so the edit
/// can be written without opening them. The list says it is complete only
/// when the walk read every project file, found no file holding it beyond
/// these, and every line fits.
fn every_line(
    files: &[File],
    item: &Sought,
    exact: Option<&str>,
    until: Instant,
) -> Option<(String, Vec<String>)> {
    let mut written = None;
    let mut holding = 0;
    let mut entries = Vec::new();
    let mut length = 0;
    let mut whole = true;
    for file in files {
        let (held, lines, spelling) = naming(file, &item.text, exact, until)?;
        written = written.or(spelling);
        holding += usize::from(held);
        for number in lines {
            let entry = line_entry(file, number);
            if entries.len() == MAX_RENAME_LINES || length + entry.len() > MAX_RENAME_CHARS {
                whole = false;
                continue;
            }
            length += entry.len();
            entries.push(entry);
        }
    }
    let name = written?;
    whole &= item.spelled == Some(holding);
    let title = if whole {
        format!("Every line naming `{name}`; no other project file holds it:")
    } else {
        format!("Lines naming `{name}` in the files read; other files may hold it too:")
    };
    Some((title, entries))
}

/// Line `number` of `file` as a search prints it: path, number and text.
fn line_entry(file: &File, number: usize) -> String {
    let text: String = (file.lines[number - 1].trim().chars())
        .take(MAX_LINE_CHARS)
        .collect();
    format!("{}:{number}: {text}", file.path)
}

/// Whether section `at` of `file` is a body left to be written.
pub(super) fn stubbed(file: &File, at: usize) -> bool {
    let section = &file.sections[at];
    let body = (file.lines)
        .get(section.start - 1..section.end.min(file.lines.len()))
        .unwrap_or_default();
    (body.iter()).any(|line| STUB_MARKS.iter().any(|mark| line.contains(mark)))
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
        (pick.whole && stubbed(file, pick.at)).then_some((file, &file.sections[pick.at]))
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
        let (_, lines, _) = naming(other, name, None, until)?;
        for number in lines.into_iter().filter(|&n| !inside(other.path, n)) {
            let entry = line_entry(other, number);
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
