//! The map's text from its blocks, within the length a note may take.
use super::super::Rendered;
use super::{Entry, HEADER, MAX_MAP_CHARS, SHOWN_NOTE};
use std::path::Path;

/// The map's text: each block that lists something, under its title, with
/// each entry that fits and the code it shows whole.
pub(super) fn render(blocks: &[(String, Vec<Entry>)]) -> Option<Rendered> {
    let mut text = String::new();
    let mut shown = Vec::new();
    let mut code = 0;
    let mut listed = 0;
    let header = HEADER.len() + 1 + SHOWN_NOTE.len();
    for (title, entries) in blocks {
        let mut opened = false;
        for entry in entries {
            let heading = if opened { 0 } else { 2 + title.len() };
            let more = heading + 1 + entry.text.len() - entry.code;
            if header + text.len() - code + more > MAX_MAP_CHARS {
                continue;
            }
            if !opened {
                text.push_str("\n\n");
                text.push_str(title);
                opened = true;
            }
            text.push('\n');
            text.push_str(&entry.text);
            shown.extend(entry.shown.iter().cloned());
            code += entry.code;
            listed += 1;
        }
    }
    let note = if shown.is_empty() { "" } else { SHOWN_NOTE };
    let text = format!(
        "{HEADER}{}{note}{text}",
        if note.is_empty() { "" } else { " " }
    );
    (listed > 0).then_some(Rendered { text, shown })
}

/// Lines quoted from files: code, held to their own limits.
pub(super) fn quoted(entries: Vec<String>) -> Vec<Entry> {
    let code = |text: String| Entry {
        code: text.len(),
        text,
        shown: Vec::new(),
    };
    entries.into_iter().map(code).collect()
}

/// A project folder that holds a folder of its own name (`boltons/boltons/`)
/// misleads an agent already inside it: it writes `boltons/ioutils.py` as
/// `ioutils.py` beside it and its first edit fails. One line spells out the
/// first such path in full.
pub(super) fn nested(mut done: Rendered, root: &Path) -> Rendered {
    // The line sits in the header, outside the fenced file contents, so a
    // folder name that could read as an instruction is never written there.
    let plain = |text: &str| {
        text.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    };
    let Some(name) = root.file_name().and_then(|name| name.to_str()) else {
        return done;
    };
    if !root.to_str().is_some_and(plain) {
        return done;
    }
    let inner = format!("{name}/");
    // Only entry lines count: a line inside a fence is file content and may
    // say anything, and the path itself must pass the same plain check.
    // `fenced` opens and closes with one line of backticks longer than any
    // run inside, so only that exact line ends the fence.
    let mut fence: Option<&str> = None;
    let first = (done.text.lines())
        .filter(|line| {
            let ticks = line.len() >= 3 && line.chars().all(|c| c == '`');
            match fence {
                Some(open) if *line == open => fence = None,
                Some(_) => {}
                None if ticks => fence = Some(line),
                None => return line.starts_with(&inner),
            }
            false
        })
        .filter_map(|line| line.split(':').next())
        .find(|path| plain(path))
        .map(str::to_owned);
    if let Some(first) = first {
        let full = root.join(&first);
        let line = format!(
            " Paths start at {}: `{first}` is {}.",
            root.display(),
            full.display()
        );
        done.text.insert_str(HEADER.len(), &line);
    }
    done
}

#[cfg(test)]
#[path = "context_assistance_prompt_map_render_tests.rs"]
mod tests;
