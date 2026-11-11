//! The map's text from its blocks, within the length a note may take.
use super::super::Rendered;
use super::{Entry, HEADER, MAX_MAP_CHARS, SHOWN_NOTE};

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
