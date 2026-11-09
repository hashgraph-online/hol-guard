//! The definitions the newest commit changed, as they read now. Asked to fix
//! what a commit broke, an agent reads each changed definition before its
//! edit, since a diff gives a line or two around each change; a short one
//! shown whole here needs no read.
use super::super::sections::{headed, sections, Section};
use super::{clean, Hunk};

/// The longest definition shown, and the most characters of all of them.
const MAX_LINES: usize = 40;
const MAX_CODE: usize = 2_500;
const TITLE: &str = "Changed definitions as they read now:";

/// The lines a change covers in the current text: the first to the last it
/// adds, or the line it removes at.
pub(super) fn changed_lines(hunk: &Hunk) -> (usize, usize) {
    let lines = touched(hunk);
    let start = lines.first().copied().unwrap_or(hunk.start.max(1));
    (start, lines.last().copied().unwrap_or(start))
}

/// The smallest definition holding the start of a change, or else its end.
pub(super) fn holding(found: &[Section], (start, end): (usize, usize)) -> Option<&Section> {
    let holding = |line: usize| {
        (found.iter())
            .filter(|section| section.start <= line && line <= section.end)
            .min_by_key(|section| section.end - section.start)
    };
    holding(start).or_else(|| holding(end))
}

/// The current numbers of the lines a change adds, or the line it removes
/// at when it adds none.
pub(super) fn touched(hunk: &Hunk) -> Vec<usize> {
    let mut at = hunk.start.max(1);
    let mut added = Vec::new();
    let mut removed = None;
    for line in hunk.body.lines() {
        match line.as_bytes().first() {
            Some(b'+') => {
                added.push(at);
                at += 1;
            }
            Some(b'-') => {
                removed.get_or_insert(at);
            }
            Some(b'\\') => {}
            _ => at += 1,
        }
    }
    if added.is_empty() {
        added.extend(removed);
    }
    added
}

/// Each named definition a changed line falls in, whole, when it is short,
/// in the order of the files and their changes, until the total is met.
/// Prose and any text that does not pass the secret screen are left out.
pub(super) fn code(changed: &[Hunk], texts: &[(String, String)]) -> Option<String> {
    let mut out = String::new();
    for (path, text) in texts.iter().filter(|(path, _)| !headed(path)) {
        let lines: Vec<&str> = text.lines().collect();
        let found = sections(path, &lines);
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let touched = (changed.iter())
            .filter(|hunk| hunk.path == *path)
            .flat_map(touched);
        for line in touched {
            let Some(section) = holding(&found, (line, line)) else {
                continue;
            };
            let span = (section.start, section.end);
            if section.name.is_some()
                && !spans.contains(&span)
                && section.end + 1 - section.start <= MAX_LINES
            {
                spans.push(span);
            }
        }
        // In file order, each enclosing definition before those inside it,
        // which are left out once it is shown.
        spans.sort_by_key(|&(start, end)| (start, std::cmp::Reverse(end)));
        let mut shown: Vec<(usize, usize)> = Vec::new();
        for (start, end) in spans {
            if (shown.iter()).any(|&(outer, last)| outer <= start && end <= last) {
                continue;
            }
            let Some(body) = lines.get(start - 1..end.min(lines.len())) else {
                continue;
            };
            let body = body.join("\n");
            let part = format!("\n{path}:{start}-{end}\n```\n{body}\n```");
            if out.len() + part.len() <= MAX_CODE && clean(&body) {
                out.push_str(&part);
                shown.push((start, end));
            }
        }
    }
    (!out.is_empty()).then(|| format!("\n\n{TITLE}{out}"))
}

#[cfg(test)]
#[path = "context_assistance_prompt_changes_code_tests.rs"]
mod tests;
