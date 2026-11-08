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

/// The lines a change covers in the current text: those it adds, or the
/// line it removes at.
pub(super) fn changed_lines(hunk: &Hunk) -> (usize, usize) {
    let start = hunk.start.max(1);
    let added = (hunk.body.lines())
        .filter(|line| line.starts_with('+'))
        .count();
    (start, start + added.max(1) - 1)
}

/// The smallest definition holding the start of a change, or else its end.
pub(super) fn holding<'a>(
    found: &'a [Section],
    (start, end): (usize, usize),
) -> Option<&'a Section> {
    let holding = |line: usize| {
        (found.iter())
            .filter(|section| section.start <= line && line <= section.end)
            .min_by_key(|section| section.end - section.start)
    };
    holding(start).or_else(|| holding(end))
}

/// Each named definition a change falls in, whole, when it is short, in the
/// order of the files and their changes, until the total is met. Prose and
/// any text that does not pass the secret screen are left out.
pub(super) fn code(changed: &[Hunk], texts: &[(String, String)]) -> Option<String> {
    let mut out = String::new();
    for (path, text) in texts.iter().filter(|(path, _)| !headed(path)) {
        let lines: Vec<&str> = text.lines().collect();
        let found = sections(path, &lines);
        let mut shown: Vec<(usize, usize)> = Vec::new();
        for hunk in changed.iter().filter(|hunk| hunk.path == *path) {
            let Some(section) = holding(&found, changed_lines(hunk)) else {
                continue;
            };
            let span = (section.start, section.end);
            if section.name.is_none()
                || shown.contains(&span)
                || section.end + 1 - section.start > MAX_LINES
            {
                continue;
            }
            shown.push(span);
            let Some(body) = lines.get(section.start - 1..section.end.min(lines.len())) else {
                continue;
            };
            let body = body.join("\n");
            let part = format!("\n{path}:{}-{}\n```\n{body}\n```", span.0, span.1);
            if out.len() + part.len() <= MAX_CODE && clean(&body) {
                out.push_str(&part);
            }
        }
    }
    (!out.is_empty()).then(|| format!("\n\n{TITLE}{out}"))
}

#[cfg(test)]
#[path = "context_assistance_prompt_changes_code_tests.rs"]
mod tests;
