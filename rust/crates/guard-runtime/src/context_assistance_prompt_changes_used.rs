//! The tests that use what a change touched. Asked to fix what a commit
//! broke, an agent searches the tests for the changed definitions and reads
//! the ones that fail; the changes note names the definitions, and these are
//! the tests, so neither search is needed.
use super::super::sections::{headed, opening, sections, written_name};
use super::super::seen::{self, Session, Span};
use super::super::{add_context, map};
use super::code::{holding, touched};
use super::Hunk;
use crate::context_assistance_prompt_files::{test_file, walk};
use crate::context_assistance_prompt_words::term_form;
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};

/// The most changed definitions whose tests are looked for.
const MAX_NAMES: usize = 3;

/// The changes note, and the names of the definitions the changes fall in.
#[derive(Clone, Debug, PartialEq)]
pub(in super::super) struct Changed {
    pub(in super::super) text: String,
    pub(in super::super) names: Vec<String>,
}

/// The names of the definitions `changed` falls in, by the files' current
/// text, as they are written, lowercased. A method such as `__init__`,
/// which every class has, is named by its class. Changed tests and prose
/// files name nothing to look for. Two names spelled alike, as the prompt's
/// words are, count once.
pub(super) fn names(changed: &[Hunk], texts: &[(String, String)]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (path, text) in texts {
        if test_file(path) || headed(path) {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        let found = sections(path, &lines);
        let touched = (changed.iter())
            .filter(|hunk| hunk.path == *path)
            .flat_map(touched);
        for line in touched {
            let Some(section) = holding(&found, (line, line)) else {
                continue;
            };
            let outer = (found.iter())
                .filter(|outer| outer.start <= section.start && section.end <= outer.end)
                .filter(|outer| (outer.start, outer.end) != (section.start, section.end))
                .min_by_key(|outer| outer.end - outer.start);
            let name = written_name(opening(&lines, section))
                .filter(|name| !name.starts_with("__"))
                .or_else(|| outer.and_then(|outer| written_name(opening(&lines, outer))));
            let Some(name) = name.map(|name| name.to_lowercase()) else {
                continue;
            };
            let form = term_form(&name);
            if form.chars().count() >= 3 && !names.iter().any(|n| term_form(n) == form) {
                names.push(name);
            }
        }
    }
    names.truncate(MAX_NAMES);
    names
}

/// Adds the tests that use the definitions `changed` names to `response`,
/// within `budget`, when project context is still on after the read.
pub(in super::super) fn add_tests(
    response: &mut Value,
    (home, root, app, session): (&Path, &Path, &str, Option<&Session>),
    changed: Option<Changed>,
    earlier: &[Span],
    budget: Duration,
    context_on: impl Fn() -> bool,
) {
    let Some(Changed { names, .. }) = changed else {
        return;
    };
    // Files hold a name as written, `split_value`; the tests are matched by
    // the prompt's spelling of their words, `splitvalue`.
    let words: Vec<String> = names.iter().map(|name| term_form(name)).collect();
    let mut terms = words.clone();
    terms.extend(names.into_iter().filter(|name| !words.contains(name)));
    let started = Instant::now();
    let searched = walk(root, &terms, &[], &[], budget);
    let until = started + budget;
    let Some(tests) = map::changed_tests(home, root, app, &searched, &words, earlier, until) else {
        return;
    };
    if !context_on() {
        return;
    }
    if let Some(session) = session {
        seen::remember(session, &tests.shown);
    }
    add_context(response, &tests.text);
}

#[cfg(test)]
#[path = "context_assistance_prompt_changes_used_tests.rs"]
mod tests;
