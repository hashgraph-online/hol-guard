//! The tests that use what a change touched. Asked to fix what a commit
//! broke, an agent searches the tests for the changed definitions and reads
//! the ones that fail; the changes note names the definitions, and these are
//! the tests, so neither search is needed.
use super::super::sections::{headed, opening, sections, written_name};
use super::super::seen::{self, Session, Span};
use super::super::{add_context, map};
use super::code::{changed_lines, holding};
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
/// text, as the prompt's words are spelled. A method such as `__init__`,
/// which every class has, is named by its class. Changed tests and prose
/// files name nothing to look for.
pub(super) fn names(changed: &[Hunk], texts: &[(String, String)]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (path, text) in texts {
        if test_file(path) || headed(path) {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        let found = sections(path, &lines);
        for hunk in changed.iter().filter(|hunk| hunk.path == *path) {
            let Some(section) = holding(&found, changed_lines(hunk)) else {
                continue;
            };
            let outer = (found.iter())
                .filter(|outer| outer.start <= section.start && section.end <= outer.end)
                .filter(|outer| (outer.start, outer.end) != (section.start, section.end))
                .min_by_key(|outer| outer.end - outer.start);
            let name = written_name(opening(&lines, section))
                .filter(|name| !name.starts_with("__"))
                .or_else(|| outer.and_then(|outer| written_name(opening(&lines, outer))));
            let Some(name) = name.map(|name| term_form(&name)) else {
                continue;
            };
            if name.chars().count() >= 3 && !names.contains(&name) {
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
    let started = Instant::now();
    let searched = walk(root, &names, &[], &[], budget);
    let until = started + budget;
    let Some(tests) = map::changed_tests(home, root, app, &searched, &names, earlier, until) else {
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
