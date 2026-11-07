//! The rest of the prompt map: the test files that already test what the
//! prompt names, where a new test goes; the doc sections about it; and the
//! changelog section an entry for the change belongs in.
use super::super::sections::{headed_sections, written_name};
use super::{around, Asked, File, Kind};
use crate::context_assistance_engine::prose;
use crate::context_assistance_prompt_words::term_form;
use std::collections::BTreeSet;
use std::path::Path;

const CHANGELOG_NAMES: [&str; 4] = ["changes", "changelog", "history", "news"];
const MAX_TEST_FILES: usize = 3;
const MAX_DOCS: usize = 4;
/// A doc section this long is a whole page, not the part about the request.
const MAX_DOC_SECTION: usize = 200;
const MAX_TITLE_CHARS: usize = 60;

/// True when the prompt asks about docs or documentation.
pub(super) fn asks_for_docs(prompt: &str) -> bool {
    prompt_words(prompt).any(|word| word == "doc" || word == "docs" || word.starts_with("document"))
}

/// True when the prompt asks for a changelog entry without naming the file.
pub(super) fn asks_for_changelog(prompt: &str) -> bool {
    prompt_words(prompt).any(|word| word == "changelog")
}

fn prompt_words(prompt: &str) -> impl Iterator<Item = String> + '_ {
    prompt
        .split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
}

/// The words of a line spelled as `terms` spells them, with each piece of a
/// hyphened word too.
pub(super) fn line_words(line: &str) -> BTreeSet<String> {
    line.split(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '-')))
        .filter(|word| word.len() >= 3)
        .flat_map(|word| {
            let hyphened = word.contains('-');
            let pieces = word.split('-').filter(move |_| hyphened);
            std::iter::once(word).chain(pieces).map(term_form)
        })
        .collect()
}

/// A prose file named like a changelog: `CHANGES.rst`, `CHANGELOG.md`.
pub(super) fn changelog_file(path: &str) -> bool {
    let lower = path.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    let stem = name.split('.').next().unwrap_or(name);
    CHANGELOG_NAMES.contains(&stem) && prose(Path::new(path))
}

/// The test files with the most tests that use `mentioned`, each with its
/// count and its last such test, where a new one fits.
pub(super) fn tests(files: &[File], mentioned: &[String]) -> Vec<String> {
    if mentioned.is_empty() {
        return Vec::new();
    }
    let mut found: Vec<(usize, String)> = Vec::new();
    for file in files.iter().filter(|file| file.kind == Kind::Test) {
        let named_test = |at: &usize| {
            written_name(file.opening(*at))
                .is_some_and(|name| name.to_lowercase().starts_with("test"))
        };
        let tests: Vec<usize> = (0..file.sections.len()).filter(named_test).collect();
        // A test class counts by the tests inside it.
        let single = |at: &usize| {
            !(tests.iter()).any(|other| around(&file.sections[*at], &file.sections[*other]))
        };
        let mut count = 0;
        let mut last = None;
        for at in tests.iter().copied().filter(single) {
            let section = &file.sections[at];
            let body = file
                .lines
                .get(section.start - 1..section.end.min(file.lines.len()))
                .unwrap_or_default();
            let uses = body.iter().any(|line| {
                let words = line_words(line);
                mentioned.iter().any(|word| words.contains(word))
            });
            if uses {
                count += 1;
                last = Some(at);
            }
        }
        if let Some(at) = last {
            let section = &file.sections[at];
            let name = written_name(file.opening(at)).unwrap_or_default();
            found.push((
                count,
                format!(
                    "{}: {count} related tests, last {name} {}-{}",
                    file.path, section.start, section.end
                ),
            ));
        }
    }
    found.sort_by(|a, b| b.0.cmp(&a.0));
    found
        .into_iter()
        .take(MAX_TEST_FILES)
        .map(|(_, line)| line)
        .collect()
}

/// The doc sections that hold the most of `words`, rarer words counting for
/// more and a word in the heading twice.
pub(super) fn docs(files: &[File], words: &[String]) -> Vec<String> {
    let mut held: Vec<(&File, usize, BTreeSet<String>, BTreeSet<String>)> = Vec::new();
    let mut count = 0;
    for file in files.iter().filter(|file| file.kind == Kind::Doc) {
        for (at, section) in file.sections.iter().enumerate() {
            if section.end - section.start >= MAX_DOC_SECTION {
                continue;
            }
            count += 1;
            let lines = file
                .lines
                .get(section.start - 1..section.end.min(file.lines.len()))
                .unwrap_or_default();
            let wanted = |line: &&str| {
                line_words(line)
                    .into_iter()
                    .filter(|word| words.contains(word))
                    .collect::<BTreeSet<String>>()
            };
            let body: BTreeSet<String> = lines.iter().flat_map(&wanted).collect();
            let title = lines.first().map(wanted).unwrap_or_default();
            if !body.is_empty() {
                held.push((file, at, body, title));
            }
        }
    }
    let count = count.max(1) as f64;
    let rarity = |word: &String| {
        let holding = held
            .iter()
            .filter(|(_, _, body, _)| body.contains(word))
            .count();
        (1.0 + count / holding.max(1) as f64).ln()
    };
    let mut scored: Vec<(f64, String)> = held
        .iter()
        .map(|(file, at, body, title)| {
            let score: f64 = body
                .iter()
                .map(|word| rarity(word) * if title.contains(word) { 2.0 } else { 1.0 })
                .sum();
            let section = &file.sections[*at];
            let heading = heading(file, section.start);
            (
                score,
                format!("{}:{}-{} {heading}", file.path, section.start, section.end),
            )
        })
        .filter(|(score, _)| *score > 0.0)
        .collect();
    scored.sort_by(|a, b| b.0.total_cmp(&a.0));
    scored
        .into_iter()
        .take(MAX_DOCS)
        .map(|(_, line)| line)
        .collect()
}

/// The newest section of the changelog the prompt names, or of the
/// top-most changelog when it asks for one, where this change's entry goes.
pub(super) fn changelog(files: &[File], asked: &Asked) -> Option<String> {
    let file = (files.iter())
        .filter(|file| file.kind == Kind::Changelog)
        .filter(|file| asked.changelog || named_in(file.path, &asked.named))
        .min_by_key(|file| (file.path.matches('/').count(), file.path))?;
    let sections = headed_sections(&file.lines);
    let newest = sections
        .iter()
        .find(|section| {
            let title = file.lines[section.start - 1].to_lowercase();
            title.chars().any(|c| c.is_ascii_digit()) || title.contains("unreleased")
        })
        .or(sections.first())?;
    Some(format!(
        "{}:{}-{} newest section: {}",
        file.path,
        newest.start,
        newest.end,
        heading(file, newest.start)
    ))
}

fn heading(file: &File, start: usize) -> String {
    let line = file.lines.get(start - 1).copied().unwrap_or_default();
    line.trim_start_matches('#')
        .trim()
        .chars()
        .take(MAX_TITLE_CHARS)
        .collect()
}

/// Whether the prompt named the file at `path`, by its name or a path ending.
fn named_in(path: &str, named: &[String]) -> bool {
    let lower = path.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    named.iter().any(|wanted| {
        let wanted = wanted.to_lowercase();
        name == wanted || lower == wanted || lower.ends_with(&format!("/{wanted}"))
    })
}
