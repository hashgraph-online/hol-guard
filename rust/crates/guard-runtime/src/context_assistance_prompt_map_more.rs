//! The rest of the prompt map: the test files that already test what the
//! prompt names, where a new test goes; the doc sections about it; and the
//! changelog section an entry for the change belongs in.
use super::super::sections::{headed_sections, marked_test, members, written_name, Section};
use super::super::seen::Span;
use super::{
    docstring, Asked, Entry, File, Kind, Pick, LONG_SECTION, MAX_LINE_CHARS, MAX_MEMBERS_CHARS,
};
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
/// How many of a named file's definitions stand in for its outline.
const MAX_OUTLINE: usize = 8;
/// The most lines of a definition shown whole.
const MAX_SHOWN_LINES: usize = 80;
/// The most characters of code one map shows whole for their tests.
const MAX_SHOWN_CHARS: usize = 1_600;
/// The most characters of named definitions one map shows whole. The agent
/// opens a named definition before editing it, and that read costs a whole
/// request, so even a long one is cheaper to show.
const MAX_SHOWN_DEFINITION_CHARS: usize = 4_000;
/// The most close tests looked at for showing whole.
const MAX_SHOWN_TESTS: usize = 4;
/// How much a long doc section is marked down, as BM25's `k1`.
const LENGTH_K: f64 = 1.2;

/// True when the prompt asks about docs or documentation.
pub(super) fn asks_for_docs(prompt: &str) -> bool {
    prompt_words(prompt).any(|word| word == "doc" || word == "docs" || word.starts_with("document"))
}

/// True when the prompt renames something or changes it everywhere it is
/// used, so every use matters, not only the definition.
pub(super) fn asks_everywhere(prompt: &str) -> bool {
    prompt_words(prompt).any(|word| word == "rename" || word == "everywhere")
}

/// The member, such as a method, named `name` in `file`: the one inside a
/// class the prompt also names (`CondExpr.as_const`) when there is one.
pub(super) fn member(file: &File, name: &str, names: &[(&str, bool)]) -> Option<usize> {
    let holds = |at: usize| file.sections[at].name.as_deref() == Some(name) && !file.container(at);
    let inside_named = |at: usize| {
        (file.parent[at].and_then(|outer| file.sections[outer].name.as_deref()))
            .is_some_and(|outer| names.iter().any(|(name, _)| *name == outer))
    };
    let mut found = (0..file.sections.len()).filter(|&at| file.parent[at].is_some() && holds(at));
    let first = found.next()?;
    Some(
        std::iter::once(first)
            .chain(found)
            .find(|&at| inside_named(at))
            .unwrap_or(first),
    )
}

/// Whether `path` is in a folder of examples or demos.
/// The first top-level definitions of a file the prompt names, for a prompt
/// that names nothing in it: a file name gives no search words, so its
/// outline is what the map can point at.
pub(super) fn outline<'a>(file: &'a File) -> impl Iterator<Item = usize> + 'a {
    (0..file.sections.len())
        .filter(|&at| file.parent[at].is_none() && file.sections[at].name.is_some())
        .take(MAX_OUTLINE)
}

pub(super) fn sample(path: &str) -> bool {
    (path.split('/').rev().skip(1)).any(|folder| {
        matches!(
            folder,
            "example" | "examples" | "demo" | "demos" | "samples"
        )
    })
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

/// The test files whose tests best match `mentioned`, each with its count of
/// close matches and the last of its best ones, where a new test fits. A test
/// scores the rarity of the words it uses, so the few tests that use a rare
/// word outrank the many that say "option". The best file's short close
/// tests are shown whole, as a named function is, since an agent fixing or
/// writing the code reads them next; not for a rename or a review, nor when
/// `earlier` holds them, shown by an earlier prompt or above.
pub(super) fn tests(
    files: &[File],
    mentioned: &[String],
    asked: &Asked,
    earlier: &[Span],
) -> Vec<Entry> {
    if mentioned.is_empty() {
        return Vec::new();
    }
    // Every test, with the mentioned words it uses.
    let mut using: Vec<(&File, usize, BTreeSet<&String>)> = Vec::new();
    for file in files.iter().filter(|file| file.kind == Kind::Test) {
        let named_test = |at: &usize| {
            marked_test(&file.lines, &file.sections[*at])
                || written_name(file.opening(*at))
                    .is_some_and(|name| name.to_lowercase().starts_with("test"))
        };
        let named: Vec<usize> = (0..file.sections.len()).filter(named_test).collect();
        let above = |at: usize| std::iter::successors(file.parent[at], |&outer| file.parent[outer]);
        let test = |at: usize| named.binary_search(&at).is_ok();
        // A helper inside a test (`def test(): raise ...`) is part of it.
        let tests: Vec<usize> = (named.iter().copied())
            .filter(|&at| !above(at).any(|outer| test(outer) && !file.container(outer)))
            .collect();
        // A test class counts by the tests inside it.
        let holds: BTreeSet<usize> = tests.iter().flat_map(|&at| above(at)).collect();
        for at in tests.iter().copied().filter(|at| !holds.contains(at)) {
            let section = &file.sections[at];
            let body = file
                .lines
                .get(section.start - 1..section.end.min(file.lines.len()))
                .unwrap_or_default();
            let words: BTreeSet<String> = body.iter().flat_map(|line| line_words(line)).collect();
            let used = mentioned
                .iter()
                .filter(|word| words.contains(*word))
                .collect();
            using.push((file, at, used));
        }
    }
    let count = using.len() as f64;
    let rarity: Vec<f64> = (mentioned.iter())
        .map(|word| {
            let holding = using
                .iter()
                .filter(|(_, _, used)| used.contains(&word))
                .count();
            ((count + 1.0) / holding.max(1) as f64).ln()
        })
        .collect();
    let weight = |word: &String| {
        let at = mentioned.iter().position(|other| other == word);
        at.map_or(0.0, |at| rarity[at])
    };
    let scored: Vec<(&File, usize, f64)> = (using.iter())
        .map(|(file, at, used)| (*file, *at, used.iter().map(|word| weight(word)).sum()))
        .filter(|(_, _, score)| *score > 0.0)
        .collect();
    let mut found = Vec::new();
    for file in files.iter().filter(|file| file.kind == Kind::Test) {
        let own: Vec<&(&File, usize, f64)> = (scored.iter())
            .filter(|(of, _, _)| std::ptr::eq(*of, file))
            .collect();
        let Some(best) = own
            .iter()
            .map(|(_, _, score)| *score)
            .max_by(f64::total_cmp)
        else {
            continue;
        };
        let mut near: Vec<(&File, usize, f64)> = (own.iter().map(|test| **test))
            .filter(|(_, _, score)| *score * 2.0 >= best)
            .collect();
        // The closest are shown first.
        near.sort_by(|a, b| b.2.total_cmp(&a.2));
        let close = near.len();
        let Some((_, at, _)) = own.iter().rev().find(|(_, _, score)| *score >= best) else {
            continue;
        };
        let section = &file.sections[*at];
        // A test in a test class by both names, as a runner selects it.
        let name = match file.parent[*at].and_then(|outer| written_name(file.opening(outer))) {
            Some(outer) if outer.starts_with("Test") || outer.ends_with("Tests") => {
                file.qualified(*at)
            }
            _ => written_name(file.opening(*at)).unwrap_or_default(),
        };
        found.push((
            best,
            close,
            format!(
                "{}: {close} related tests, last {name} {}-{}",
                file.path, section.start, section.end
            ),
            near,
        ));
    }
    found.sort_by(|a, b| b.0.total_cmp(&a.0).then(b.1.cmp(&a.1)));
    let mut room = if asked.everywhere || asked.changes {
        0
    } else {
        MAX_SHOWN_CHARS
    };
    let mut listed = Vec::new();
    for (_, _, line, near) in found.into_iter().take(MAX_TEST_FILES) {
        let mut entry = Entry::plain(line);
        for (file, at, _) in near.into_iter().take(MAX_SHOWN_TESTS) {
            let Some((span, code)) = whole(file, at) else {
                continue;
            };
            if code.len() <= room && !earlier.contains(&span) {
                room -= code.len();
                let shown = format!(
                    "\n{}:{}-{}{}",
                    file.path,
                    span.start,
                    span.end,
                    fenced(&code)
                );
                entry.code += shown.len();
                entry.text.push_str(&shown);
                entry.shown.push(span);
            }
        }
        // Only the best file's tests are shown.
        room = 0;
        listed.push(entry);
    }
    listed
}

/// The doc sections about `words`. A section is about the code names it
/// quotes, ``like_this`` or :class:`This`, not the everyday words of its prose,
/// so only quoted words count: rarer ones for more, one in the heading four
/// times over, and a long section for less, since it quotes many names in
/// passing. A project with a docs folder documents its features there, so its
/// top-level files, a README or CONTRIBUTING, are left out.
pub(super) fn docs(files: &[File], words: &[String]) -> Vec<String> {
    let mut held: Vec<(&File, usize, BTreeSet<String>, BTreeSet<String>)> = Vec::new();
    let mut count = 0;
    let mut length = 0;
    let doc = |file: &&File| file.kind == Kind::Doc;
    let foldered = files.iter().filter(doc).any(|file| file.path.contains('/'));
    let listed = |file: &&File| !foldered || file.path.contains('/');
    for file in files.iter().filter(doc).filter(listed) {
        for (at, section) in file.sections.iter().enumerate() {
            if section.end - section.start >= MAX_DOC_SECTION {
                continue;
            }
            count += 1;
            length += section.end + 1 - section.start;
            let lines = file
                .lines
                .get(section.start - 1..section.end.min(file.lines.len()))
                .unwrap_or_default();
            let wanted = |text: &str| {
                line_words(text)
                    .into_iter()
                    .filter(|word| words.contains(word))
                    .collect::<BTreeSet<String>>()
            };
            let quoted: BTreeSet<String> = (lines.iter())
                .flat_map(|line| code_spans(line))
                .flat_map(&wanted)
                .collect();
            let title = lines.first().map(|line| wanted(line)).unwrap_or_default();
            if !quoted.is_empty() {
                held.push((file, at, quoted, title));
            }
        }
    }
    let count = count.max(1) as f64;
    let average = length.max(1) as f64 / count;
    let rarity = |word: &String| {
        let holding = held
            .iter()
            .filter(|(_, _, quoted, _)| quoted.contains(word))
            .count();
        ((count + 1.0) / holding.max(1) as f64).ln()
    };
    let mut scored: Vec<(f64, String)> = held
        .iter()
        .map(|(file, at, quoted, title)| {
            let section = &file.sections[*at];
            let lines = (section.end + 1 - section.start) as f64;
            // BM25's length weight for a word found once.
            let short = (1.0 + LENGTH_K) / (1.0 + LENGTH_K * (0.25 + 0.75 * lines / average));
            let score: f64 = quoted
                .iter()
                .map(|word| rarity(word) * if title.contains(word) { 4.0 } else { 1.0 })
                .sum();
            let heading = heading(file, section.start);
            (
                score * short,
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

/// The text between each pair of matching backtick runs in a line: the code
/// a doc quotes as `name`, ``name`` or :func:`name`.
fn code_spans(line: &str) -> Vec<&str> {
    let mut spans = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('`') {
        let run = rest[open..].chars().take_while(|c| *c == '`').count();
        let after = &rest[open + run..];
        let Some(close) = after.find(&"`".repeat(run)) else {
            break;
        };
        spans.push(&after[..close]);
        rest = &after[close + run..];
    }
    spans
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
pub(super) fn named_in(path: &str, named: &[String]) -> bool {
    let lower = path.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    named.iter().any(|wanted| {
        let wanted = wanted.to_lowercase();
        name == wanted || lower == wanted || lower.ends_with(&format!("/{wanted}"))
    })
}

/// The smallest section holding each one, in one pass: visited by start, a
/// section's parent is the innermost still-open section around it.
pub(super) fn parents(sections: &[Section]) -> Vec<Option<usize>> {
    let mut order: Vec<usize> = (0..sections.len()).collect();
    order.sort_by_key(|&at| (sections[at].start, std::cmp::Reverse(sections[at].end)));
    let mut parent = vec![None; sections.len()];
    let mut open: Vec<usize> = Vec::new();
    for at in order {
        while open
            .last()
            .is_some_and(|&outer| !around(&sections[outer], &sections[at]))
        {
            open.pop();
        }
        parent[at] = open.last().copied();
        open.push(at);
    }
    parent
}

/// Whether `outer` holds `inner` and is larger.
fn around(outer: &Section, inner: &Section) -> bool {
    outer.start <= inner.start
        && inner.end <= outer.end
        && (outer.start, outer.end) != (inner.start, inner.end)
}

/// One named definition: `path:start-end` and its first line, then its
/// members' lines when it is a class or impl. A long one gives only its first
/// line number, so the member list is what an agent opens.
pub(super) fn entry(files: &[File], pick: &Pick) -> String {
    let file = &files[pick.file];
    let section = &file.sections[pick.at];
    let first: String = file.opening(pick.at).chars().take(MAX_LINE_CHARS).collect();
    let inside = members(&file.sections, &file.parent, &file.lines, pick.at);
    let length = section.end - section.start + 1;
    let mut entry = if length > LONG_SECTION && !inside.is_empty() {
        format!("{}:{} ({length} lines) {first}", file.path, section.start)
    } else {
        format!("{}:{}-{} {first}", file.path, section.start, section.end)
    };
    let mut list = String::new();
    for (name, start, end) in inside {
        let piece = format!("{name} {start}-{end}");
        if list.len() + 2 + piece.len() > MAX_MEMBERS_CHARS {
            list.push_str(", ...");
            break;
        }
        if !list.is_empty() {
            list.push_str(", ");
        }
        list.push_str(&piece);
    }
    if !list.is_empty() {
        entry.push_str("\n  members: ");
        entry.push_str(&list);
    }
    entry
}

/// Each named definition's entry and the spans shown whole. A short function
/// or method the prompt names is shown whole, even when the prompt asks about
/// changes, since a diff shows only the lines that changed; but not for a
/// rename, which asks where code is, nor when an earlier prompt of the
/// session was shown it.
pub(super) fn listed(files: &[File], chosen: &[Pick], asked: &Asked) -> Vec<Entry> {
    let mut listed = Vec::new();
    let mut room = if asked.everywhere {
        0
    } else {
        MAX_SHOWN_DEFINITION_CHARS
    };
    for pick in chosen {
        let mut item = Entry::plain(entry(files, pick));
        let code = pick
            .whole
            .then(|| docstring::shown(&files[pick.file], pick.at, asked));
        if let Some((span, code, note)) = code.flatten() {
            if code.len() <= room && !asked.earlier.contains(&span) {
                room -= code.len();
                let shown = fenced(&code);
                item.code += shown.len();
                item.text.push_str(&shown);
                item.text.push_str(&note);
                item.shown.push(span);
            }
        }
        listed.push(item);
    }
    listed
}

/// A short function or method's own lines, to show whole, with the span they
/// fill. A class or a longer definition is given by its lines only.
pub(super) fn whole(file: &File, at: usize) -> Option<(Span, String)> {
    let section = &file.sections[at];
    if file.container(at) || section.end + 1 - section.start > MAX_SHOWN_LINES {
        return None;
    }
    let code = (file.lines.get(section.start.checked_sub(1)?..section.end)?).join("\n");
    let span = Span::new(file.path, section.start as u64, section.end as u64, &code);
    Some((span, code))
}

/// `code` on the lines after an entry, in a fence longer than any run of
/// backticks it holds.
pub(super) fn fenced(code: &str) -> String {
    let longest = code.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest.max(2) + 1);
    format!("\n{fence}\n{code}\n{fence}")
}
