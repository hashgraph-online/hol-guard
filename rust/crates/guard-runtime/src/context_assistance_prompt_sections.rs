//! The sections of a project file the prompt map places code in: each
//! definition in a code file, and each headed section of a prose file.
use crate::context_assistance_engine::{definition, opened, prose};
use crate::context_assistance_prompt_words::term_form;
use std::collections::BTreeMap;
use std::path::Path;

/// Lines `start..=end` (from 1) of one file, and the name it defines.
#[derive(Clone, Debug)]
pub(super) struct Section {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) name: Option<String>,
}

pub(super) fn sections(path: &str, lines: &[&str]) -> Vec<Section> {
    if headed(path) {
        headed_sections(lines)
    } else {
        code_sections(lines)
    }
}

/// Whether `path` is a prose file, split by headings, not definitions.
pub(super) fn headed(path: &str) -> bool {
    prose(Path::new(path))
}

/// Each definition in a code file, from its decorators to the last line
/// indented under it or the brace that closes it. Lines inside a docstring
/// or block comment open nothing.
fn code_sections(lines: &[&str]) -> Vec<Section> {
    let mut sections = Vec::new();
    let mut closer: Option<&str> = None;
    for (index, line) in lines.iter().enumerate() {
        closer = match closer {
            Some(mark) => (!line.contains(mark)).then_some(mark),
            None => {
                if definition(line) {
                    let mut start = index;
                    while start > 0 && decorates(lines[start - 1]) {
                        start -= 1;
                    }
                    sections.push(Section {
                        start: start + 1,
                        end: block_end(lines, index) + 1,
                        name: defined_name(line),
                    });
                }
                opened(line)
            }
        };
    }
    sections
}

/// A decorator or attribute line above a definition.
fn decorates(line: &str) -> bool {
    let line = line.trim_start();
    line.starts_with('@') || line.starts_with("#[")
}

/// The last line of the definition that opens on line `at`: the last line
/// indented deeper than it, or the closing brace at its own depth when it
/// left a brace open. A closing parenthesis or bracket at its depth ends a
/// long signature, not the body.
fn block_end(lines: &[&str], at: usize) -> usize {
    let depth = indent(lines[at]);
    let mut last = at;
    for (index, line) in lines.iter().enumerate().skip(at + 1) {
        let text = line.trim_start();
        if text.is_empty() {
            continue;
        }
        if indent(line) > depth {
            last = index;
            continue;
        }
        if indent(line) < depth {
            break;
        }
        if text.starts_with('}') {
            let open: isize = lines[at..=last].iter().map(|line| braces(line)).sum();
            return if open > 0 { index } else { last };
        }
        if text == "end" || text.starts_with("end ") {
            return index;
        }
        if text.starts_with([')', ']', '{']) || text == "where" || text.starts_with("where ") {
            last = index;
            continue;
        }
        break;
    }
    last
}

/// Opening braces on `line` less closing ones, outside quoted text and a
/// `//` comment.
fn braces(line: &str) -> isize {
    let chars: Vec<char> = line.chars().collect();
    let mut open = 0;
    let mut quote = None;
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        match quote {
            Some(_) if c == '\\' => at += 1,
            Some(mark) if c == mark => quote = None,
            Some(_) => {}
            None => match c {
                '"' | '`' => quote = Some(c),
                // A `'` with none after it is a Rust lifetime, not a quote.
                '\'' if chars[at + 1..].contains(&'\'') => quote = Some(c),
                '/' if chars.get(at + 1) == Some(&'/') => break,
                '{' => open += 1,
                '}' => open -= 1,
                _ => {}
            },
        }
        at += 1;
    }
    open
}

fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The name a definition line gives, spelled as `terms` spells words.
fn defined_name(line: &str) -> Option<String> {
    written_name(line).map(|name| term_form(&name))
}

/// The name a definition line gives, as the code writes it.
pub(super) fn written_name(line: &str) -> Option<String> {
    let mut words = line.split_whitespace().skip_while(|word| {
        matches!(
            *word,
            "export"
                | "default"
                | "pub"
                | "pub(crate)"
                | "pub(super)"
                | "async"
                | "static"
                | "public"
                | "private"
                | "protected"
                | "abstract"
        )
    });
    words.next()?;
    let name: String = words
        .next()?
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// The line `section` opens with, past its decorators and attributes.
pub(super) fn opening<'a>(lines: &[&'a str], section: &Section) -> &'a str {
    lines
        .get(section.start - 1..section.end.min(lines.len()))
        .unwrap_or_default()
        .iter()
        .map(|line| line.trim())
        .find(|line| !decorates(line))
        .unwrap_or_default()
}

/// Whether an attribute over the section marks it as a test, as Rust's
/// `#[test]` or `#[tokio::test]` and Java's `@Test` do, whatever its name.
pub(super) fn marked_test(lines: &[&str], section: &Section) -> bool {
    (lines.get(section.start - 1..section.end.min(lines.len())))
        .unwrap_or_default()
        .iter()
        .map(|line| line.trim())
        .take_while(|line| decorates(line))
        .any(|attribute| {
            let name = attribute
                .trim_start_matches("#[")
                .trim_start_matches('@')
                .split([']', '(', ' '])
                .next()
                .unwrap_or_default();
            let last = name.rsplit("::").next().unwrap_or_default();
            matches!(
                last,
                "test" | "Test" | "rstest" | "test_case" | "ParameterizedTest"
            )
        })
}

/// The definitions directly inside section `outer` (a class's methods, an
/// impl's functions), each with its name as written and its lines; `parent`
/// is each section's smallest holder. A later one replaces an earlier one of
/// the same name, so overloads count once.
pub(super) fn members(
    sections: &[Section],
    parent: &[Option<usize>],
    lines: &[&str],
    outer: usize,
) -> Vec<(String, usize, usize)> {
    let mut found: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for (at, section) in sections.iter().enumerate() {
        if parent.get(at).copied().flatten() != Some(outer) {
            continue;
        }
        if let Some(name) = written_name(opening(lines, section)) {
            found.insert(name, (section.start, section.end));
        }
    }
    let mut found: Vec<(String, usize, usize)> = (found.into_iter())
        .map(|(name, (start, end))| (name, start, end))
        .collect();
    found.sort_by_key(|(_, start, _)| *start);
    found
}

/// Each section of a prose file, from its heading to the next one: a
/// Markdown `#` heading, or a reStructuredText title over an underline.
/// Lines inside a fenced block are not headings.
pub(super) fn headed_sections(lines: &[&str]) -> Vec<Section> {
    let mut starts = Vec::new();
    let mut fence: Option<(char, usize)> = None;
    for (index, line) in lines.iter().enumerate() {
        let text = line.trim_start();
        let mark = text.chars().next().filter(|c| matches!(c, '`' | '~'));
        let run = mark.map_or(0, |mark| text.chars().take_while(|c| *c == mark).count());
        if let Some(mark) = mark.filter(|_| run >= 3) {
            let rest = &text[run..];
            match fence {
                None if mark == '~' || !rest.contains('`') => {
                    fence = Some((mark, run));
                    continue;
                }
                Some((open, length)) if open == mark && run >= length && rest.trim().is_empty() => {
                    fence = None;
                    continue;
                }
                _ => {}
            }
        }
        if fence.is_some() {
            continue;
        }
        let hashes = line.chars().take_while(|c| *c == '#').count();
        if (1..=4).contains(&hashes)
            && line[hashes..].starts_with(' ')
            && !line[hashes..].trim().is_empty()
        {
            starts.push(index);
        } else if index > 0 && underline(line) && !lines[index - 1].trim().is_empty() {
            starts.push(index - 1);
        }
    }
    starts.dedup();
    let mut sections = Vec::new();
    for (at, &start) in starts.iter().enumerate() {
        let end = starts.get(at + 1).map_or(lines.len(), |next| *next);
        let title = lines[start].trim_start_matches('#').trim();
        sections.push(Section {
            start: start + 1,
            end: end.max(start + 1),
            name: (!title.is_empty()).then(|| term_form(title)),
        });
    }
    sections
}

fn underline(line: &str) -> bool {
    let line = line.trim_end();
    line.len() >= 3
        && line
            .chars()
            .all(|c| matches!(c, '=' | '-' | '~' | '^' | '#' | '*'))
        && line.chars().all(|c| line.starts_with(c))
}
