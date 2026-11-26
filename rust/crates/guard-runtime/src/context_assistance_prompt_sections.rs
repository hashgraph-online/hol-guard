//! The sections of a project file the prompt map places code in: each
//! definition in a code file, and each headed section of a prose file.
use crate::context_assistance_engine::{definition, opened, prose};
use crate::context_assistance_prompt_words::{term_form, test_file};
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
        let calls = test_file(path) && SCRIPTS.iter().any(|end| path.ends_with(end));
        code_sections(lines, path.ends_with(".rs"), calls)
    }
}

/// Files whose tests are calls, `it("...", () => {...})`, not definitions.
const SCRIPTS: [&str; 8] = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"];

/// Whether `path` is a prose file, split by headings, not definitions.
pub(super) fn headed(path: &str) -> bool {
    prose(Path::new(path))
}

/// Each definition in a code file, from its decorators to the last line
/// indented under it or the brace that closes it. Lines inside a docstring
/// or block comment open nothing. In Rust, `rust`, a `'` is a lifetime
/// unless it opens a character literal. In a JavaScript or TypeScript test
/// file, `calls`, each `describe`, `it` and `test` call opens one too.
fn code_sections(lines: &[&str], rust: bool, calls: bool) -> Vec<Section> {
    let mut sections = Vec::new();
    let mut closer: Option<&str> = None;
    for (index, line) in lines.iter().enumerate() {
        closer = match closer {
            Some(mark) => (!line.contains(mark)).then_some(mark),
            None => {
                if definition(line) || (calls && test_call(line).is_some()) {
                    let mut start = index;
                    while start > 0 && decorates(lines[start - 1]) {
                        start -= 1;
                    }
                    sections.push(Section {
                        start: start + 1,
                        end: block_end(lines, index, rust) + 1,
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
fn block_end(lines: &[&str], at: usize, rust: bool) -> usize {
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
            let open: isize = lines[at..=last].iter().map(|line| braces(line, rust)).sum();
            return if open > 0 { index } else { last };
        }
        if text == "end" || text.starts_with("end ") {
            return index;
        }
        if text.starts_with([')', ']', '{', '`']) || text == "where" || text.starts_with("where ") {
            last = index;
            continue;
        }
        break;
    }
    last
}

/// Opening braces on `line` less closing ones, outside quoted text and a
/// `//` comment.
fn braces(line: &str, rust: bool) -> isize {
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
                '\'' if rust => at += char_literal(&chars[at..]),
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

/// How far past the `'` opening `rest` its closing `'` is, when `rest`
/// starts a Rust character literal; 0 for a lifetime.
fn char_literal(rest: &[char]) -> usize {
    match rest.get(1) {
        Some('\\') => (rest.iter().skip(3).position(|&c| c == '\'')).map_or(0, |found| found + 3),
        _ if rest.get(2) == Some(&'\'') => 2,
        _ => 0,
    }
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
    crate::context_assistance_engine::written_name(line)
}

/// The test function a line calls, as `it` in `it("adds", () => {` or
/// `test.each([...])(...)`, with `describe` and `suite` for the groups.
pub(super) fn test_call(line: &str) -> Option<&'static str> {
    let text = line.trim_start();
    let called = ["describe", "suite", "it", "test"]
        .into_iter()
        .find(|name| text.starts_with(name))?;
    let mut rest = &text[called.len()..];
    // `.only`, `.skip`, `.each`, `.concurrent` and the like.
    while let Some(after) = rest.strip_prefix('.') {
        let word = after
            .find(|c: char| !c.is_alphanumeric())
            .unwrap_or(after.len());
        if word == 0 {
            return None;
        }
        rest = &after[word..];
    }
    rest.starts_with(['(', '`']).then_some(called)
}

/// Whether a section opening is a test by its name, `def test_parse` or
/// `func TestParse`, or by the call it makes, `it("parses", ...)`. A group,
/// `describe("URL tests", ...)`, is none, whatever its label says.
pub(super) fn named_test(opening: &str) -> bool {
    match test_call(opening) {
        Some(called) => matches!(called, "it" | "test"),
        None => written_name(opening).is_some_and(|name| name.to_lowercase().starts_with("test")),
    }
}

/// A test's name as its runner reports it: a test call with its label,
/// `test "adds a slash"` or `it name`, or the name a definition gives.
pub(super) fn test_name(opening: &str) -> Option<String> {
    match test_call(opening) {
        Some(called) => Some(match test_label(opening) {
            Some(label) => format!("{called} {label}"),
            None => called.to_owned(),
        }),
        None => written_name(opening),
    }
}

/// The quoted text or first value a test call passes; past a `.each` table,
/// the title after it, `"joins %s"` in `it.each([...])("joins %s", ...)`.
/// None when the line does not hold it, as under a tagged-template table.
fn test_label(line: &str) -> Option<String> {
    let text = line.trim_start();
    let head = text.find(['(', '`'])?;
    let args = if text[..head].contains(".each") {
        text.split_once(")(")?.1
    } else {
        text[head..].strip_prefix('(')?
    };
    let args = args.trim_start();
    let label = match args.chars().next() {
        Some(quote @ ('"' | '\'' | '`')) => {
            let inner = &args[1..];
            let end = inner.find(quote).unwrap_or(inner.len());
            format!("{quote}{}{quote}", &inner[..end])
        }
        _ => args
            .split([',', ')'])
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned(),
    };
    let label: String = label.chars().take(60).collect();
    (!label.is_empty()).then_some(label)
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

/// Whether `opening` starts a test class that gets its tests from the classes
/// it inherits, as `class MRUDecoratorTest(TestCase, DecoratorTestMixin):`
/// does. Its own body is what names the code those tests run.
pub(super) fn inheriting_test_class(opening: &str) -> bool {
    let name = written_name(opening).unwrap_or_default();
    opening.trim_start().starts_with("class ")
        && opening.contains('(')
        && (name.ends_with("Test") || name.ends_with("Tests"))
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
