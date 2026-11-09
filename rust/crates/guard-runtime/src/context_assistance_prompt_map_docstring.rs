//! What the map shows of a Python function a prompt about its docstring
//! names. A long function is not shown whole, but such an edit needs only its
//! signature and docstring, so the map shows those lines. A docstring that is
//! not a raw string turns `\n` in an example into a newline, so the map says
//! to write a backslash twice.
use super::super::seen::Span;
use super::more::whole;
use super::{Asked, File};

const WORDS: [&str; 4] = ["docstring", "docstrings", "doctest", "doctests"];
/// The most lines of a long function's signature and docstring shown.
const MAX_HEAD_LINES: usize = 80;
const NOT_RAW: &str = "\nIts docstring is not a raw string: write a backslash in an example \
twice (`\\\\n` shows as `\\n`).";

/// True when the prompt asks about docstrings or doctests.
pub(super) fn asks_for_docstring(prompt: &str) -> bool {
    prompt
        .split(|c: char| !c.is_alphanumeric())
        .any(|word| WORDS.contains(&word.to_lowercase().as_str()))
}

/// The code shown for a named definition, the span it fills and a note to
/// put after it: the whole definition when it is short, or, for a prompt
/// about docstrings, a long Python function's signature and docstring.
pub(super) fn shown(file: &File, at: usize, asked: &Asked) -> Option<(Span, String, String)> {
    let python = asked.docstring && file.path.ends_with(".py") && !file.container(at);
    let head = python.then(|| head(file, at)).flatten();
    let mut note = String::new();
    if head.is_some_and(|(_, raw)| raw == Some(false)) {
        note.push_str(NOT_RAW);
    }
    if let Some((span, code)) = whole(file, at) {
        return Some((span, code, note));
    }
    let (last, raw) = head?;
    let start = file.sections[at].start;
    let code = file.lines.get(start - 1..start + last)?.join("\n");
    let end = start + last;
    let what = if raw.is_some() {
        "its signature and docstring"
    } else {
        "its signature; it has no docstring"
    };
    note.insert_str(0, &format!("\nThose are lines {start}-{end} only, {what}."));
    Some((
        Span::new(file.path, start as u64, end as u64, &code),
        code,
        note,
    ))
}

/// The index, from the definition's first line, of the last line of a
/// Python function's signature and docstring, and whether that docstring is
/// a raw string, or `None` when it has none.
fn head(file: &File, at: usize) -> Option<(usize, Option<bool>)> {
    let section = &file.sections[at];
    let lines = file.lines.get(section.start.checked_sub(1)?..section.end)?;
    let def = lines.iter().position(|line| {
        let line = line.trim_start();
        line.starts_with("def ") || line.starts_with("async def ")
    })?;
    let mut depth = 0_i32;
    let mut signed = None;
    for (index, line) in lines.iter().enumerate().skip(def) {
        let code = line.split('#').next().unwrap_or_default();
        for c in code.chars() {
            match c {
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => depth -= 1,
                _ => {}
            }
        }
        if depth <= 0 && code.trim_end().ends_with(':') {
            signed = Some(index);
            break;
        }
    }
    let signed = signed?;
    let found = docstring(lines, signed + 1).unwrap_or((signed, None));
    (found.0 < MAX_HEAD_LINES).then_some(found)
}

/// Where the docstring that opens the body at `from` ends, and whether it is
/// raw, when the body opens with one.
fn docstring(lines: &[&str], from: usize) -> Option<(usize, Option<bool>)> {
    let (index, line) =
        (lines.iter().enumerate().skip(from)).find(|(_, line)| !line.trim().is_empty())?;
    let text = line.trim_start();
    let prefix = text.find(['"', '\'']).filter(|prefix| *prefix <= 2)?;
    if !text[..prefix].chars().all(|c| "rRuUbB".contains(c)) {
        return None;
    }
    let quote = ["\"\"\"", "'''"]
        .into_iter()
        .find(|quote| text[prefix..].starts_with(quote))?;
    let raw = Some(text[..prefix].contains(['r', 'R']));
    if text[prefix + 3..].contains(quote) {
        return Some((index, raw));
    }
    let close =
        (lines.iter().enumerate().skip(index + 1)).find(|(_, line)| line.contains(quote))?;
    Some((close.0, raw))
}
