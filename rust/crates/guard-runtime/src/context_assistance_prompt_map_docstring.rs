//! What the map shows of a Python function a prompt about its docstring
//! names. A long function is not shown whole, but such an edit needs only its
//! signature and docstring, so the map shows those lines. A docstring that is
//! not a raw string turns `\n` in an example into a newline, so the map says
//! to write a backslash twice. The map names the command that runs just that
//! function's doctest: shown none, agents guessed a pytest node id, then ran
//! the whole module, its tests, and read the file again after the edit.
//! `python -m doctest` loads a file outside its package, so a module with
//! relative imports fails there.
use super::super::seen::Span;
use super::more::{prompt_words, whole};
use super::{Asked, File};
use std::path::Path;

const WORDS: [&str; 4] = ["docstring", "docstrings", "doctest", "doctests"];
const EXAMPLES: [&str; 4] = ["doctest", "doctests", "example", "examples"];
/// Words of a prompt that reads a docstring for what code should do.
const BEHAVIOR: [&str; 7] = [
    "implement",
    "implemented",
    "says",
    "describe",
    "describes",
    "bug",
    "fails",
];
/// The most lines of a long function's signature and docstring shown.
const MAX_HEAD_LINES: usize = 80;
const NOT_RAW: &str = "\nIts docstring is not a raw string: write a backslash in an example \
twice (`\\\\n` shows as `\\n`).";
const DOCTESTS: &str = "\nRun its doctests with `python -m pytest --doctest-modules {path}`: \
`python -m doctest` loads the file outside its package, so its relative imports fail.";
const DOCTEST: &str = "\nRun just its doctest with `{command}`. That run is the check an added \
example needs, and the edit's own reply confirms the edit, so the file need not be read again.";
const DOCTEST_AGAIN: &str = "\nRun just its doctest with `{command}`.";
const OUTSIDE: &str = " `python -m doctest` would load the file outside its package, where its \
relative imports fail.";

/// True when the prompt asks to write a docstring or doctest: it shows a
/// `>>>` line, or names a docstring and asks for an example or does not read
/// it for what the code should do ("implement it so it does what its
/// docstring says" asks for the code). An example alone is not one: "fix
/// example.py" or "the examples folder" name no docstring.
pub(super) fn asks_for_docstring(prompt: &str) -> bool {
    let words: Vec<String> = prompt_words(prompt).collect();
    let has = |list: &[&str]| words.iter().any(|word| list.contains(&word.as_str()));
    prompt.contains(">>>") || (has(&WORDS) && (has(&EXAMPLES) || !has(&BEHAVIOR)))
}

/// The notes given beside a function shown earlier: each is said in full
/// once, and a later function gets only the command for its own doctest.
#[derive(Clone, Copy, Default)]
pub(super) struct Said {
    raw: bool,
    run: bool,
}

impl Said {
    /// What has been said once `note` is shown too.
    pub(super) fn and(self, note: &str) -> Said {
        Said {
            raw: self.raw || note.contains(NOT_RAW),
            run: self.run || note.contains("doctest"),
        }
    }
}

/// The code shown for a named definition, the span it fills and a note to
/// put after it: the whole definition when it is short, or, for a prompt
/// about docstrings, a long Python function's signature and docstring, with
/// how to write a backslash and run the doctests when that matters, unless
/// `said` holds it already.
pub(super) fn shown(
    file: &File,
    at: usize,
    asked: &Asked,
    said: Said,
) -> Option<(Span, String, String)> {
    let python = asked.docstring && file.path.ends_with(".py") && !file.container(at);
    let head = python.then(|| head(file, at)).flatten();
    let mut note = String::new();
    if !said.raw && head.is_some_and(|(_, raw)| raw == Some(false)) {
        note.push_str(NOT_RAW);
    }
    match python.then(|| command(file, at, &asked.root)).flatten() {
        Some(command) if said.run => {
            note.push_str(&DOCTEST_AGAIN.replace("{command}", &command));
        }
        Some(command) => {
            note.push_str(&DOCTEST.replace("{command}", &command));
            if relative(file) {
                note.push_str(OUTSIDE);
            }
        }
        None if python && !said.run && plain(file.path) && relative(file) => {
            note.push_str(&DOCTESTS.replace("{path}", file.path));
        }
        None => {}
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
        let (code, opened) = scanned(line);
        depth += opened;
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
    // A comment is not a statement, so a docstring may follow one.
    let (index, text) = (lines.iter().enumerate().skip(from))
        .map(|(index, line)| (index, line.trim_start()))
        .find(|(_, text)| !text.is_empty() && !text.starts_with('#'))?;
    let prefix = text.find(['"', '\'']).filter(|prefix| *prefix <= 2)?;
    if !text[..prefix].chars().all(|c| "rRuUbB".contains(c)) {
        return None;
    }
    let quote = ["\"\"\"", "'''", "\"", "'"]
        .into_iter()
        .find(|quote| text[prefix..].starts_with(quote))?;
    let raw = Some(text[..prefix].contains(['r', 'R']));
    if closes(&text[prefix + quote.len()..], quote) {
        return Some((index, raw));
    }
    // A string in single quotes ends on its own line.
    if quote.len() == 1 {
        return None;
    }
    let close = (lines.iter().enumerate().skip(index + 1)).find(|(_, line)| closes(line, quote))?;
    Some((close.0, raw))
}

/// Whether `text` holds `quote` with no backslash before it.
fn closes(text: &str, quote: &str) -> bool {
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        if c == '\\' {
            chars.next();
        } else if text[at..].starts_with(quote) {
            return true;
        }
    }
    false
}

/// A line of a signature without its comment, and the brackets it opens less
/// those it closes, both read outside string literals: `marker="#"` holds
/// no comment and `pattern="("` no bracket.
fn scanned(line: &str) -> (&str, i32) {
    let mut depth = 0;
    let mut open = None;
    let mut chars = line.char_indices();
    while let Some((at, c)) = chars.next() {
        match (open, c) {
            (Some(_), '\\') => {
                chars.next();
            }
            (Some(quote), _) if c == quote => open = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => open = Some(c),
            (None, '#') => return (&line[..at], depth),
            (None, '(' | '[' | '{') => depth += 1,
            (None, ')' | ']' | '}') => depth -= 1,
            _ => {}
        }
    }
    (line, depth)
}

/// The command running just the doctest of the function at `at`, by the
/// node id pytest gives it: the file, then `<module>.<qualified name>`, where
/// the module is dotted from the folders above it holding an `__init__.py`
/// under `root`, as pytest imports it. A node id picks that one doctest,
/// where `-k remap` would run `remap_more`'s too. None for a path or name a
/// shell would read as more than itself, a function inside another, whose
/// doctest pytest does not collect, or one inside a member, whose doctest
/// name holds more classes than the map knows.
fn command(file: &File, at: usize, root: &Path) -> Option<String> {
    let outer = file.parent[at];
    let nested = outer.is_some_and(|outer| !file.container(outer) || file.parent[outer].is_some());
    if !plain(file.path) || nested {
        return None;
    }
    let (folder, name) = file.path.rsplit_once('/').unwrap_or(("", file.path));
    let stem = name.strip_suffix(".py")?;
    let mut folders: Vec<&str> = folder.split('/').filter(|part| !part.is_empty()).collect();
    // A package's `__init__.py` is the module named for its folder.
    let mut module: Vec<&str> = if stem == "__init__" {
        Vec::new()
    } else {
        vec![stem]
    };
    while !folders.is_empty() && root.join(folders.join("/")).join("__init__.py").is_file() {
        module.push(folders.pop()?);
    }
    module.reverse();
    let qualified = file.qualified(at);
    let words = (module.iter().copied().chain(qualified.split('.'))).all(|name| {
        name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    });
    (words && !module.is_empty() && !qualified.is_empty()).then(|| {
        format!(
            "python -m pytest -q --doctest-modules {}::{}.{qualified}",
            file.path,
            module.join(".")
        )
    })
}

/// Whether a path can be named in a command as it is.
fn plain(path: &str) -> bool {
    !path.starts_with('-') && (path.chars()).all(|c| c.is_alphanumeric() || "/._-".contains(c))
}

/// Whether a Python file imports from its own package by a relative import.
fn relative(file: &File) -> bool {
    (file.lines.iter()).any(|line| line.trim_start().starts_with("from ."))
}
