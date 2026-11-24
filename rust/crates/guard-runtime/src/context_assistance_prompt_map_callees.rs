//! The project functions a named function calls. Changing or reading a
//! function, an agent opens the helpers it calls to learn what they return
//! and when they fail; the first line of each, with its lines, and the code
//! of the short ones save it that look.
use super::super::more::{fenced, whole};
use super::super::rename::stubbed;
use super::super::{written_name, Asked, Entry, File, Kind, Pick, Span, MAX_LINE_CHARS};

/// How many named functions have their calls looked up.
const MAX_CALLERS: usize = 2;
/// The most helpers listed.
const MAX_CALLEES: usize = 6;
/// The most code shown under the listed helpers.
const MAX_CALLEE_CODE_CHARS: usize = 1_200;
/// Shorter names are too often a local closure or a library call.
const MIN_NAME_CHARS: usize = 3;
/// Words a method calls its own class or value through.
const OWN_RECEIVERS: [&str; 4] = ["self", "this", "cls", "Self"];

/// For the first named functions shown whole, the functions they call that
/// the project defines once, outside tests: each as its range and first line,
/// with the code of the short ones while it fits. A helper already shown, by
/// the map or an earlier prompt, is left out. Not given for a rename, a
/// review of changes, or a function still to be written.
pub(in super::super) fn callees(
    files: &[File],
    chosen: &[Pick],
    asked: &Asked,
    shown: &[Span],
) -> Option<(String, Entry)> {
    if asked.everywhere || asked.changes {
        return None;
    }
    let callers: Vec<(&File, usize)> = (chosen.iter())
        .filter(|pick| pick.whole && !pick.base)
        .map(|pick| (&files[pick.file], pick.at))
        .filter(|(file, at)| !file.container(*at) && !stubbed(file, *at))
        .take(MAX_CALLERS)
        .collect();
    let first = callers.first()?;
    let mut names: Vec<(Option<(&File, usize)>, &str)> = Vec::new();
    for &(file, at) in &callers {
        let section = &file.sections[at];
        let body = file
            .lines
            .get(section.start.checked_sub(1)?..section.end.min(file.lines.len()))?;
        let python = file.path.ends_with(".py");
        for line in body {
            for (through, name) in called(line, python) {
                // Its own name is a recursive call; another caller's name is
                // a helper, left out below once it is found to be shown.
                let own_name = section.name.as_deref() == Some(&*stored(name));
                if name.len() < MIN_NAME_CHARS || own_name {
                    continue;
                }
                let sibling = match through {
                    None => None,
                    Some(word) if OWN_RECEIVERS.contains(&word) => Some((file, at)),
                    Some(_) => continue,
                };
                let same = |seen: &Option<(&File, usize)>| match (seen, sibling) {
                    (None, None) => true,
                    (Some((a, x)), Some((b, y))) => a.path == b.path && *x == y,
                    _ => false,
                };
                if !(names.iter()).any(|(seen, called)| *called == name && same(seen)) {
                    names.push((sibling, name));
                }
            }
        }
    }
    let mut lines = Vec::new();
    let mut spans = Vec::new();
    let mut listed: Vec<(&str, usize)> = Vec::new();
    let mut room = MAX_CALLEE_CODE_CHARS;
    for (sibling, name) in names {
        let Some((file, at)) = defined_once(files, name, sibling) else {
            continue;
        };
        let place = (file.path, at);
        let picked =
            (chosen.iter()).any(|pick| files[pick.file].path == file.path && pick.at == at);
        if picked || listed.contains(&place) {
            continue;
        }
        listed.push(place);
        let section = &file.sections[at];
        let opening: String = file.opening(at).chars().take(MAX_LINE_CHARS).collect();
        let mut line = format!("{}:{}-{} {opening}", file.path, section.start, section.end);
        if let Some((span, code)) = whole(file, at) {
            if shown.contains(&span) {
                continue;
            }
            if code.len() <= room {
                room -= code.len();
                line.push_str(&fenced(&code));
                spans.push(span);
            }
        }
        lines.push(line);
        if lines.len() == MAX_CALLEES {
            break;
        }
    }
    if lines.is_empty() {
        return None;
    }
    let caller = written_name(first.0.opening(first.1))?;
    let text = lines.join("\n");
    let entry = Entry {
        code: MAX_CALLEE_CODE_CHARS - room,
        text,
        shown: spans,
    };
    Some((format!("Project functions {caller} calls:"), entry))
}

/// The names on `line` written right before an opening parenthesis, in
/// order, each with the word it is called through: `withBase(` (none),
/// `self.parse(` (`self`), `Self::new(` (`Self`). A call through anything
/// else, such as `(a).b(`, comes with an empty word. A comment, `//` or a
/// Python `#` outside quotes, holds no calls.
fn called(line: &str, python: bool) -> Vec<(Option<&str>, &str)> {
    let code = line.split("//").next().unwrap_or(line);
    let code = if python {
        &code[..hash_comment(code)]
    } else {
        code
    };
    let word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let bytes = code.as_bytes();
    let mut names = Vec::new();
    for (end, &byte) in bytes.iter().enumerate() {
        if byte != b'(' {
            continue;
        }
        let from = bytes[..end]
            .iter()
            .rposition(|&b| !word(b))
            .map_or(0, |at| at + 1);
        if from == end || bytes[from].is_ascii_digit() {
            continue;
        }
        let before = &code[..from];
        let through =
            if let Some(rest) = (before.strip_suffix('.')).or_else(|| before.strip_suffix("::")) {
                let start = rest.bytes().rposition(|b| !word(b)).map_or(0, |at| at + 1);
                Some(&rest[start..])
            } else {
                None
            };
        names.push((through, &code[from..end]));
    }
    names
}

/// Where a Python `#` comment starts on `code`, outside quoted text; its
/// length when there is none.
fn hash_comment(code: &str) -> usize {
    let mut quote = None;
    let mut escaped = false;
    for (at, c) in code.char_indices() {
        match quote {
            Some(_) if escaped => escaped = false,
            Some(_) if c == '\\' => escaped = true,
            Some(open) if c == open => quote = None,
            Some(_) => {}
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c == '#' => return at,
            None => {}
        }
    }
    code.len()
}

/// The one function named `name` outside tests, if the files read define
/// exactly one: a top-level function for a plain call, or a method beside
/// the caller (`sibling`) for one through `self`, `this`, `cls` or `Self`.
fn defined_once<'f, 'a>(
    files: &'f [File<'a>],
    name: &str,
    sibling: Option<(&File, usize)>,
) -> Option<(&'f File<'a>, usize)> {
    let mut found = None;
    for file in files.iter().filter(|file| file.kind == Kind::Source) {
        for (at, section) in file.sections.iter().enumerate() {
            let named = section.name.as_deref() == Some(&*stored(name));
            if !named || file.container(at) || !placed(file, at, sibling) {
                continue;
            }
            if found.is_some() {
                return None;
            }
            found = Some((file, at));
        }
    }
    found
}

/// Whether the definition at `at` can be what the call reaches.
fn placed(file: &File, at: usize, sibling: Option<(&File, usize)>) -> bool {
    let Some((caller, from)) = sibling else {
        return file.parent[at].is_none();
    };
    caller.path == file.path
        && caller.parent[from].is_some()
        && file.parent[at] == caller.parent[from]
}

/// A name as sections keep it: lowercased, without underscores.
fn stored(name: &str) -> String {
    name.chars()
        .filter(|&c| c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
#[path = "context_assistance_prompt_map_callees_tests.rs"]
mod tests;
