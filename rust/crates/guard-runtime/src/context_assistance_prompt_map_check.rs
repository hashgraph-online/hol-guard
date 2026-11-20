//! For a Python definition left to be written, on Claude Code, the one test
//! run that checks the edit: the test files named after its class, itself or
//! its file. Without it the agent guessed test ids, often in a shared base
//! class the runner never collects on its own, then ran the test file and
//! then the whole suite, a request each.
use super::super::{written_name, Asked, Entry, File, Kind, Pick};
use super::stubbed;

/// The most test files the command runs.
const MAX_FILES: usize = 3;

/// `tests` with the command first, when the prompt asks for a stub to be
/// written on Claude Code and test files are named after it.
pub(in super::super) fn with(
    mut tests: Vec<Entry>,
    files: &[File],
    chosen: &[Pick],
    asked: &Asked,
) -> Vec<Entry> {
    if let Some(line) = line(files, chosen, asked) {
        tests.insert(0, Entry::plain(line));
    }
    tests
}

fn line(files: &[File], chosen: &[Pick], asked: &Asked) -> Option<String> {
    if cfg!(windows) || !asked.reads_first || asked.everywhere || asked.lookup || asked.changes {
        return None;
    }
    let root = asked.root.to_str()?;
    if root.is_empty() || root.chars().any(|c| c == '\'' || c.is_control()) {
        return None;
    }
    let pick = chosen.iter().find(|pick| {
        let file = &files[pick.file];
        pick.whole && file.path.ends_with(".py") && stubbed(file, pick.at)
    })?;
    let file = &files[pick.file];
    let mut names: Vec<String> = Vec::new();
    let mut add = |name: &str| {
        let lower = name.to_lowercase();
        if let Some(first) = first_word(name).filter(|first| first.len() >= 2) {
            names.push(first.to_lowercase());
        }
        names.push(lower);
    };
    if let Some(own) = written_name(file.opening(pick.at)) {
        add(&own);
    }
    if let Some(outer) = file.parent[pick.at].and_then(|at| written_name(file.opening(at))) {
        add(&outer);
    }
    let stem = file.path.rsplit('/').next()?.strip_suffix(".py")?;
    if !stem.starts_with("__") {
        add(stem);
    }
    let tests: Vec<&str> = (files.iter())
        .filter(|test| test.kind == Kind::Test && plain(test.path))
        .filter(|test| named_after(test.path, &names))
        .map(|test| test.path)
        .collect();
    if tests.is_empty() || tests.len() > MAX_FILES {
        return None;
    }
    Some(format!(
        "After the edit, run `cd '{root}' && python -m pytest -q {}` once to check it.",
        tests.join(" ")
    ))
}

/// A test file called after one of `names`: `test_x_axis.py` for `x_axis`
/// whole, `test_tlru.py` for `tlru`, one part of its name.
fn named_after(path: &str, names: &[String]) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let stem = name.strip_suffix(".py").unwrap_or_default();
    let key = (stem.strip_prefix("test_")).or_else(|| stem.strip_suffix("_test"));
    key.is_some_and(|key| {
        names.iter().any(|n| n == key) || key.split('_').any(|part| names.iter().any(|n| n == part))
    })
}

/// The first word of a name written in camel case or with underscores:
/// `TLRUCache` gives `TLRU`, `rr_cache` gives `rr`.
fn first_word(name: &str) -> Option<&str> {
    let name = name.trim_start_matches('_');
    let chars: Vec<(usize, char)> = name.char_indices().collect();
    for (i, &(at, c)) in chars.iter().enumerate().skip(1) {
        let before = chars[i - 1].1;
        let next = chars.get(i + 1).map(|(_, next)| *next);
        let upper_after_lower = c.is_uppercase() && before.is_lowercase();
        let acronym_end =
            c.is_uppercase() && before.is_uppercase() && next.is_some_and(char::is_lowercase);
        if c == '_' || upper_after_lower || acronym_end {
            return Some(&name[..at]);
        }
    }
    None
}

fn plain(path: &str) -> bool {
    !path.starts_with(['-', '/'])
        && !path.split('/').any(|part| part == "..")
        && (path.chars()).all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'))
}

#[cfg(test)]
#[path = "context_assistance_prompt_map_check_tests.rs"]
mod tests;
