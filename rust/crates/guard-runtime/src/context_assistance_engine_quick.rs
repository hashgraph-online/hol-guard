//! Code for a prompt that arrives while CIGAR is still starting, such as the
//! first prompt of a session. Guard reads the matched files itself, through
//! the checks an automatic scope applies, and shows the part of each that
//! holds the most of the prompt's words. A folder picked in the dashboard
//! keeps to its picked files, as it does once CIGAR is up.
use super::*;
use crate::policy_store::context_assistance_registry::picked;
use std::path::Path;
use std::time::Instant;

/// Files read for one prompt, so the read stays inside the hook's budget.
const MAX_FILES: usize = 3;
/// Words that open a definition line, after any modifiers.
const DEFINERS: [&str; 13] = [
    "def ",
    "class ",
    "fn ",
    "function ",
    "func ",
    "struct ",
    "enum ",
    "trait ",
    "impl ",
    "interface ",
    "type ",
    "mod ",
    "module ",
];
/// Words that bind a value: a definition only at a file's top level, since
/// inside a function they name a local.
const BINDERS: [&str; 3] = ["const ", "let ", "var "];
/// Marks that open or close a docstring or block comment, whose lines are
/// text about the code, not definitions.
const QUOTES: [&str; 4] = ["\"\"\"", "'''", "/*", "*/"];
/// Prose files, whose lines read as words, not definitions.
const PROSE: [&str; 6] = ["md", "markdown", "mdx", "txt", "rst", "adoc"];
/// Modifiers that may come before a definer.
const MODIFIERS: [&str; 11] = [
    "export ",
    "default ",
    "pub ",
    "pub(crate) ",
    "pub(super) ",
    "async ",
    "static ",
    "public ",
    "private ",
    "protected ",
    "abstract ",
];

/// The project root a prompt may draw on: an agent app, a folder outside
/// Guard's home, and agent context on with workspace files for that folder.
pub(super) fn screened(home: &Path, workspace: &Path, app: &str) -> Option<SourceRoot> {
    if crate::guard_config_harness::canonical_harness_id(app) != Some(app) {
        return None;
    }
    let root = SourceRoot::inspect(workspace).ok()?;
    let permitted = !root.path().starts_with(home)
        && effective(home, &root).is_ok_and(|policy| {
            policy.features.agent_context && policy.sources.workspace_documents
        });
    permitted.then_some(root)
}

/// How many of `words` the text holds.
pub(super) fn said(text: &str, words: &[String]) -> usize {
    let text = text.to_lowercase();
    words.iter().filter(|w| text.contains(w.as_str())).count()
}

/// How many of `words` the text's definition lines name, leaving out lines
/// inside a docstring or block comment.
fn defined(text: &str, words: &[String]) -> usize {
    let mut quoted = false;
    let mut definitions = Vec::new();
    for line in text.lines() {
        if !quoted && definition(line) {
            definitions.push(line);
        }
        let marks: usize = QUOTES.iter().map(|mark| line.matches(mark).count()).sum();
        quoted ^= marks % 2 == 1;
    }
    said(&definitions.join("\n"), words)
}

/// A line that opens a function, type or top-level value definition.
fn definition(line: &str) -> bool {
    let top_level = !line.starts_with(char::is_whitespace);
    let mut rest = line.trim_start();
    while let Some(after) = MODIFIERS
        .iter()
        .find_map(|modifier| rest.strip_prefix(modifier))
    {
        rest = after;
    }
    DEFINERS.iter().any(|definer| rest.starts_with(definer))
        || (top_level && BINDERS.iter().any(|binder| rest.starts_with(binder)))
}

/// Whether `path` names a prose file.
fn prose(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| PROSE.contains(&extension.to_ascii_lowercase().as_str()))
}

/// The part of `file` that defines the most of `words`, then holds the most
/// of them, the earliest on a tie, with how many it holds. A part that
/// defines what the prompt asks about beats one that only mentions it, such
/// as a module's opening comment. A prose file keeps to the word count.
/// `None` when no part holds any.
pub(super) fn best_part(file: &AdmittedFile, words: &[String]) -> Option<(usize, PickedExcerpt)> {
    let code = !prose(Path::new(&file.relative_path));
    let (_, score, doc) = file
        .documents
        .iter()
        .map(|doc| {
            let names = if code { defined(&doc.text, words) } else { 0 };
            (names, said(&doc.text, words), doc)
        })
        .filter(|(_, score, _)| *score > 0)
        .max_by_key(|(names, score, doc)| (*names, *score, std::cmp::Reverse(doc.start_line)))?;
    let start = u64::from(doc.start_line);
    let lines = doc.text.lines().count().max(1) as u64;
    Some((
        score,
        PickedExcerpt {
            path: file.relative_path.clone(),
            start_line: start,
            end_line: start + lines - 1,
            text: doc.text.clone(),
        },
    ))
}

/// The best part of each of the first few matched files, best file first,
/// and the names of the matched files that passed the same checks, enough
/// to name `others` files beyond the ones shown. A file the source screen
/// refuses (a secret, a key, binary text) is neither shown nor named, and
/// reading stops at `until`.
pub(crate) fn quick_excerpts(
    home: &Path,
    workspace: &Path,
    app: &str,
    found: &[String],
    words: &[String],
    others: usize,
    until: Instant,
) -> (Vec<PickedExcerpt>, Vec<String>) {
    let mut parts = Vec::new();
    let mut names = Vec::new();
    let Some(root) = screened(home, workspace, app) else {
        return (parts, names);
    };
    let chosen = picked_files(home, root.path());
    let allowed = found
        .iter()
        .filter(|relative| chosen.as_ref().is_none_or(|files| files.contains(relative)));
    for relative in allowed {
        if Instant::now() >= until || names.len() >= MAX_FILES + others {
            break;
        }
        let Some(file) = stamp(&root, relative).and_then(|_| root.read(relative).ok()) else {
            continue;
        };
        names.push(relative.clone());
        if parts.len() < MAX_FILES {
            parts.extend(best_part(&file, words).map(|(_, part)| part));
        }
    }
    (parts, names)
}

/// The files picked in the dashboard for `root`, which CIGAR uses for every
/// app in place of the files a prompt matches. `None` when there is no pick.
fn picked_files(home: &Path, root: &Path) -> Option<Vec<String>> {
    picked::load(home)
        .unwrap_or_default()
        .into_iter()
        .find(|folder| folder.workspace == root && !folder.sources.is_empty())
        .map(|folder| folder.sources)
}

#[cfg(test)]
#[path = "context_assistance_engine_quick_tests.rs"]
mod tests;
