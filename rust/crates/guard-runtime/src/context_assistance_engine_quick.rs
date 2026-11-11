//! Code for a prompt that arrives while CIGAR is still starting, such as the
//! first prompt of a session. Guard reads the matched files itself, through
//! the checks an automatic scope applies, and shows the part of each that
//! holds the most of the prompt's words. Files picked by hand, in the
//! dashboard or for an app, keep the read to those files, as they do for
//! CIGAR.
use super::*;
use crate::policy_store::context_assistance_registry::picked;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// Files read for one prompt, so the read stays inside the hook's budget.
const MAX_FILES: usize = 3;
/// Files kept out for what they hold that one prompt reads to place lines in,
/// and the most of each, the size Guard's own read takes.
const MAX_WITHHELD_FILES: usize = 4;
const MAX_WITHHELD_BYTES: usize = 262_144;
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
/// Marks that open and close a docstring, whose lines are text about the
/// code, not definitions.
const DOCSTRINGS: [&str; 2] = ["\"\"\"", "'''"];
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

/// Files picked by hand for one project in a running worker, and the app
/// they were picked for.
pub(super) struct Hand {
    pub(super) root: PathBuf,
    pub(super) app: String,
    pub(super) files: Vec<String>,
}

type Hands = Mutex<BTreeMap<PathBuf, Vec<Hand>>>;

/// Each Guard home's hand picks as of its worker's last request, so a prompt
/// Guard reads itself while CIGAR is busy keeps to the files CIGAR would use.
/// A worker that stops leaves its last record, which can only narrow what
/// Guard reads, until the next worker replaces it.
fn hands() -> &'static Hands {
    static HANDS: OnceLock<Hands> = OnceLock::new();
    HANDS.get_or_init(Default::default)
}

pub(super) fn publish(home: &Path, picked: Vec<Hand>) {
    if let Ok(mut all) = hands().lock() {
        all.insert(home.to_path_buf(), picked);
    }
}

/// The files CIGAR keeps to for `app` in `root`: a running pick for that
/// app, else a dashboard pick, else none. A record Guard cannot read keeps
/// to no files at all.
fn kept_to(home: &Path, root: &Path, app: &str) -> Option<Vec<String>> {
    let live = {
        let Ok(all) = hands().lock() else {
            return Some(Vec::new());
        };
        all.get(home).and_then(|picked| {
            picked
                .iter()
                .filter(|hand| hand.root == root)
                .filter_map(|hand| Some((pick_rank(&hand.app, app, hand.files.len())?, hand)))
                .min_by_key(|(rank, _)| *rank)
                .map(|(_, hand)| hand.files.clone())
        })
    };
    live.or_else(|| picked_files(home, root))
}

/// Whether `app` may still draw on `workspace`, checked again after a read
/// in case project context was turned off for it meanwhile.
pub(crate) fn project_context_on(home: &Path, workspace: &Path, app: &str) -> bool {
    screened(home, workspace, app).is_some()
}

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
    let mut closer: Option<&str> = None;
    let mut definitions = Vec::new();
    for line in text.lines() {
        closer = match closer {
            Some(mark) => (!line.contains(mark)).then_some(mark),
            None => {
                if definition(line) {
                    definitions.push(line);
                }
                opened(line)
            }
        };
    }
    said(&definitions.join("\n"), words)
}

/// The mark that closes a docstring or block comment `line` leaves open. A
/// block comment opens only at the start of a line, so a `/*` inside a
/// string such as a glob, or at the end of a line comment, opens nothing.
pub(crate) fn opened(line: &str) -> Option<&'static str> {
    let comment = line.trim_start().strip_prefix("/*");
    if comment.is_some_and(|rest| !rest.contains("*/")) {
        return Some("*/");
    }
    DOCSTRINGS
        .into_iter()
        .find(|mark| line.matches(mark).count() % 2 == 1)
}

/// A line that opens a function, type or top-level value definition.
pub(crate) fn definition(line: &str) -> bool {
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
pub(crate) fn prose(path: &Path) -> bool {
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
    let chosen = kept_to(home, root.path(), app);
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

/// The whole text of each of `found` that passes the checks
/// `quick_excerpts` applies, in order, reading at most `limit` files and
/// stopping at `until`.
pub(crate) fn screened_texts(
    home: &Path,
    workspace: &Path,
    app: &str,
    found: &[String],
    limit: usize,
    until: Instant,
) -> Vec<(String, String)> {
    let Some(root) = screened(home, workspace, app) else {
        return Vec::new();
    };
    let chosen = kept_to(home, root.path(), app);
    let mut texts = Vec::new();
    let allowed = found
        .iter()
        .filter(|relative| chosen.as_ref().is_none_or(|files| files.contains(relative)));
    for relative in allowed {
        if Instant::now() >= until || texts.len() >= limit {
            break;
        }
        let Some(file) = stamp(&root, relative).and_then(|_| root.read(relative).ok()) else {
            continue;
        };
        let text: String = file.documents.iter().map(|doc| doc.text.as_str()).collect();
        texts.push((relative.clone(), text));
    }
    texts
}

/// The text of each of `found` that `screened_texts` keeps out only for what
/// it holds, such as a line Guard's secret check takes for a credential, and
/// is not already in `read`. A file whose path the checks refuse is left
/// out. The text places definitions by line and is never shown.
pub(crate) fn withheld_texts(
    home: &Path,
    workspace: &Path,
    app: &str,
    found: &[String],
    read: &[(String, String)],
    until: Instant,
) -> Vec<(String, String)> {
    let Some(root) = screened(home, workspace, app) else {
        return Vec::new();
    };
    let Ok(canonical) = std::fs::canonicalize(root.path()) else {
        return Vec::new();
    };
    let chosen = kept_to(home, root.path(), app);
    let mut texts = Vec::new();
    for relative in found {
        if Instant::now() >= until || texts.len() >= MAX_WITHHELD_FILES {
            break;
        }
        let picked = chosen.as_ref().is_none_or(|files| files.contains(relative));
        if !picked || read.iter().any(|(path, _)| path == relative) {
            continue;
        }
        let decision = guard_secure_fs::classify_project_document(relative, root.path());
        let allowed = decision.allowed;
        let path = (decision.resolved_path).filter(|path| allowed && path.starts_with(&canonical));
        let Some(path) = path else {
            continue;
        };
        if !matches!(root.read(relative), Err(RuntimeError::ScopeDenied)) {
            continue;
        }
        let bounded = guard_secure_fs::read_bounded(&path, MAX_WITHHELD_BYTES).ok();
        if let Some(text) = bounded.and_then(|file| String::from_utf8(file.bytes).ok()) {
            texts.push((relative.clone(), text));
        }
    }
    texts
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
