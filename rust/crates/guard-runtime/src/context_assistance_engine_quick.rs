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

/// The part of `file` that holds the most of `words`, the earliest on a tie,
/// with how many it holds. `None` when no part holds any.
pub(super) fn best_part(file: &AdmittedFile, words: &[String]) -> Option<(usize, PickedExcerpt)> {
    let (score, doc) = file
        .documents
        .iter()
        .map(|doc| (said(&doc.text, words), doc))
        .filter(|(score, _)| *score > 0)
        .max_by_key(|(score, doc)| (*score, std::cmp::Reverse(doc.start_line)))?;
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

/// The best part of each of the first few matched files, best file first.
/// A file the source screen refuses (a secret, a key, binary text) is left
/// out, and reading stops at `until`.
pub(crate) fn quick_excerpts(
    home: &Path,
    workspace: &Path,
    app: &str,
    found: &[String],
    words: &[String],
    until: Instant,
) -> Vec<PickedExcerpt> {
    let Some(root) = screened(home, workspace, app) else {
        return Vec::new();
    };
    let chosen = picked_files(home, root.path());
    found
        .iter()
        .filter(|relative| chosen.as_ref().is_none_or(|files| files.contains(relative)))
        .take_while(|_| Instant::now() < until)
        .filter(|relative| stamp(&root, relative).is_some())
        .filter_map(|relative| root.read(relative).ok())
        .filter_map(|file| best_part(&file, words).map(|(_, part)| part))
        .take(MAX_FILES)
        .collect()
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
