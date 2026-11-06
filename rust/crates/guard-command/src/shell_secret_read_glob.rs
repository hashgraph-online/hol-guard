//! Screening for the glob patterns a search tool accepts.
//!
//! A search glob is not a path: it stands for the set of files the tool will
//! open, so it is read as a name pattern and refused when any spelling it
//! stands for could name a sensitive file. `shell_secret_read_support` owns
//! the operand reader that decides which arguments reach this screen.

use std::path::Path;

use crate::codex_output_fnmatch::fnmatchcase;
use crate::shell_secret_read_support::{
    SOURCE_INSPECTION_BENIGN_DOTFILES, SOURCE_INSPECTION_SENSITIVE_PARTS,
};

/// Bounds on `{a,b}` expansion in a search glob.
///
/// A brace alternation stands for several patterns, so each spelling is
/// screened on its own. The bounds keep a crafted pattern from costing more
/// than a fixed amount of work: at most this many spellings, reached through
/// at most this many brace groups along any one spelling.
const MAX_GLOB_EXPANSIONS: usize = 64;
const MAX_GLOB_BRACE_GROUPS: usize = 2;

/// The characters a pattern may use once Guard rewrites it.
///
/// Expansion only happens for text that is unambiguously a filename pattern.
/// Plenty of non-glob arguments carry braces -- jq filters, GraphQL documents,
/// `sed` expressions -- and they reach this screen because the operand reader
/// cannot tell them apart. Restricting the expanded text to filename
/// characters leaves all of those rejected, exactly as they were before.
const GLOB_EXPANSION_CHARACTERS: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-*?/";

/// `_search_glob_pattern_is_safe` (:419-445).
pub(crate) fn search_glob_pattern_is_safe(pattern: &str, root: Option<&Path>) -> bool {
    let _ = root;
    let is_exclusion = pattern.starts_with('!');
    let effective_pattern = if is_exclusion { &pattern[1..] } else { pattern };
    if effective_pattern.is_empty()
        || effective_pattern.chars().count() > 4096
        || effective_pattern.contains('\n')
        || effective_pattern.contains('\x00')
        || effective_pattern.contains('!')
    {
        return false;
    }
    if is_exclusion {
        // An exclusion narrows the search, so it is admitted without reading
        // its components. It gains nothing from recursion or alternation, and
        // widening the syntax here would only widen what is admitted unread.
        if ["**", "{", "}"]
            .iter()
            .any(|token| effective_pattern.contains(token))
        {
            return false;
        }
        return search_glob_spelling_is_safe(effective_pattern, true);
    }
    if effective_pattern.contains('{') || effective_pattern.contains('}') {
        let mut spellings = Vec::new();
        if expand_glob_alternations(effective_pattern, 0, &mut spellings).is_none() {
            return false;
        }
        return spellings
            .iter()
            .all(|spelling| search_glob_spelling_is_safe(spelling, false));
    }
    search_glob_spelling_is_safe(effective_pattern, false)
}

/// Screen one brace-free spelling of a search glob.
fn search_glob_spelling_is_safe(pattern: &str, is_exclusion: bool) -> bool {
    let path = crate::codex_output_py::PyPath::new(pattern);
    let components = path.parts();
    if pattern.is_empty()
        || path.is_absolute()
        || components
            .iter()
            .any(|component| matches!(component.as_str(), "" | "." | ".."))
        // `**` on its own names every path, so nothing is left to read.
        || (!components.is_empty() && components.iter().all(|component| component == "**"))
    {
        return false;
    }
    if is_exclusion {
        return true;
    }
    for (index, component) in components.iter().enumerate() {
        if component == "**" {
            // A trailing `**` is the one place the recursive component names
            // files rather than a run of directories: `src/**` selects every
            // entry under `src`, sensitive names included, which is what the
            // screen refuses `src/*` and `**/*` for. Anywhere else `**` stands
            // for the directories between two named components, so there is no
            // name here to compare against. The named components around it are
            // still screened, and a search tool skips hidden entries while
            // walking, which is what the dotfile screen below covers.
            if index + 1 == components.len() {
                return false;
            }
            continue;
        }
        let folded = component.to_lowercase();
        if folded.starts_with('.') && !SOURCE_INSPECTION_BENIGN_DOTFILES.contains(&folded.as_str())
        {
            return false;
        }
        for sensitive in SOURCE_INSPECTION_SENSITIVE_PARTS {
            let sensitive_folded = sensitive.to_lowercase();
            if fnmatchcase(&sensitive_folded, &folded)
                || fnmatchcase(
                    &format!("{sensitive_folded}.guard-sensitive-probe"),
                    &folded,
                )
            {
                return false;
            }
        }
    }
    true
}

/// Expand `{a,b}` alternations into the spellings they stand for.
///
/// `None` means the pattern is not an alternation Guard will rewrite: an
/// unmatched brace, a group with a single or empty alternative, a spelling
/// outside [`GLOB_EXPANSION_CHARACTERS`], or either bound exceeded. The caller
/// reads that as unsafe, which is what the pattern already was.
fn expand_glob_alternations(pattern: &str, depth: usize, out: &mut Vec<String>) -> Option<()> {
    let Some(open) = pattern.find('{') else {
        if pattern.contains('}')
            || pattern
                .chars()
                .any(|c| !GLOB_EXPANSION_CHARACTERS.contains(c))
            || out.len() == MAX_GLOB_EXPANSIONS
        {
            return None;
        }
        out.push(pattern.to_owned());
        return Some(());
    };
    if depth == MAX_GLOB_BRACE_GROUPS {
        return None;
    }
    let mut level = 0usize;
    let mut close = None;
    for (offset, c) in pattern[open..].char_indices() {
        match c {
            '{' => level += 1,
            '}' => {
                level -= 1;
                if level == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    let prefix = &pattern[..open];
    let suffix = &pattern[close + 1..];
    let inner = &pattern[open + 1..close];
    let mut level = 0usize;
    let mut start = 0usize;
    let mut alternatives = Vec::new();
    for (offset, c) in inner.char_indices() {
        match c {
            '{' => level += 1,
            '}' => level = level.saturating_sub(1),
            ',' if level == 0 => {
                alternatives.push(&inner[start..offset]);
                start = offset + 1;
            }
            _ => {}
        }
    }
    alternatives.push(&inner[start..]);
    if alternatives.len() < 2 {
        return None;
    }
    for alternative in alternatives {
        if alternative.is_empty() {
            return None;
        }
        expand_glob_alternations(&format!("{prefix}{alternative}{suffix}"), depth + 1, out)?;
    }
    Some(())
}
