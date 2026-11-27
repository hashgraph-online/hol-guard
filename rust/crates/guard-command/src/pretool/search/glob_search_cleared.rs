//! A content-search glob proven under the search pattern's clearance.
//!
//! `grep -rn 'needle' tests` is proven when every sensitive-named file in
//! `tests` is one the pattern cannot match, since such a file prints nothing.
//! `grep -rn 'needle' tests/**/*.py` reads a subset of the same files, but its
//! glob proof walked the directory without the clearance, so a test called
//! `test_api_token.py` kept the narrower search reviewed while the wider one
//! was allowed.
use super::glob_expand::search_glob_directory;
use super::literal_bracket::literal_spelling_searchable;
use super::{inside_agent_state, ReadContext};
use crate::pretool::search_pattern_clearance::PatternClearance;
use std::path::Path;

/// Entries [`surely_matches`] reads before it gives up.
const MAX_SURE_MATCH_ENTRIES: usize = 4_096;

/// Whether every file a glob operand can hand the search lies in one literal
/// directory whose walk, hidden entries included, is proven under
/// `clearance`.
///
/// [`search_glob_directory`] gives that directory only when no component
/// steps out of it, none starts with a dot, it is no sibling-repository scope
/// and nothing below it is a link, so the shell can expand the glob only to
/// entries the walk visits, under any shell option, and a recursive search of
/// a matched directory stays inside it. The glob must also name something
/// under every shell option, so `nullglob` cannot remove it and leave
/// `grep -r` to walk the working directory.
pub(in crate::pretool) fn safe_glob_search_cleared(
    value: &str,
    context: ReadContext<'_>,
    clearance: &PatternClearance,
) -> bool {
    if !value.contains(['*', '?', '[']) {
        return false;
    }
    // Every floor asks again, and the directory's link screen walks the
    // whole tree, so the answer is remembered for the evaluation.
    let key = format!("glob-search-cleared\0{value}\0{context:?}");
    super::super::walk_memo::memoized_cleared(key, clearance, || {
        literal_spelling_searchable(value, context)
            && search_glob_directory(value, context).is_some_and(|(directory, _)| {
                !inside_agent_state(&directory, context)
                    && surely_matches(&directory, value)
                    && super::super::walk_memo::cleared(
                        directory,
                        &[],
                        &[],
                        (false, false, false),
                        clearance,
                    )
            })
    })
}

/// Whether `value`, whose literal prefix is `directory`, names an existing
/// entry under the options that match least: no `dotglob`, no `nocaseglob`,
/// and `**` read as one `*`. Every other option only adds matches, so the
/// shell always hands the word on. A bracket, an escape or a budget that
/// runs out answers no.
fn surely_matches(directory: &Path, value: &str) -> bool {
    let components: Vec<&str> = value
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let Some(first) = components
        .iter()
        .position(|component| component.contains(['*', '?', '[']))
    else {
        return false;
    };
    let pattern = &components[first..];
    if pattern
        .iter()
        .any(|component| component.contains(['[', '\\']) || component.starts_with('~'))
    {
        return false;
    }
    let mut budget = MAX_SURE_MATCH_ENTRIES;
    let mut pending = vec![(directory.to_path_buf(), 0_usize)];
    while let Some((path, index)) = pending.pop() {
        let Some(component) = pattern.get(index) else {
            return true;
        };
        let last = index + 1 == pattern.len();
        if !component.contains(['*', '?']) {
            let next = path.join(component);
            if next
                .symlink_metadata()
                .is_ok_and(|metadata| last || metadata.is_dir())
            {
                pending.push((next, index + 1));
            }
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries {
            let Some(left) = budget.checked_sub(1) else {
                return false;
            };
            budget = left;
            let Ok(entry) = entry else {
                continue;
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if name.starts_with('.')
                || !crate::pretool::search::glob_matches(component.as_bytes(), name.as_bytes())
            {
                continue;
            }
            if last || entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push((entry.path(), index + 1));
            }
        }
    }
    false
}
