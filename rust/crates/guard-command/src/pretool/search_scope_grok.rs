//! The Grok `Grep` tool's directory search.

use super::super::search_pattern_clearance::PatternClearance;
use super::super::search_scope_filter::SearchFilter;
use super::super::search_scope_glob::expand_braces;
use super::{content_search_scope_proven, filtered_content_search_scope_proven, grep_input};
use serde_json::{Map, Value};

/// True when a Grok `Grep` directory search cannot reach a sensitive file.
///
/// Grok's search is built on ripgrep. It includes hidden files and searches
/// a gitignored file its `glob` matches, so no ignore file narrows the walk:
/// every directory below the folder is entered. The `glob` still decides
/// which files are opened, so a sensitive file it does not select, such as a
/// `secrets.json` beside the `*.md` notes being searched, cannot add to the
/// output. Any other sensitive file fails the proof unless the search pattern
/// provably cannot match it. A single-file target returns false so the
/// file-read proof decides.
pub(in crate::pretool) fn grok_grep_directory_scope_proven(
    payload: &Value,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    grep_input(payload, true).is_some_and(|input| unignored_grep_scope_proven(input, home_dir, cwd))
}

/// The search of a ripgrep-built `Grep` tool that may open hidden and ignored
/// files, given its input with Claude's keys. Grok's tool and Cursor's both
/// search this way.
pub(super) fn unignored_grep_scope_proven(
    input: &Map<String, Value>,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let target = match input.get("path") {
        None => ".",
        Some(Value::String(path)) if !path.is_empty() => path.as_str(),
        Some(_) => return false,
    };
    // A plain pattern that no reachable sensitive file contains cannot print
    // a line from one, so those files need not hold the search.
    let clearance = input
        .get("pattern")
        .and_then(Value::as_str)
        .and_then(PatternClearance::new);
    match input.get("glob") {
        None => content_search_scope_proven(target, home_dir, cwd, clearance.as_ref()),
        Some(Value::String(glob)) if contained(glob) => match name_filter(glob) {
            Some(filter) => filtered_content_search_scope_proven(
                target,
                &filter,
                home_dir,
                cwd,
                clearance.as_ref(),
            ),
            None => content_search_scope_proven(target, home_dir, cwd, clearance.as_ref()),
        },
        Some(_) => false,
    }
}

/// A glob is matched below the searched folder; one spelled as an absolute
/// path or climbing out of it is not modeled.
fn contained(glob: &str) -> bool {
    !glob.starts_with(['/', '~', '\\'])
        && glob.as_bytes().get(1) != Some(&b':')
        && !glob.split(['/', '\\']).any(|part| part == "..")
}

/// The files a `glob` selects, when it names files by their name alone.
///
/// A glob without a separator matches each file's own name wherever it sits,
/// which is the reading the walk filter models. A glob holding a separator is
/// matched against a path whose base the host chooses (the folder searched or
/// the workspace), so it is left unmodeled and the walk screens every file.
///
/// Grok hands the whole glob to `rg --glob`, and its own tool description
/// gives `*.{ts,tsx}` as an example, so a brace list selects each of its
/// names and the filter screens every one. A comma or brace still standing
/// once the list is expanded -- a top-level list such as `*.md,*.json`, an
/// unpaired brace, or a nested list ripgrep reads differently -- is left
/// unmodeled, and so is a negation; the walk screens every file then.
fn name_filter(glob: &str) -> Option<SearchFilter> {
    if glob.is_empty() || glob.contains(['/', '\\']) || glob.contains(char::is_whitespace) {
        return None;
    }
    let names = expand_braces(glob).ok()?;
    if names.iter().any(|name| name.contains([',', '{', '}'])) {
        return None;
    }
    SearchFilter::from_rg_inclusions(&[glob]).filter(|filter| !filter.is_path_shaped())
}
