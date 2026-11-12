//! The Claude `Grep` tool's directory search.

use super::super::search_pattern_clearance::PatternClearance;
use super::super::search_scope_filter::SearchFilter;
use super::super::search_scope_walk::{walk_scope_cleared, Ignores};
use super::{claude_grep_input, verified_directory_root};
use serde_json::Value;

/// True when a Claude `Grep` directory search cannot reach a sensitive file.
/// A single-file target returns false so the existing file-read proof decides.
pub(in crate::pretool) fn claude_grep_directory_scope_proven(
    payload: &Value,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some(input) = claude_grep_input(payload) else {
        return false;
    };
    let target = match input.get("path") {
        None => ".",
        Some(Value::String(path)) if !path.is_empty() => path.as_str(),
        Some(_) => return false,
    };
    let Some(filter) = SearchFilter::from_input(input) else {
        return false;
    };
    let Some(root) = verified_directory_root(target, home_dir, cwd) else {
        return false;
    };
    // Claude prints only matching lines and the names of matching files, so
    // a sensitive file a plain pattern provably cannot match adds nothing.
    let clearance = input
        .get("pattern")
        .and_then(Value::as_str)
        .and_then(PatternClearance::new);
    !crate::pretool::read_paths::inside_agent_state_tree(&root, home_dir)
        && walk_scope_cleared(
            &root,
            &filter,
            Ignores::Ripgrep,
            clearance.as_ref(),
            home_dir,
            &mut None,
        )
        .is_ok()
}
