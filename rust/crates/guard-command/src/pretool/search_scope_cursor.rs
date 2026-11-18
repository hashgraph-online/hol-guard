//! The Cursor `Grep` tool's directory search.

use super::grep_input;
use super::grok::unignored_grep_scope_proven;
use serde_json::Value;

/// True when a Cursor `Grep` directory search cannot reach a sensitive file.
///
/// Cursor's search is built on ripgrep like Grok's, and Guard cannot confirm
/// which ignore files it honors, so it gets Grok's proof: every directory
/// below the folder is entered, hidden and ignored ones included, and any
/// sensitive file the `glob` selects fails the proof unless the pattern
/// provably cannot match it. Cursor's hook names the folder `file_path`
/// where the tool's own input says `path`; the two must agree when both are
/// sent. A single-file target returns false so the file-read proof decides.
pub(in crate::pretool) fn cursor_grep_directory_scope_proven(
    payload: &Value,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let Some(payload) = with_claude_keys(payload) else {
        return false;
    };
    grep_input(&payload, false)
        .is_some_and(|input| unignored_grep_scope_proven(input, home_dir, cwd))
}

/// The payload with Cursor's `file_path` renamed to `path`.
fn with_claude_keys(payload: &Value) -> Option<Value> {
    let mut payload = payload.clone();
    let input = payload.get_mut("tool_input")?.as_object_mut()?;
    if let Some(folder) = input.remove("file_path") {
        if input.get("path").is_some_and(|path| path != &folder) {
            return None;
        }
        input.insert("path".to_owned(), folder);
    }
    Some(payload)
}
