//! Which harness a Claude-format hook belongs to, decided where the hook runs.
//!
//! Claude Code and Cursor both run the hooks in Claude's user settings, so the
//! same installed entry serves two harnesses. Only the process running a hook
//! can tell which one started it: Cursor puts its markers in the hook's
//! environment, and Claude Code does not. An install used to read those
//! markers from its own environment and write `runtime-harness=cursor` into
//! the shared settings, so one install run from a Cursor terminal filed every
//! later Claude Code call as Cursor's and held it under Cursor's posture. The
//! bridge now drops any written `runtime-harness` and names Cursor only when
//! the hook it is running carries Cursor's markers.
//!
//! Claude Code started from a Cursor terminal inherits those markers, so a
//! hook that also carries Claude Code's own `CLAUDECODE=1` belongs to Claude
//! Code: that marker is set by the Claude Code process itself, while the
//! Cursor markers may only be left over from the terminal it was launched
//! in.

use crate::claude_hook_bridge_render::py_strip;
use crate::claude_hook_bridge_url::py_unquote;
use crate::runner_sync_url::urlencode;

/// Presence-only markers Cursor sets in the environment of the hooks it runs.
pub(crate) const CURSOR_ENV_MARKERS: [&str; 5] = [
    "CURSOR_VERSION",
    "CURSOR_PROJECT_DIR",
    "CURSOR_TRACE_ID",
    "CURSOR_SESSION_ID",
    "CURSOR_TRANSCRIPT_PATH",
];

/// Set to `1` by Claude Code in the environment of everything it runs.
const CLAUDE_CODE_MARKER: &str = "CLAUDECODE";

const RUNTIME_HARNESS: &str = "runtime-harness";
const WORKSPACE: &str = "workspace";

/// A hook that Cursor is running.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CursorRun {
    /// `CURSOR_PROJECT_DIR`, stripped, when Cursor named one.
    pub(crate) project_dir: Option<String>,
}

/// The Cursor run `lookup` describes, or `None` when no Cursor marker is set
/// to a non-blank value or Claude Code marks the run as its own.
pub(crate) fn cursor_run(lookup: impl Fn(&str) -> Option<String>) -> Option<CursorRun> {
    if lookup(CLAUDE_CODE_MARKER).is_some_and(|value| py_strip(&value) == "1") {
        return None;
    }
    let set = |key: &str| lookup(key).filter(|value| !py_strip(value).is_empty());
    CURSOR_ENV_MARKERS
        .iter()
        .any(|key| set(key).is_some())
        .then(|| CursorRun {
            project_dir: set("CURSOR_PROJECT_DIR").map(|dir| py_strip(&dir).to_owned()),
        })
}

/// The Cursor run of this process's own environment.
pub(crate) fn current_cursor_run() -> Option<CursorRun> {
    cursor_run(|key| std::env::var_os(key).map(|value| value.to_string_lossy().into_owned()))
}

fn names(field: &str, name: &str) -> bool {
    let key = field.split_once('=').map_or(field, |(key, _)| key);
    py_unquote(&key.replace('+', " ")) == name
}

/// The configured hook query with the harness this run belongs to: any
/// written `runtime-harness` is dropped, and a Cursor run names Cursor and
/// its project as the workspace, as the install-time attribution did.
pub(crate) fn attributed_query(query: &str, cursor: Option<&CursorRun>) -> String {
    let mut fields: Vec<String> = query
        .split('&')
        .filter(|field| !field.is_empty() && !names(field, RUNTIME_HARNESS))
        .map(str::to_owned)
        .collect();
    if let Some(cursor) = cursor {
        if let Some(project) = &cursor.project_dir {
            fields.retain(|field| !names(field, WORKSPACE));
            fields.push(urlencode(&[(WORKSPACE.to_owned(), project.clone())]));
        }
        fields.push(urlencode(&[(
            RUNTIME_HARNESS.to_owned(),
            "cursor".to_owned(),
        )]));
    }
    fields.join("&")
}

#[cfg(test)]
#[path = "claude_hook_bridge_harness_tests.rs"]
mod tests;
