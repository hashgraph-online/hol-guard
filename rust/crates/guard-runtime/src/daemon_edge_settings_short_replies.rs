//! Turning CIGAR on also asks Codex for short replies, once.
//!
//! The settings save stays native. After it is written, the edge asks the
//! Guard library to run the short-replies `ensure` under the Codex install
//! lock. That step is best effort: a Codex config Guard cannot change leaves
//! the saved CIGAR setting as it is.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::super::super::super::library;
use super::{lookup, ReadConfig};
use crate::pyjson::PyVal;
use crate::transition_files::short_replies_first_ask_due;

const ENSURE_CALL: &str = "route.codex_short_replies_ensure";

/// Whether this save should ask Codex for short replies: it turns CIGAR on,
/// Guard has not asked yet, and the Guard home sits in the home folder.
pub(super) fn ask_due(settings: &[(String, PyVal)], guard_home: &Path) -> bool {
    let user_home = crate::claude_hook_bridge::home_directory();
    turns_cigar_on(settings) && short_replies_first_ask_due(guard_home, user_home.as_deref())
}

/// Whether the save sets `context_assistance.enabled` to true.
pub(super) fn turns_cigar_on(settings: &[(String, PyVal)]) -> bool {
    matches!(lookup(settings, "context_assistance"), Some(PyVal::Dict(cigar))
        if matches!(lookup(cigar, "enabled"), Some(PyVal::Bool(true))))
}

/// Run the short-replies `ensure`. Failures are ignored.
pub(super) fn ask(config: &ReadConfig) {
    let _ = library::call(config, ENSURE_CALL, Value::Object(ensure_args()));
}

fn ensure_args() -> Map<String, Value> {
    let mut args = Map::new();
    args.insert("payload".to_owned(), json!({}));
    args
}
