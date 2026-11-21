//! Turning CIGAR on also asks Codex for short replies, once.
//!
//! The settings save stays native. After it is written, the edge runs the
//! short-replies `ensure` under the Codex install lock. That step is best
//! effort: a Codex config Guard cannot change leaves the saved CIGAR setting
//! as it is.

use std::path::Path;

use super::super::context_assistance::codex_config;
use super::{lookup, ReadConfig};
use crate::codex_config_switch::{change, Switch};
use crate::pyjson::PyVal;
use crate::transition_files::short_replies_first_ask_due;

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
    if let Some(homes) = codex_config::homes(config) {
        let _ = change(Switch::ShortReplies, &homes, "ensure", None);
    }
}
