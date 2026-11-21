//! Durable lifecycle records describe effects; they are never execution grants.
//! Native callers must validate current settings, policy and protected bytes.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataTransition {
    MemoryRebuild,
    ReuseCompatible,
    PreparedCopy,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchError {
    InvalidJournal,
    InvalidTransition,
    SelectionConflict,
    SettingsConflict,
}
impl SwitchError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidJournal => "cigar_upgrade_journal_invalid",
            Self::InvalidTransition => "cigar_upgrade_transition_invalid",
            Self::SelectionConflict => "cigar_upgrade_selection_conflict",
            Self::SettingsConflict => "cigar_upgrade_settings_conflict",
        }
    }
}
