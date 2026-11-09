//! How much of the hook's wait the note on changes may take. A prompt the
//! changes answer alone gets no search after the note, so the note may use
//! all the wait but the search's least; any other prompt leaves the search
//! two thirds.
use super::about_changes;
use crate::context_assistance_prompt_words::{marked_terms, named, phrases};
use std::time::Duration;

/// Whether the changes alone answer `prompt`: it is about changes and names
/// no code, file or phrase, so the lines they list are where to look.
pub(in super::super) fn answered_alone(prompt: &str) -> bool {
    about_changes(prompt)
        && phrases(prompt).is_empty()
        && named(prompt).is_empty()
        && !marked_terms(prompt).iter().any(|(_, name)| *name)
}

/// The note's share of `left`, leaving the search at least `least` when a
/// search follows it.
pub(in super::super) fn share(prompt: &str, left: Duration, least: Duration) -> Duration {
    if answered_alone(prompt) {
        left.saturating_sub(least)
    } else {
        left / 3
    }
}

#[cfg(test)]
#[path = "context_assistance_prompt_changes_wait_tests.rs"]
mod tests;
