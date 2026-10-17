//! Oh My Pi's `learn` writes one note into the agent's memory bank. The note
//! is read back at the top of every later run, so what it says reaches a run
//! that never saw it written, and its PreToolUse stays the review it has
//! today: a memory write is a person's call, not a reading this authority
//! makes from the note's wording.
//!
//! What this file answers is the other half. Once that review is approved the
//! note is already in the bank by the time a result comes back, and the store
//! returns an acknowledgement that carries no operation of its own. Holding
//! that acknowledgement back leaves Oh My Pi waiting on an approval for a call
//! that has already happened, so a call shaped as one project note is named
//! here and its result is released. A global note, which reaches every
//! project's recall, and a call that also mints a skill file are not that
//! shape and keep the ordinary output path.

use serde_json::{Map, Value};

/// The keys Oh My Pi's `learn` schema carries for a memory note. `skill`
/// writes a managed skill file, so a call holding it is not one of these.
const NOTE_KEYS: [&str; 3] = ["memory", "context", "scope"];

/// A memory note into this project's own bank, which the store has already
/// written by the time a result comes back. The note's own content does not
/// have to read as plain here: the write happened because a person approved
/// it, and the acknowledgement it returns adds no operation.
pub(super) fn note_input(input: &Map<String, Value>) -> bool {
    input.keys().all(|key| NOTE_KEYS.contains(&key.as_str()))
        && input
            .get("memory")
            .and_then(Value::as_str)
            .is_some_and(|memory| !memory.trim().is_empty())
        && input.get("context").is_none_or(Value::is_string)
        // A global lesson reaches every project's recall, so Oh My Pi itself
        // asks for it the way it asks for a file write, and so does this.
        && input
            .get("scope")
            .is_none_or(|scope| scope.as_str() == Some("project"))
}
