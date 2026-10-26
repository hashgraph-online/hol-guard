//! Oh My Pi's `learn` writes one note into the agent's memory bank, and can
//! also create or update one managed skill in the same call. Both are read
//! back by later runs that never saw them written, so its PreToolUse stays the
//! review it has today: a memory or skill write is a person's call, not a
//! reading this authority makes from its wording.
//!
//! What this file answers is the other half. Once that review is approved the
//! note (and skill) is already written by the time a result comes back, and
//! the store returns an acknowledgement that carries no operation of its own.
//! Holding that acknowledgement back leaves Oh My Pi waiting on an approval for
//! a call that has already happened, so a call shaped as one project note,
//! with or without one well-formed skill, is named here and its result is
//! released. A global note, which reaches every project's recall, is not that
//! shape and keeps the ordinary output path.

use serde_json::{Map, Value};

/// The keys Oh My Pi's `learn` schema carries: the note, and the optional
/// skill written in the same call.
const NOTE_KEYS: [&str; 4] = ["memory", "context", "scope", "skill"];

/// Oh My Pi 18.11's `skill` object. Every field is a required string.
const SKILL_KEYS: [&str; 4] = ["action", "name", "description", "body"];

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
        && input.get("skill").is_none_or(skill_input)
}

/// One managed skill exactly as Oh My Pi's schema shapes it, created or
/// updated under a kebab-case name. The body is the skill's text, which the
/// person approved with the call; anything else is not this shape.
fn skill_input(skill: &Value) -> bool {
    let Some(skill) = skill.as_object() else {
        return false;
    };
    skill.len() == SKILL_KEYS.len()
        && SKILL_KEYS
            .iter()
            .all(|key| skill.get(*key).is_some_and(Value::is_string))
        && matches!(
            skill.get("action").and_then(Value::as_str),
            Some("create" | "update")
        )
        && skill
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(kebab_case)
}

/// `a-z`, `0-9` and single hyphens, at most 64 characters: the rule Oh My
/// Pi's skill registry applies (`^[a-z0-9]+(?:-[a-z0-9]+)*$`).
fn kebab_case(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}
