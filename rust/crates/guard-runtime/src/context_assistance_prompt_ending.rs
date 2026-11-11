//! The hint that ends a note Guard added to a prompt, on how to spend fewer
//! turns on it.
use super::seen::{self, Session};
use super::{add_context, context_len, project_root, session, ACT_ON_IT, BATCHING};
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::GuardHookEnvelopeV2;
use serde_json::Value;
use std::path::Path;

/// Ends a note Guard added to this prompt with how to spend fewer turns on
/// it, worded for the harness; a prompt Guard added nothing to gets nothing.
/// The first note of a session carries it, and the conversation keeps it, so
/// a later note leaves it off instead of sending it once per prompt.
pub(super) fn end_note(
    response: &mut Value,
    harness: &str,
    before: usize,
    session: Option<&Session>,
) {
    let ending = match harness {
        "claude-code" => BATCHING,
        "codex" => ACT_ON_IT,
        _ => return,
    };
    let hint = seen::hint();
    if context_len(response) <= before
        || session.is_some_and(|session| seen::earlier(session).contains(&hint))
    {
        return;
    }
    add_context(response, ending);
    if let Some(session) = session {
        seen::remember(session, &[hint]);
    }
}

/// The session a prompt belongs to, found the way `attach` finds it.
pub(super) fn prompt_session(
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    store: &PolicySnapshotStore,
) -> Option<Session> {
    let cwd = (envelope.source.cwd.as_deref())
        .or_else(|| envelope.raw_payload.get("cwd").and_then(Value::as_str))?;
    let home = Path::new(&envelope.source.home_dir);
    let root = project_root(Path::new(cwd), home, store.guard_home())?;
    session(envelope, &root, harness)
}

#[cfg(test)]
#[path = "context_assistance_prompt_ending_tests.rs"]
mod tests;
