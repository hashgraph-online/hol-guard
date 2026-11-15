//! The hint that ends a note Guard added to a prompt, on how to spend fewer
//! turns on it.
use super::seen::{self, Session};
use super::{add_context, context_len, project_root, session};
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::GuardHookEnvelopeV2;
use serde_json::Value;
use std::path::Path;

/// Claude Code models tend to send one tool call per turn, and every turn
/// re-sends the whole conversation, so the reads and edits a note makes
/// possible cost least when they go out together. They also run the whole
/// suite and commit after the check a note names has passed, unasked; each is
/// one more turn.
const BATCHING: &str = "Each tool call re-sends this whole conversation. When you \
already know several ranges to read or several edits to make, make those tool calls together in \
one response, not one per turn. Once the check a note names passes, the change is done: a full \
test run or a commit nobody asked for costs another turn each.";
/// Codex models tend to read again lines a note already shows, then patch and
/// test in separate turns; each turn re-sends the whole conversation. The
/// edit and the test go out as two tool calls from one exec script: a shell
/// command that writes files and then runs tests is one Guard cannot match to
/// the project's controls, so it is held and the turn is spent anyway.
const ACT_ON_IT: &str = "The code and diffs in this note are what the files hold now: \
work from them instead of reading those lines again. When you can, make the edit and run its check \
in the same turn: one exec script can call apply_patch and then run the test command, as two tool \
calls. Make edits with apply_patch, not with a shell or Python script that writes files.";

/// Oh My Pi models open a todo list for most steps, often in a turn of its
/// own, and read again lines a note already shows. Oh My Pi drops a note when
/// the agent is busy, so Guard cannot tell whether an earlier one was shown,
/// and this short hint goes with every note.
const SKIP_THE_LIST: &str = "The code and diffs in this note are what the files hold now: \
work from them instead of reading those lines again. For a fix that takes one or two edits, skip \
the todo list and go straight to the edit and its check. Tool calls that do not depend on each \
other can go out together in one response.";

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
        "omp" => SKIP_THE_LIST,
        _ => return,
    };
    let hint = seen::hint();
    let add = context_len(response) > before
        && !session.is_some_and(|session| seen::earlier(session).contains(&hint));
    if harness == "claude-code" {
        fit(response, if add { ending.len() + 2 } else { 0 });
    }
    if !add {
        return;
    }
    add_context(response, ending);
    if let Some(session) = session {
        seen::remember(session, &[hint]);
    }
}

/// Claude Code saves hook context longer than 10,000 characters to a file
/// and shows the model only its first 2,000, so the map after a change note
/// is lost. A longer note is cut at a line that leaves no code block open.
const CLAUDE_MAX_CHARS: usize = 9_500;
const CUT: &str = "(The rest of this note was cut to fit.)";

fn fit(response: &mut Value, reserve: usize) {
    let Some(text) = response.pointer_mut("/hookSpecificOutput/additionalContext") else {
        return;
    };
    let max = CLAUDE_MAX_CHARS.saturating_sub(reserve);
    if let Some(kept) = text.as_str().and_then(|text| cut(text, max)) {
        *text = Value::String(kept);
    }
}

/// `text` cut to at most `max` characters, or `None` when it fits.
fn cut(text: &str, max: usize) -> Option<String> {
    if text.chars().count() <= max {
        return None;
    }
    let room = max.saturating_sub(CUT.len() + 1);
    let end = text
        .char_indices()
        .nth(room)
        .map_or(text.len(), |(at, _)| at);
    let mut kept = &text[..text[..end].rfind('\n').unwrap_or(0)];
    if kept.matches("```").count() % 2 == 1 {
        let open = kept.rfind("```").unwrap_or(0);
        kept = &kept[..kept[..open].rfind('\n').unwrap_or(0)];
    }
    Some(format!("{kept}\n{CUT}"))
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
