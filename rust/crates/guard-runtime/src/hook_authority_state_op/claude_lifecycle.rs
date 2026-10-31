//! The daemon's answers to Claude Code's lifecycle hooks, each in the one
//! transaction `evaluate` opens.
//!
//! A `PermissionRequest`, a `permission_prompt` notification and a `Stop`
//! used to cost the daemon several calls into this op and the renderer: load
//! the session's notice, mark it seen, record the event, then render each
//! piece of copy. Each op here runs that sequence against the same store and
//! returns the harness response the edge's direct lane renders for the same
//! hook, so a notice written between those calls can no longer be answered
//! without being marked seen.
//!
//! The daemon sends the session it read from the hook and only the payload
//! fields the copy reads, so the tool's own input never travels twice.

use super::*;
use crate::hook_direct::claude_permission_text::{
    notification_tool_name, permission_prompt_event, permission_prompt_notification_response,
    permission_request_response, PERMISSION_PROMPT_EVENT,
};
use crate::hook_direct::lifecycle::constant_response;

const TURN_STOP_EVENT: &str = "claude/turn_stop";
/// The harness and event `claude_turn_stop` answers.
const CLAUDE_CODE: &str = "claude-code";
const STOP: &str = "Stop";

impl Env<'_> {
    /// `claude_permission_request_response`: Claude's dialog is denied in
    /// favour of the Guard approval question, shown with the review reason,
    /// or left to Claude when the session has no notice.
    pub(super) fn claude_permission_request(
        &self,
        session_id: Option<&str>,
        payload: &Object,
    ) -> Value {
        let notice = self.claude_seen_notice(session_id, payload);
        json!({ "harness_response": permission_request_response(payload, notice.as_ref()) })
    }

    /// `_claude_permission_prompt_notification_response`, with the
    /// `claude/permission_prompt` event the daemon records for every prompt.
    pub(super) fn claude_permission_prompt(
        &self,
        session_id: Option<&str>,
        payload: &Object,
    ) -> Result<Value, &'static str> {
        let notice = self.claude_seen_notice(session_id, payload);
        let event = permission_prompt_event(payload, notice.as_ref()).ok_or(ERROR_INVALID)?;
        self.record_event(PERMISSION_PROMPT_EVENT, &event)?;
        Ok(json!({
            "harness_response": permission_prompt_notification_response(payload, notice.as_ref()),
        }))
    }

    /// `claude_turn_stop`: the session's unanswered prompts are dropped, so the
    /// next turn reviews the call again instead of inheriting a block nobody
    /// chose, and the turn's end is recorded with how many were dropped. The
    /// reply carries the constant the direct lane answers `Stop` with, so the
    /// daemon needs no second call to the edge for it.
    pub(super) fn claude_turn_stop(
        &self,
        session_id: Option<&str>,
        payload: &Object,
    ) -> Result<Value, &'static str> {
        let discarded = session_id.map_or(0, |session_id| self.claude_discard_session(session_id));
        let session = dumps_default(payload.get("session_id").unwrap_or(&Value::Null))
            .ok_or(ERROR_INVALID)?;
        self.record_event(
            TURN_STOP_EVENT,
            &format!(
                "{{\"session_id\": {session}, \"discarded_pending_permissions\": {discarded}}}"
            ),
        )?;
        Ok(json!({
            "discarded": discarded,
            "harness_response": constant_response(CLAUDE_CODE, STOP),
        }))
    }

    /// The session's notice for the tool the hook names, marked seen.
    fn claude_seen_notice(&self, session_id: Option<&str>, payload: &Object) -> Option<Object> {
        let session_id = session_id?;
        let notice =
            self.claude_load_notice(session_id, notification_tool_name(payload).as_deref())?;
        if let (Some(artifact_id), Some(artifact_hash), Some(command)) = (
            opt_str(&notice, "artifact_id"),
            opt_str(&notice, "artifact_hash"),
            opt_str(&notice, "command"),
        ) {
            self.claude_mark_prompt_seen(session_id, &artifact_id, &artifact_hash, &command);
        }
        Some(notice)
    }

    /// An event the daemon wrote with `json.dumps`, already rendered. A failed
    /// write rolls the whole op back.
    fn record_event(&self, name: &str, text: &str) -> Result<(), &'static str> {
        self.connection
            .execute(
                "insert into guard_events (event_name, payload_json, occurred_at) \
                 values (?1, ?2, ?3)",
                params![name, text, self.now],
            )
            .map(|_| ())
            .map_err(|_| ERROR_STORE)
    }
}

/// The daemon's `claude_turn_stop` for a Claude `Stop` the direct lane
/// answers: the session's unanswered prompts are dropped and the turn's end
/// is recorded, in one transaction.
///
/// Only the bound key verifies the pending index, so without one a session
/// that has an index defers and the daemon drops it. A row signed under
/// another key id, or a busy store, rolls back and defers as well.
pub(crate) fn claude_turn_stop_direct(
    store_path: &std::path::Path,
    key: Option<(&[u8], &str)>,
    now: &str,
    session_id: Option<&str>,
    payload: &Object,
) -> Result<(), DirectNoticeDefer> {
    let connection = begin_direct(store_path)?;
    let rollback = |defer| {
        let _ = connection.execute_batch("ROLLBACK");
        Err(defer)
    };
    if let (None, Some(session_id)) = (key, session_id) {
        match unkeyed_index_present(&connection, session_id) {
            Ok(false) => {}
            Ok(true) => return rollback(DirectNoticeDefer::UnkeyedNotice),
            Err(defer) => return rollback(defer),
        }
    }
    let foreign_key = std::cell::Cell::new(false);
    let env = Env {
        connection: &connection,
        key: key.map(|(bytes, _)| zeroize::Zeroizing::new(bytes.to_vec())),
        key_id: key.map(|(_, id)| id),
        now,
        foreign_key: Some(&foreign_key),
    };
    let discard = if key.is_some() { session_id } else { None };
    let recorded = env.claude_turn_stop(discard, payload);
    if foreign_key.get() {
        return rollback(DirectNoticeDefer::ForeignKey);
    }
    if recorded.is_err() || connection.execute_batch("COMMIT").is_err() {
        return rollback(DirectNoticeDefer::StoreUnavailable);
    }
    Ok(())
}

/// The session's pending index row, read on the transaction's own
/// connection.
fn unkeyed_index_present(
    connection: &Connection,
    session_id: &str,
) -> Result<bool, DirectNoticeDefer> {
    if !crate::local_store_read::table_exists(connection, "sync_state")
        .map_err(|_| DirectNoticeDefer::StoreUnavailable)?
    {
        return Ok(false);
    }
    connection
        .query_row(
            "select exists(select 1 from sync_state where state_key = ?1)",
            params![format!("{}{session_id}", CLAUDE_FAMILY.index_prefix)],
            |row| row.get(0),
        )
        .map_err(|_| DirectNoticeDefer::StoreUnavailable)
}
