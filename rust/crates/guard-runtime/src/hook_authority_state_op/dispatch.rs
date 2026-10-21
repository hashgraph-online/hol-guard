//! The request dispatcher: each operation name the host sends, mapped onto
//! the flow in `flows.rs` that serves it.

use super::*;

/// The Claude pending row a request names, as a state key and the artifact the
/// row must carry.
///
/// A request that names the artifact gets the key derived here, so the host
/// cannot ask for one row under another row's name; the artifact then also
/// stands as the identity `claude_load_pending` checks the row against. A
/// request that instead echoes a key the resident issued (from
/// `claude_load_single_pending` or the session index) is acted on as given, and
/// only the expectations it carries narrow it.
fn claude_pending_target<'a>(
    session_id: &str,
    request: &'a HookAuthorityStateRequestV1,
) -> Result<(String, Option<&'a str>), &'static str> {
    match request.artifact_id.as_deref() {
        Some(artifact_id) => Ok((
            claude_pending_key(session_id, artifact_id),
            Some(artifact_id),
        )),
        None => Ok((
            required(&request.pending_key)?.to_owned(),
            request.expected_artifact_id.as_deref(),
        )),
    }
}

impl Env<'_> {
    pub(super) fn dispatch(
        &self,
        request: &HookAuthorityStateRequestV1,
    ) -> Result<Value, &'static str> {
        match request.op.as_str() {
            "claude_record_notice" => {
                let payload = request.payload.as_ref().ok_or(ERROR_INVALID)?;
                self.claude_record_notice(
                    required(&request.session_id)?,
                    request.tool_name.as_deref(),
                    payload,
                );
                Ok(json!({}))
            }
            "claude_load_notice" => Ok(json!({
                "notice": self.claude_load_notice(
                    required(&request.session_id)?,
                    request.tool_name.as_deref(),
                )
            })),
            "claude_mark_prompt_seen" => {
                self.claude_mark_prompt_seen(
                    required(&request.session_id)?,
                    required(&request.artifact_id)?,
                    required(&request.artifact_hash)?,
                    required(&request.command)?,
                );
                Ok(json!({}))
            }
            "claude_load_single_pending" => Ok(
                match self.claude_load_single_pending(required(&request.session_id)?) {
                    Some((key, pending)) => json!({ "pending_key": key, "pending": pending }),
                    None => json!({ "pending_key": null, "pending": null }),
                },
            ),
            "claude_load_pending" => {
                let session_id = required(&request.session_id)?;
                let (pending_key, artifact_id) = claude_pending_target(session_id, request)?;
                Ok(json!({
                    "pending": self.claude_load_pending(
                        session_id,
                        &pending_key,
                        artifact_id,
                        request.expected_artifact_hash.as_deref(),
                        request.expected_command.as_deref(),
                    )
                }))
            }
            "claude_remove_pending" => {
                let session_id = required(&request.session_id)?;
                let (pending_key, _) = claude_pending_target(session_id, request)?;
                self.claude_remove_pending(session_id, &pending_key);
                Ok(json!({}))
            }
            "claude_discard_session" => Ok(json!({
                "discarded": self.claude_discard_session(required(&request.session_id)?)
            })),
            "claude_load_index" => Ok(json!({
                "pending_keys": self.load_index(&CLAUDE_FAMILY, required(&request.session_id)?)
            })),
            "cursor_load_index" => Ok(json!({
                "pending_keys": self.load_index(&CURSOR_FAMILY, required(&request.conversation_id)?)
            })),
            "cursor_store_index" => {
                let keys = request.pending_keys.as_ref().ok_or(ERROR_INVALID)?;
                Ok(json!({
                    "stored": self.store_index(&CURSOR_FAMILY, required(&request.conversation_id)?, keys)
                }))
            }
            "cursor_append_key" => Ok(json!({
                "stored": self.append_key(
                    &CURSOR_FAMILY,
                    required(&request.conversation_id)?,
                    required(&request.pending_key)?,
                )
            })),
            "cursor_store_pending_state" => {
                let payload = request.payload.as_ref().ok_or(ERROR_INVALID)?;
                let conversation_id = required(&request.conversation_id)?;
                let state_key = cursor_target(
                    conversation_id,
                    request.command.as_deref(),
                    request.state_key.as_ref(),
                    cursor_pending_key,
                )?;
                Ok(json!({
                    "stored": self.store_signed(&state_key, payload, &CURSOR_PENDING),
                    "state_key": state_key,
                }))
            }
            "cursor_load_pending_state" => {
                let conversation_id = required(&request.conversation_id)?;
                let command = required(&request.command)?;
                let expected_key = cursor_target(
                    conversation_id,
                    Some(command),
                    request.expected_key.as_ref(),
                    cursor_pending_key,
                )?;
                let state_key = request.state_key.clone().unwrap_or(expected_key.clone());
                Ok(json!({
                    "pending": self.cursor_load_pending_state(
                        conversation_id,
                        command,
                        &state_key,
                        &expected_key,
                    )
                }))
            }
            "cursor_find_pending" => {
                let conversation_id = required(&request.conversation_id)?;
                let command = required(&request.command)?;
                let expected_key = cursor_target(
                    conversation_id,
                    Some(command),
                    request.expected_key.as_ref(),
                    cursor_pending_key,
                )?;
                Ok(json!({
                    "pending": self.cursor_find_pending(conversation_id, command, &expected_key)
                }))
            }
            "cursor_remove_pending" => {
                let conversation_id = required(&request.conversation_id)?;
                let pending_key = cursor_target(
                    conversation_id,
                    request.command.as_deref(),
                    request.pending_key.as_ref(),
                    cursor_pending_key,
                )?;
                self.cursor_remove_pending(conversation_id, &pending_key)?;
                Ok(json!({}))
            }
            "cursor_record_allow" => Ok(json!({
                "stored": self.cursor_record_allow(request)?
            })),
            "cursor_load_allowance" => {
                let conversation_id = required(&request.conversation_id)?;
                let command = required(&request.command)?;
                let state_key = cursor_target(
                    conversation_id,
                    Some(command),
                    request.state_key.as_ref(),
                    cursor_allow_key,
                )?;
                Ok(json!({
                    "allowance": self.cursor_load_allowance(conversation_id, command, &state_key)
                }))
            }
            _ => Err(ERROR_INVALID),
        }
    }
}
