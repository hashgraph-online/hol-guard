//! Claude notice/pending and Cursor pending/allowance flows built on the
//! signed state primitives in `store.rs`.

use super::*;

impl Env<'_> {
    pub(super) fn claude_record_notice(
        &self,
        session_id: &str,
        tool_name: Option<&str>,
        payload: &Value,
    ) {
        let Some(artifact_id) = payload.get("artifact_id").and_then(Value::as_str) else {
            return;
        };
        let notice_key = notice_key(session_id, tool_name);
        let pending_key = claude_pending_key(session_id, artifact_id);
        if !self.store_signed(&pending_key, payload, &CLAUDE_PENDING) {
            return;
        }
        if !self.append_key(&CLAUDE_FAMILY, session_id, &pending_key) {
            self.delete(&pending_key);
            return;
        }
        if !self.store_signed(&notice_key, payload, &CLAUDE_NOTICE) {
            self.claude_remove_pending(session_id, &pending_key);
        }
    }

    pub(super) fn claude_load_pending(
        &self,
        session_id: &str,
        pending_key: &str,
        expected_artifact_id: Option<&str>,
        expected_artifact_hash: Option<&str>,
        expected_command: Option<&str>,
    ) -> Option<Object> {
        let persisted = self.load_verified(pending_key, &CLAUDE_PENDING)?;
        let artifact_id = opt_str(&persisted, "artifact_id");
        let artifact_hash = opt_str(&persisted, "artifact_hash");
        let command = opt_str(&persisted, "command");
        let expected_key = artifact_id
            .as_deref()
            .map(|id| claude_pending_key(session_id, id));
        let context_matches = exact_str(&persisted, "session_id") == Some(session_id)
            && artifact_id.is_some()
            && artifact_hash.is_some()
            && command.is_some()
            && expected_key.as_deref() == Some(pending_key)
            && expected_artifact_id.is_none_or(|expected| artifact_id.as_deref() == Some(expected))
            && expected_artifact_hash
                .is_none_or(|expected| artifact_hash.as_deref() == Some(expected))
            && expected_command.is_none_or(|expected| command.as_deref() == Some(expected));
        if context_matches {
            return Some(persisted);
        }
        self.invalidate(
            pending_key,
            &persisted,
            &CLAUDE_PENDING,
            "local_authority_integrity_pending_context_mismatch",
        );
        None
    }

    pub(super) fn claude_load_notice(
        &self,
        session_id: &str,
        tool_name: Option<&str>,
    ) -> Option<Object> {
        let mut selected_tool = tool_name;
        let mut selected_key = notice_key(session_id, selected_tool);
        let mut persisted = self.load_verified(&selected_key, &CLAUDE_NOTICE);
        if persisted.is_none() && tool_name.is_some() {
            selected_tool = None;
            selected_key = notice_key(session_id, None);
            persisted = self.load_verified(&selected_key, &CLAUDE_NOTICE);
        }
        let persisted = persisted?;
        let artifact_id = opt_str(&persisted, "artifact_id");
        let artifact_hash = opt_str(&persisted, "artifact_hash");
        let command = opt_str(&persisted, "command");
        let stored_tool = opt_str(&persisted, "tool_name");
        let context_matches = exact_str(&persisted, "session_id") == Some(session_id)
            && artifact_id.is_some()
            && artifact_hash.is_some()
            && command.is_some()
            && stored_tool.as_deref() == selected_tool;
        let (Some(artifact_id), Some(artifact_hash), Some(command), true) =
            (artifact_id, artifact_hash, command, context_matches)
        else {
            self.invalidate(
                &selected_key,
                &persisted,
                &CLAUDE_NOTICE,
                "local_authority_integrity_notice_context_mismatch",
            );
            return None;
        };
        let pending_key = claude_pending_key(session_id, &artifact_id);
        let pending = self.claude_load_pending(
            session_id,
            &pending_key,
            Some(&artifact_id),
            Some(&artifact_hash),
            Some(&command),
        );
        if pending.is_none() {
            self.delete(&selected_key);
            return None;
        }
        Some(persisted)
    }

    pub(super) fn claude_mark_prompt_seen(
        &self,
        session_id: &str,
        artifact_id: &str,
        artifact_hash: &str,
        command: &str,
    ) {
        let pending_key = claude_pending_key(session_id, artifact_id);
        let Some(mut updated) = self.claude_load_pending(
            session_id,
            &pending_key,
            Some(artifact_id),
            Some(artifact_hash),
            Some(command),
        ) else {
            return;
        };
        updated.insert("permission_prompt_seen".to_owned(), Value::Bool(true));
        updated.insert("permission_prompt_seen_at".to_owned(), json!(self.now));
        self.store_signed(&pending_key, &Value::Object(updated), &CLAUDE_PENDING);
    }

    pub(super) fn claude_load_single_pending(&self, session_id: &str) -> Option<(String, Object)> {
        let mut items = Vec::new();
        for pending_key in self.load_index(&CLAUDE_FAMILY, session_id) {
            if let Some(pending) =
                self.claude_load_pending(session_id, &pending_key, None, None, None)
            {
                items.push((pending_key, pending));
            }
        }
        let seen = items
            .iter()
            .filter(|(_, pending)| {
                pending.get("permission_prompt_seen") == Some(&Value::Bool(true))
            })
            .count();
        if seen == 1 {
            let position = items.iter().position(|(_, pending)| {
                pending.get("permission_prompt_seen") == Some(&Value::Bool(true))
            })?;
            return Some(items.swap_remove(position));
        }
        if items.len() != 1 {
            return None;
        }
        items.pop()
    }

    pub(super) fn claude_remove_pending(&self, session_id: &str, pending_key: &str) {
        self.delete(pending_key);
        let remaining: Vec<String> = self
            .load_index(&CLAUDE_FAMILY, session_id)
            .into_iter()
            .filter(|key| key != pending_key)
            .collect();
        self.store_index(&CLAUDE_FAMILY, session_id, &remaining);
    }

    /// `_discard_claude_pending_permissions`: drops every indexed pending
    /// permission and the index itself; the count is zero when the delete fails.
    pub(super) fn claude_discard_session(&self, session_id: &str) -> usize {
        let mut keys = self.load_index(&CLAUDE_FAMILY, session_id);
        if keys.is_empty() {
            return 0;
        }
        let discarded = keys.len();
        keys.push(format!("{}{session_id}", CLAUDE_FAMILY.index_prefix));
        if self.delete_all(&keys) {
            discarded
        } else {
            0
        }
    }

    // ---- Cursor ------------------------------------------------------------

    /// `_load_cursor_pending_shell_permission`: the direct lookup, then every
    /// indexed key against the same expected key. An indexed key that is not
    /// the expected one fails the context check and is invalidated, as before.
    pub(super) fn cursor_find_pending(
        &self,
        conversation_id: &str,
        command: &str,
        expected_key: &str,
    ) -> Option<Object> {
        if let Some(pending) =
            self.cursor_load_pending_state(conversation_id, command, expected_key, expected_key)
        {
            return Some(pending);
        }
        self.load_index(&CURSOR_FAMILY, conversation_id)
            .iter()
            .find_map(|indexed_key| {
                self.cursor_load_pending_state(conversation_id, command, indexed_key, expected_key)
            })
    }

    /// Deletes the pending state and rewrites the index without it. A failed
    /// write is a store error, so the caller rolls the whole removal back.
    pub(super) fn cursor_remove_pending(
        &self,
        conversation_id: &str,
        pending_key: &str,
    ) -> Result<(), &'static str> {
        if !self.delete(pending_key) {
            return Err(ERROR_STORE);
        }
        let remaining: Vec<String> = self
            .load_index(&CURSOR_FAMILY, conversation_id)
            .into_iter()
            .filter(|key| key != pending_key)
            .collect();
        let stored = if remaining.is_empty() {
            self.delete(&format!("{}{conversation_id}", CURSOR_FAMILY.index_prefix))
        } else {
            self.store_index(&CURSOR_FAMILY, conversation_id, &remaining)
        };
        if stored {
            Ok(())
        } else {
            Err(ERROR_STORE)
        }
    }

    pub(super) fn cursor_load_pending_state(
        &self,
        conversation_id: &str,
        command: &str,
        state_key: &str,
        expected_key: &str,
    ) -> Option<Object> {
        let persisted = self.load_verified(state_key, &CURSOR_PENDING)?;
        let context_matches = state_key == expected_key
            && exact_str(&persisted, "conversation_id") == Some(conversation_id)
            && opt_str(&persisted, "artifact_id").is_some()
            && opt_str(&persisted, "artifact_hash").is_some()
            && opt_str(&persisted, "command").as_deref() == Some(command);
        if context_matches {
            return Some(persisted);
        }
        self.invalidate(
            state_key,
            &persisted,
            &CURSOR_PENDING,
            "local_authority_integrity_pending_context_mismatch",
        );
        None
    }

    pub(super) fn cursor_record_allow(
        &self,
        request: &HookAuthorityStateRequestV1,
    ) -> Result<bool, &'static str> {
        let state_key = required(&request.state_key)?;
        let payload = json!({
            "state_key": state_key,
            "conversation_id": required(&request.conversation_id)?,
            "saved_at": self.now,
            "action": "allow",
            "artifact_id": required(&request.artifact_id)?,
            "artifact_hash": required(&request.artifact_hash)?,
            "artifact_name": required(&request.artifact_name)?,
            "command": required(&request.command)?,
            "native_source": "cursor-native",
        });
        Ok(self.store_signed(state_key, &payload, &CURSOR_ALLOW))
    }

    pub(super) fn cursor_load_allowance(
        &self,
        conversation_id: &str,
        command: &str,
        state_key: &str,
    ) -> Option<Object> {
        let approved = match self.read(state_key) {
            Stored::InvalidJson => {
                self.record_failure(
                    &CURSOR_ALLOW,
                    state_key,
                    Value::Null,
                    "tampered",
                    Some("local_authority_integrity_payload_invalid_json"),
                );
                self.delete(state_key);
                return None;
            }
            Stored::Object(object) => object,
            Stored::Absent | Stored::Unreadable | Stored::List => return None,
        };
        let has_integrity =
            matches!(approved.get("integrity"), Some(Value::Object(map)) if !map.is_empty());
        let (status, message) = self.verify(&approved, &CURSOR_ALLOW, has_integrity);
        let context_matches = exact_str(&approved, "state_key") == Some(state_key)
            && exact_str(&approved, "conversation_id") == Some(conversation_id)
            && exact_str(&approved, "command") == Some(command);
        let fresh = exact_str(&approved, "action") == Some("allow")
            && is_fresh(
                approved.get("saved_at").and_then(Value::as_str),
                self.now,
                MAX_AGE_SECONDS,
            );
        if status == "valid" && context_matches && fresh {
            return Some(approved);
        }
        if status == "valid" && context_matches {
            self.delete(state_key);
            return None;
        }
        let (status, message) = if status != "valid" {
            (status, message)
        } else {
            (
                "tampered",
                Some("local_authority_integrity_context_mismatch"),
            )
        };
        self.record_failure(
            &CURSOR_ALLOW,
            state_key,
            approved.get("artifact_id").cloned().unwrap_or(Value::Null),
            status,
            message,
        );
        self.delete(state_key);
        None
    }
}
