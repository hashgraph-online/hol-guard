//! Signed `sync_state` persistence for the hook authority state op: read,
//! delete, audit, sign, verify and the key indexes.

use super::*;

impl Env<'_> {
    pub(super) fn read(&self, state_key: &str) -> Stored {
        let row = self
            .connection
            .query_row(
                "select payload_json from sync_state where state_key = ?1",
                params![state_key],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional();
        let text = match row {
            Err(_) => return Stored::Unreadable,
            Ok(None) => return Stored::Absent,
            Ok(Some(None)) => return Stored::InvalidJson,
            Ok(Some(Some(text))) => text,
        };
        match serde_json::from_str::<Value>(&text) {
            Err(_) => Stored::InvalidJson,
            Ok(Value::Object(object)) => Stored::Object(object),
            Ok(Value::Array(_)) => Stored::List,
            Ok(_) => Stored::Absent,
        }
    }

    pub(super) fn delete(&self, state_key: &str) {
        let _ = self.connection.execute(
            "delete from sync_state where state_key = ?1",
            params![state_key],
        );
    }

    pub(super) fn add_event(&self, name: &str, payload: &Value) {
        let Some(text) = dumps_default(payload) else {
            return;
        };
        let _ = self.connection.execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?1, ?2, ?3)",
            params![name, text, self.now],
        );
    }

    pub(super) fn record_failure(
        &self,
        kind: &Kind,
        state_key: &str,
        artifact_id: Value,
        status: &str,
        message: Option<&str>,
    ) {
        self.add_event(
            "rule.ignored.local_integrity",
            &json!({
                "decision_id": null,
                "harness": kind.harness,
                "artifact_id": artifact_id,
                "scope": "session",
                "source": kind.source,
                "integrity_status": status,
                "message": message,
                "state_key_fingerprint": fingerprint(state_key),
            }),
        );
    }

    fn key_bytes(&self) -> Option<&[u8]> {
        self.key.as_ref().map(|key| key.as_slice())
    }

    /// Sign `payload` for `kind` and persist it under `state_key`. `false` when
    /// there is no key or the store refuses the write.
    pub(super) fn store_signed(&self, state_key: &str, payload: &Value, kind: &Kind) -> bool {
        let (Some(key), Some(key_id)) = (self.key_bytes(), self.key_id) else {
            return false;
        };
        let Value::Object(source) = payload else {
            return false;
        };
        if let Some(flag) = self.foreign_key {
            if let Stored::Object(existing) = self.read(state_key) {
                let signed_key_id = existing
                    .get("integrity")
                    .and_then(Value::as_object)
                    .and_then(|integrity| integrity.get("integrity_key_id"))
                    .and_then(Value::as_str);
                if signed_key_id.is_some_and(|signed| Some(signed) != self.key_id) {
                    flag.set(true);
                    return false;
                }
            }
        }
        let mut signed: Object = source
            .iter()
            .filter(|(name, _)| name.as_str() != "integrity")
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        signed.insert("state_key".to_owned(), Value::String(state_key.to_owned()));
        let Ok(fields) = sign_local_authority_payload(
            &Value::Object(signed.clone()),
            key,
            key_id,
            kind.purpose,
            self.now,
        ) else {
            return false;
        };
        signed.insert(
            "integrity".to_owned(),
            json!({
                "integrity_version": fields.integrity_version,
                "payload_hash": fields.payload_hash,
                "payload_mac": fields.payload_mac,
                "integrity_key_id": fields.integrity_key_id,
                "signed_at": fields.signed_at,
            }),
        );
        let Some(text) = dumps_default(&Value::Object(signed)) else {
            return false;
        };
        self.connection
            .execute(
                "insert into sync_state (state_key, payload_json, updated_at) values (?1, ?2, ?3) \
                 on conflict(state_key) do update set \
                 payload_json = excluded.payload_json, updated_at = excluded.updated_at",
                params![state_key, text, self.now],
            )
            .is_ok()
    }

    pub(super) fn verify(
        &self,
        persisted: &Object,
        kind: &Kind,
        use_key: bool,
    ) -> (&'static str, Option<&'static str>) {
        let integrity = match persisted.get("integrity") {
            Some(value @ Value::Object(_)) => value.clone(),
            _ => json!({}),
        };
        let signed: Object = persisted
            .iter()
            .filter(|(name, _)| name.as_str() != "integrity")
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let (key, key_id) = if use_key {
            (self.key_bytes(), self.key_id)
        } else {
            (None, None)
        };
        let result = verify_local_authority_payload(
            &Value::Object(signed),
            &integrity,
            key,
            key_id,
            kind.purpose,
        );
        (result.status, result.message)
    }

    /// The signed row under `state_key` when it is authentic, bound to its key
    /// and fresh. Anything else is recorded and deleted.
    pub(super) fn load_verified(&self, state_key: &str, kind: &Kind) -> Option<Object> {
        let persisted = match self.read(state_key) {
            Stored::Unreadable | Stored::Absent => return None,
            Stored::InvalidJson => {
                self.record_failure(
                    kind,
                    state_key,
                    Value::Null,
                    "tampered",
                    Some("local_authority_integrity_payload_invalid_json"),
                );
                self.delete(state_key);
                return None;
            }
            Stored::List => {
                self.record_failure(
                    kind,
                    state_key,
                    Value::Null,
                    "missing_integrity",
                    Some("local_authority_integrity_metadata_missing"),
                );
                self.delete(state_key);
                return None;
            }
            Stored::Object(object) => object,
        };
        if let Some(flag) = self.foreign_key {
            let signed_key_id = persisted
                .get("integrity")
                .and_then(Value::as_object)
                .and_then(|integrity| integrity.get("integrity_key_id"))
                .and_then(Value::as_str);
            if signed_key_id.is_some_and(|signed| Some(signed) != self.key_id) {
                flag.set(true);
                return None;
            }
        }
        let (status, message) = self.verify(&persisted, kind, true);
        let context_matches = exact_str(&persisted, "state_key") == Some(state_key);
        if status != "valid" || !context_matches {
            let (status, message) = if status != "valid" {
                (status, message)
            } else {
                (
                    "tampered",
                    Some("local_authority_integrity_state_key_mismatch"),
                )
            };
            self.record_failure(
                kind,
                state_key,
                persisted.get("artifact_id").cloned().unwrap_or(Value::Null),
                status,
                message,
            );
            self.delete(state_key);
            return None;
        }
        if !is_fresh(
            persisted.get("saved_at").and_then(Value::as_str),
            self.now,
            MAX_AGE_SECONDS,
        ) {
            self.add_event(
                "approval.pending_state_expired",
                &json!({
                    "harness": kind.harness,
                    "source": kind.source,
                    "artifact_id": persisted.get("artifact_id").cloned().unwrap_or(Value::Null),
                    "state_key_fingerprint": fingerprint(state_key),
                }),
            );
            self.delete(state_key);
            return None;
        }
        Some(persisted)
    }

    pub(super) fn invalidate(
        &self,
        state_key: &str,
        persisted: &Object,
        kind: &Kind,
        message: &str,
    ) {
        self.record_failure(
            kind,
            state_key,
            persisted.get("artifact_id").cloned().unwrap_or(Value::Null),
            "tampered",
            Some(message),
        );
        self.delete(state_key);
    }

    // ---- per-owner indexes -------------------------------------------------

    pub(super) fn load_index(&self, family: &Family, owner: &str) -> Vec<String> {
        let index_key = format!("{}{owner}", family.index_prefix);
        let Some(persisted) = self.load_verified(&index_key, family.kind) else {
            return Vec::new();
        };
        let expected_prefix = format!("{}{owner}:", family.item_prefix);
        let keys = persisted
            .get("pending_keys")
            .and_then(Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .filter(|text| text.starts_with(&expected_prefix))
                    })
                    .collect::<Option<Vec<&str>>>()
            });
        match keys {
            Some(keys) if exact_str(&persisted, family.owner_field) == Some(owner) => {
                dedupe(keys.into_iter().map(str::to_owned))
            }
            _ => {
                self.invalidate(
                    &index_key,
                    &persisted,
                    family.kind,
                    "local_authority_integrity_pending_index_context_mismatch",
                );
                Vec::new()
            }
        }
    }

    pub(super) fn store_index(&self, family: &Family, owner: &str, keys: &[String]) -> bool {
        let index_key = format!("{}{owner}", family.index_prefix);
        if keys.is_empty() {
            self.delete(&index_key);
            return true;
        }
        let mut payload = Object::new();
        payload.insert(family.owner_field.to_owned(), json!(owner));
        payload.insert(
            "pending_keys".to_owned(),
            json!(dedupe(keys.iter().cloned())),
        );
        payload.insert("saved_at".to_owned(), json!(self.now));
        self.store_signed(&index_key, &Value::Object(payload), family.kind)
    }

    pub(super) fn append_key(&self, family: &Family, owner: &str, pending_key: &str) -> bool {
        let mut keys = self.load_index(family, owner);
        if keys.iter().any(|key| key == pending_key) {
            return true;
        }
        keys.push(pending_key.to_owned());
        self.store_index(family, owner, &keys)
    }
}
