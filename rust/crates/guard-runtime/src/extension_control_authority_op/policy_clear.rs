//! `clear_policy`: `clear_policy_bundle_authority`, written by the resident.
//!
//! A clear drops every remote policy decision and the cached bundle, its
//! acknowledgement and the managed-controls activation, and moves the
//! managed publication epoch past the activation it retires. The caller
//! publishes the cleared view before the write lands, so it first asks for
//! the epoch without writing, validates that view, then asks again with that
//! epoch: the write goes ahead only while the authority snapshot, the epoch
//! and the stored acknowledgement are still the ones it published from.

use std::cell::RefCell;

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlPolicyClearV1};
use guard_policy_snapshot::policy_integrity::REMOTE_POLICY_SOURCES;
use rusqlite::{params, params_from_iter};
use serde_json::{json, Value};

use super::managed::{
    activation_layers, require_key, revision_from_state, ACTIVE_STATE_KEY, REVISION_STATE_KEY,
};
use super::managed_seals::revision_state;
use super::records::{query_row, row_int, row_str, row_text, store_fault, tampered, Res};
use super::resume::immediate;
use super::writes::open_writer;
use super::{fault_value, Ctx};

pub(super) const NEGOTIATED_STATE_KEY: &str = "managed_controls_negotiated_capabilities";
const ACK_STATE_KEY: &str = "policy_bundle_ack";
/// The `sync_state` keys a clear may write.
const PAYLOAD_KEYS: [&str; 5] = [
    "cloud_exceptions",
    "policy",
    "policy_bundle_last_error",
    "team_policy_pack",
    ACK_STATE_KEY,
];
const CHANGED: &str = "extension control authority changed during clear";
const INVALID: &str = "invalid policy clear request";

pub(super) fn clear_policy_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Result<Value, String> {
    let connection = match open_writer(request)? {
        Ok(connection) => connection,
        Err(reply) => return Ok(reply),
    };
    let ctx = Ctx {
        connection: &connection,
        key,
        request,
        events: RefCell::new(Vec::new()),
    };
    Ok(ctx
        .clear_policy()
        .unwrap_or_else(|fault| fault_value(&fault, Vec::new())))
}

impl Ctx<'_> {
    fn clear_policy(&self) -> Res<Value> {
        let clear = self
            .request
            .policy_clear
            .as_ref()
            .ok_or_else(|| tampered(INVALID))?;
        let now = self
            .request
            .now
            .as_deref()
            .ok_or_else(|| tampered(INVALID))?;
        for (state_key, payload) in &clear.payloads {
            if !PAYLOAD_KEYS.contains(&state_key.as_str())
                || serde_json::from_str::<Value>(payload).is_err()
            {
                return Err(tampered(INVALID));
            }
        }
        immediate(self.connection, || {
            self.require_base(clear)?;
            let managed_revision = self.cleared_managed_revision()?;
            let stored_ack = self.state_text(ACK_STATE_KEY)?;
            let Some(expected) = clear.managed_revision else {
                // The plan: nothing is written, so the commit only releases
                // the lock.
                return Ok(json!({
                    "managed_revision": managed_revision,
                    "stored_ack": stored_ack,
                }));
            };
            if expected != managed_revision || clear.stored_ack != stored_ack {
                return Err(tampered(CHANGED));
            }
            self.write_clear(clear, managed_revision, now)?;
            Ok(json!({ "cleared": true, "managed_revision": managed_revision }))
        })
    }

    /// The authority snapshot is still the one the caller read.
    fn require_base(&self, clear: &ExtensionControlPolicyClearV1) -> Res<()> {
        let row = query_row(
            self.connection,
            "select revision, snapshot_digest from extension_control_authority_snapshot
             where singleton = 1",
            [],
        )?;
        let observed = match row {
            None => (None, None),
            Some(row) => (
                Some(row_int(&row, "revision")?),
                Some(row_str(&row, "snapshot_digest")?),
            ),
        };
        if observed != (clear.base_revision, clear.base_snapshot_digest.clone()) {
            return Err(tampered(CHANGED));
        }
        Ok(())
    }

    pub(super) fn state_text(&self, state_key: &str) -> Res<Option<String>> {
        query_row(
            self.connection,
            "select payload_json from sync_state where state_key = ?",
            [state_key],
        )?
        .map(|row| row_text(&row, "payload_json"))
        .transpose()
    }

    /// The publication epoch after the clear: one past the retired
    /// activation, or the stored epoch when nothing is active.
    fn cleared_managed_revision(&self) -> Res<i64> {
        let active = self.state_text(ACTIVE_STATE_KEY)?;
        let revision = self.state_text(REVISION_STATE_KEY)?;
        if active.is_none() && revision.is_none() {
            return Ok(0);
        }
        let key = require_key(self.key)?;
        let stored = revision
            .map(|text| {
                serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|state| revision_from_state(&state, key).ok())
                    .ok_or_else(|| tampered("invalid managed controls revision"))
            })
            .transpose()?;
        let Some(active) = active else {
            return Ok(stored.unwrap_or(0));
        };
        let active_revision = serde_json::from_str::<Value>(&active)
            .ok()
            .and_then(|state| {
                let catalog_digest = state
                    .get("catalogDigest")
                    .filter(|digest| digest.as_str().is_some_and(|text| !text.is_empty()))?
                    .clone();
                activation_layers(&state, &catalog_digest, key).ok()
            })
            .map(|(_, revision)| revision)
            .ok_or_else(|| tampered("invalid managed controls activation"))?;
        if stored.is_some_and(|stored| stored != active_revision) {
            return Err(tampered("managed controls revision mismatch"));
        }
        Ok(active_revision + 1)
    }

    fn write_clear(
        &self,
        clear: &ExtensionControlPolicyClearV1,
        managed_revision: i64,
        now: &str,
    ) -> Res<()> {
        let mut payloads = clear.payloads.clone();
        if managed_revision > 0 {
            let state = revision_state(managed_revision, require_key(self.key)?)?;
            payloads.insert(REVISION_STATE_KEY.to_owned(), state.to_string());
        }
        let placeholders = vec!["?"; REMOTE_POLICY_SOURCES.len()].join(",");
        self.connection
            .execute(
                &format!("delete from policy_decisions where source in ({placeholders})"),
                params_from_iter(REMOTE_POLICY_SOURCES),
            )
            .map_err(store_fault)?;
        self.connection
            .execute(
                "delete from sync_state where state_key in (?, ?, ?, ?)",
                params![
                    "policy_bundle",
                    ACK_STATE_KEY,
                    ACTIVE_STATE_KEY,
                    NEGOTIATED_STATE_KEY
                ],
            )
            .map_err(store_fault)?;
        for (state_key, payload) in &payloads {
            self.connection
                .execute(
                    "insert into sync_state (state_key, payload_json, updated_at)
                     values (?, ?, ?)
                     on conflict(state_key) do update set
                       payload_json = excluded.payload_json,
                       updated_at = excluded.updated_at",
                    params![state_key, payload, now],
                )
                .map_err(store_fault)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "policy_clear_tests.rs"]
mod tests;
