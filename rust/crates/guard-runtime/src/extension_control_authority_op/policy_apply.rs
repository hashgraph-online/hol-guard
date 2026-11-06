//! `apply_policy`: `apply_policy_bundle_authority`, written by the resident.
//!
//! The caller verifies the bundle, asks the resident for its acknowledgement
//! and managed-controls seals, and encodes every payload before the write.
//! The resident then writes the remote policy decisions, the bundle state,
//! the managed-controls activation and the custom-extension continuity in one
//! transaction, and only while the authority snapshot and each `sync_state`
//! value the caller decided from are still the ones it read. When one moved,
//! nothing is written and the caller decides again.

use std::cell::RefCell;

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlPolicyApplyV1};
use guard_policy_snapshot::policy_integrity::REMOTE_POLICY_SOURCES;
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter};
use serde_json::{json, Value};

use super::managed::{ACTIVE_STATE_KEY, REVISION_STATE_KEY};
use super::policy_clear::NEGOTIATED_STATE_KEY;
use super::records::{degraded, query_row, row_int, row_str, store_fault, tampered, Res};
use super::resume::immediate;
use super::writes::open_writer;
use super::{fault_value, Ctx, STORE_UNAVAILABLE};
use crate::guard_store_args::Args;
use crate::guard_store_continuity_write::apply_continuity;
use crate::guard_store_db::StoreError;

/// The `sync_state` keys an activation decides from.
const OBSERVED_KEYS: [&str; 5] = [
    "policy_bundle_acceptance_checkpoint",
    "runtime_session_summary",
    "policy_bundle_ack",
    ACTIVE_STATE_KEY,
    REVISION_STATE_KEY,
];
/// Each last-good key and the payload `copy_last_good` copies into it.
const LAST_GOOD_COPIES: [(&str, &str); 2] = [
    ("policy_bundle_last_good", "policy_bundle"),
    ("managed_controls_last_good", ACTIVE_STATE_KEY),
];
/// The `sync_state` keys an activation may write.
const PAYLOAD_KEYS: [&str; 13] = [
    "cloud_exceptions",
    "policy",
    "policy_bundle",
    "policy_bundle_ack",
    "policy_bundle_acceptance_checkpoint",
    "policy_bundle_keyring",
    "policy_bundle_last_error",
    "policy_bundle_last_good",
    "team_policy_pack",
    ACTIVE_STATE_KEY,
    "managed_controls_last_good",
    NEGOTIATED_STATE_KEY,
    REVISION_STATE_KEY,
];
/// `policy_decisions` columns in the order each row carries them.
const COLUMNS: &str = "harness, scope, artifact_id, artifact_hash, workspace, publisher, action, \
     reason, owner, source, expires_at, updated_at, integrity_version, integrity_generation, \
     payload_hash, payload_mac, integrity_key_id, signed_at";
const COLUMN_COUNT: usize = 18;
const SOURCE_COLUMN: usize = 9;
const INVALID: &str = "invalid policy activation request";
const CONTINUITY_CHANGED: &str = "custom_extension_continuity_changed_during_activation";

pub(super) fn apply_policy_op(
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
        .apply_policy()
        .unwrap_or_else(|fault| fault_value(&fault, Vec::new())))
}

/// One decision's column values; a remote row only.
fn row_values(row: &[Value]) -> Res<Vec<SqlValue>> {
    let remote = row
        .get(SOURCE_COLUMN)
        .and_then(Value::as_str)
        .is_some_and(|source| REMOTE_POLICY_SOURCES.contains(&source));
    if row.len() != COLUMN_COUNT || !remote {
        return Err(tampered(INVALID));
    }
    row.iter()
        .map(|value| match value {
            Value::Null => Ok(SqlValue::Null),
            Value::String(text) => Ok(SqlValue::Text(text.clone())),
            Value::Number(number) => number
                .as_i64()
                .map(SqlValue::Integer)
                .ok_or_else(|| tampered(INVALID)),
            _ => Err(tampered(INVALID)),
        })
        .collect()
}

fn validate(apply: &ExtensionControlPolicyApplyV1) -> Res<Vec<Vec<SqlValue>>> {
    let payloads_valid = apply.payloads.iter().all(|(state_key, payload)| {
        PAYLOAD_KEYS.contains(&state_key.as_str()) && serde_json::from_str::<Value>(payload).is_ok()
    });
    let retires_written = apply.retire_managed
        && [ACTIVE_STATE_KEY, NEGOTIATED_STATE_KEY]
            .iter()
            .any(|state_key| apply.payloads.contains_key(*state_key));
    let copies_written = apply.copy_last_good
        && (!apply.payloads.contains_key("policy_bundle")
            || LAST_GOOD_COPIES
                .iter()
                .any(|(last_good, _)| apply.payloads.contains_key(*last_good)));
    if !payloads_valid
        || retires_written
        || copies_written
        || apply
            .observed
            .keys()
            .any(|state_key| !OBSERVED_KEYS.contains(&state_key.as_str()))
    {
        return Err(tampered(INVALID));
    }
    apply.rows.iter().map(|row| row_values(row)).collect()
}

impl Ctx<'_> {
    fn apply_policy(&self) -> Res<Value> {
        let apply = self
            .request
            .policy_apply
            .as_ref()
            .ok_or_else(|| tampered(INVALID))?;
        let now = self
            .request
            .now
            .as_deref()
            .ok_or_else(|| tampered(INVALID))?;
        let rows = validate(apply)?;
        immediate(self.connection, || {
            if !self.unchanged(apply)? {
                return Ok(json!({ "changed": true }));
            }
            if let Some(continuity) = &apply.continuity {
                if !self.apply_continuity(continuity)? {
                    return Ok(json!({ "rejected": CONTINUITY_CHANGED }));
                }
            }
            self.write_activation(apply, &rows, now)?;
            Ok(json!({ "applied": true }))
        })
    }

    /// The authority snapshot and every observed value are the ones read.
    fn unchanged(&self, apply: &ExtensionControlPolicyApplyV1) -> Res<bool> {
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
        if observed != (apply.base_revision, apply.base_snapshot_digest.clone()) {
            return Ok(false);
        }
        for (state_key, expected) in &apply.observed {
            if &self.state_text(state_key)? != expected {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Applies the continuity under a savepoint; `false` when the store
    /// refused it, with none of it written.
    fn apply_continuity(&self, continuity: &serde_json::Map<String, Value>) -> Res<bool> {
        self.connection
            .execute_batch("SAVEPOINT policy_continuity")
            .map_err(store_fault)?;
        let outcome = apply_continuity(self.connection, &Args(continuity));
        if outcome.is_err() {
            self.connection
                .execute_batch("ROLLBACK TO policy_continuity")
                .map_err(store_fault)?;
        }
        self.connection
            .execute_batch("RELEASE policy_continuity")
            .map_err(store_fault)?;
        match outcome {
            Ok(_) => Ok(true),
            Err(StoreError::Value(_)) => Ok(false),
            Err(StoreError::Invalid(_)) => Err(tampered(INVALID)),
            Err(_) => Err(degraded(STORE_UNAVAILABLE)),
        }
    }

    fn write_activation(
        &self,
        apply: &ExtensionControlPolicyApplyV1,
        rows: &[Vec<SqlValue>],
        now: &str,
    ) -> Res<()> {
        if apply.retire_managed {
            self.connection
                .execute(
                    "delete from sync_state where state_key in (?, ?)",
                    params![ACTIVE_STATE_KEY, NEGOTIATED_STATE_KEY],
                )
                .map_err(store_fault)?;
        }
        let placeholders = vec!["?"; REMOTE_POLICY_SOURCES.len()].join(",");
        self.connection
            .execute(
                &format!("delete from policy_decisions where source in ({placeholders})"),
                params_from_iter(REMOTE_POLICY_SOURCES),
            )
            .map_err(store_fault)?;
        let values = vec!["?"; COLUMN_COUNT].join(", ");
        let insert = format!("insert into policy_decisions ({COLUMNS}) values ({values})");
        for row in rows {
            self.connection
                .execute(&insert, params_from_iter(row))
                .map_err(store_fault)?;
        }
        let copies = LAST_GOOD_COPIES
            .iter()
            .filter(|_| apply.copy_last_good)
            .filter_map(|(last_good, source)| Some((*last_good, apply.payloads.get(*source)?)));
        let payloads = apply
            .payloads
            .iter()
            .map(|(state_key, payload)| (state_key.as_str(), payload));
        for (state_key, payload) in payloads.chain(copies) {
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
#[path = "policy_apply_tests.rs"]
mod tests;
