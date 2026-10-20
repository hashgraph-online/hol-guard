//! Startup generation decision for `PolicyIntegrityRows`.
//!
//! Startup prefetches the trusted policy-integrity control state, then
//! authenticates it against the store's local rows before trusting it. This
//! reads those rows read-only and decides, with the same verifier the
//! saved-decision lookup uses:
//!
//! - with no pending generation and no legacy row, a single newer generation
//!   that every row authenticates at is adopted;
//! - a pending generation is completed when every row verifies at it, and
//!   abandoned when every row still verifies at the current generation;
//! - cutover is marked complete once no legacy row remains.
//!
//! `still_matches` reports whether every local row verifies at the trusted
//! generation as given. Remote-sourced rows are excluded, as are rows whose
//! source is null, exactly as the store's own queries exclude them.

use std::collections::BTreeSet;

use guard_contracts::{PolicyIntegrityGenerationOutcomeV1, PolicyIntegrityGenerationRequestV1};
use guard_policy_snapshot::policy_integrity::{verify_local_policy_row, REMOTE_POLICY_SOURCES};
use rusqlite::types::ValueRef;
use serde_json::{json, Map, Value};

use crate::local_store_read::{open_read_only, require_store_path, table_exists};
use crate::policy_integrity_resolver::normalize_policy_integrity_control_state;

const POLICY_INTEGRITY_VERSION: i64 = 2;
const CONTROL_STATE_VERSION: i64 = 1;
const ROW_COLUMNS: [&str; 19] = [
    "decision_id",
    "harness",
    "scope",
    "artifact_id",
    "artifact_hash",
    "workspace",
    "publisher",
    "action",
    "reason",
    "owner",
    "source",
    "expires_at",
    "updated_at",
    "integrity_version",
    "integrity_generation",
    "payload_hash",
    "payload_mac",
    "integrity_key_id",
    "signed_at",
];

pub(crate) fn decide(
    request: &PolicyIntegrityGenerationRequestV1,
    key: &[u8],
    key_id: &str,
) -> Result<PolicyIntegrityGenerationOutcomeV1, &'static str> {
    let trusted = normalize_policy_integrity_control_state(&request.trusted_state)
        .filter(|normalized| *normalized == request.trusted_state)
        .ok_or("native_policy_integrity_state_invalid")?;
    let LocalRows { rows, has_legacy } = load_local_rows(request)?;
    let verifier = Verifier { key, key_id };
    let trusted_generation = generation_of(&trusted);
    let still_matches = rows
        .iter()
        .all(|row| verifier.valid_at(row, trusted_generation));
    Ok(PolicyIntegrityGenerationOutcomeV1 {
        prepared_state: prepared_state(&rows, has_legacy, &verifier, trusted),
        still_matches,
    })
}

struct Verifier<'a> {
    key: &'a [u8],
    key_id: &'a str,
}

impl Verifier<'_> {
    fn valid_at(&self, row: &Value, generation: Option<i64>) -> bool {
        verify_local_policy_row(row, Some(self.key), Some(self.key_id), false, generation).status
            == "valid"
    }
}

fn prepared_state(
    rows: &[Value],
    has_legacy: bool,
    verifier: &Verifier<'_>,
    trusted: Value,
) -> Value {
    let mut prepared = trusted;
    if !prepared["pending_generation"].is_i64() && !has_legacy {
        if let Some(newer) =
            newer_authenticated_generation(rows, verifier, generation_of(&prepared))
        {
            prepared["generation"] = Value::from(newer);
        }
    }
    let mut prepared = resolved_pending_generation(rows, verifier, prepared);
    if prepared["cutover_complete"] != Value::Bool(true) && !has_legacy {
        prepared["cutover_complete"] = Value::Bool(true);
    }
    prepared
}

/// The one generation above `trusted` that every row authenticates at, when
/// no row is at `trusted` itself and none is older or unauthenticated.
fn newer_authenticated_generation(
    rows: &[Value],
    verifier: &Verifier<'_>,
    trusted: Option<i64>,
) -> Option<i64> {
    let mut generations = Vec::with_capacity(rows.len());
    for row in rows {
        if row["integrity_version"].as_i64() != Some(POLICY_INTEGRITY_VERSION) {
            return None;
        }
        generations.push(row["integrity_generation"].as_i64()?);
    }
    let mut current_valid = 0usize;
    let mut newer = BTreeSet::new();
    for (row, generation) in rows.iter().zip(generations) {
        if !verifier.valid_at(row, Some(generation)) {
            return None;
        }
        match trusted {
            Some(trusted) if generation == trusted => current_valid += 1,
            Some(trusted) if generation < trusted => return None,
            _ => {
                newer.insert(generation);
            }
        }
    }
    if current_valid > 0 || newer.len() != 1 {
        return None;
    }
    newer.into_iter().next()
}

fn resolved_pending_generation(rows: &[Value], verifier: &Verifier<'_>, trusted: Value) -> Value {
    let Some(current) = generation_of(&trusted) else {
        return trusted;
    };
    let pending = match trusted["pending_generation"].as_i64() {
        Some(pending) if pending > current => pending,
        _ => return trusted,
    };
    if rows.is_empty() {
        return cut_over_at(pending);
    }
    let mut has_legacy = false;
    let (mut pending_candidates, mut pending_valid, mut current_valid) = (0usize, 0usize, 0usize);
    for row in rows {
        let current_ok = verifier.valid_at(row, Some(current));
        if row["integrity_version"].as_i64() == Some(POLICY_INTEGRITY_VERSION) {
            pending_candidates += 1;
            if verifier.valid_at(row, Some(pending)) {
                pending_valid += 1;
                continue;
            }
        } else {
            has_legacy = true;
        }
        if current_ok {
            current_valid += 1;
        }
    }
    let mut next = trusted;
    if has_legacy {
        if pending_candidates > 0 && current_valid == rows.len() {
            next["pending_generation"] = Value::Null;
        }
    } else if pending_valid == rows.len() {
        next = cut_over_at(pending);
    } else if current_valid == rows.len() {
        next["pending_generation"] = Value::Null;
    }
    next
}

fn cut_over_at(generation: i64) -> Value {
    json!({
        "cutover_complete": true,
        "generation": generation,
        "pending_generation": null,
        "version": CONTROL_STATE_VERSION,
    })
}

fn generation_of(state: &Value) -> Option<i64> {
    state["generation"].as_i64()
}

struct LocalRows {
    /// Text and integers as is, any other SQLite value as null, which is how
    /// the verifier reads a row.
    rows: Vec<Value>,
    /// Some row is not version 2 or lacks a signature column, by SQLite's own
    /// comparison rules.
    has_legacy: bool,
}

fn load_local_rows(
    request: &PolicyIntegrityGenerationRequestV1,
) -> Result<LocalRows, &'static str> {
    const UNAVAILABLE: &str = "native_policy_integrity_store_unavailable";
    let store_path = require_store_path(&request.store_path, &request.guard_home)
        .map_err(|_| "native_policy_integrity_store_path_invalid")?;
    let connection = open_read_only(&store_path)
        .map_err(|_| UNAVAILABLE)?
        .ok_or(UNAVAILABLE)?;
    if !table_exists(&connection, "policy_decisions").map_err(|_| UNAVAILABLE)? {
        return Err(UNAVAILABLE);
    }
    let remote = REMOTE_POLICY_SOURCES
        .iter()
        .enumerate()
        .map(|(index, _)| format!("?{}", index + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let legacy_sql = format!(
        "select exists(select 1 from policy_decisions where source not in ({remote}) and (\
         integrity_version is null or integrity_version != {POLICY_INTEGRITY_VERSION} \
         or payload_hash is null or payload_mac is null or integrity_key_id is null \
         or signed_at is null))"
    );
    let has_legacy = connection
        .query_row(
            &legacy_sql,
            rusqlite::params_from_iter(REMOTE_POLICY_SOURCES.iter()),
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| UNAVAILABLE)?;
    let sql = format!(
        "select {} from policy_decisions where source not in ({remote}) order by updated_at desc",
        ROW_COLUMNS.join(", ")
    );
    let mut statement = connection.prepare(&sql).map_err(|_| UNAVAILABLE)?;
    let mut cursor = statement
        .query(rusqlite::params_from_iter(REMOTE_POLICY_SOURCES.iter()))
        .map_err(|_| UNAVAILABLE)?;
    let mut rows = Vec::new();
    while let Some(row) = cursor.next().map_err(|_| UNAVAILABLE)? {
        let mut object = Map::with_capacity(ROW_COLUMNS.len());
        for (index, column) in ROW_COLUMNS.iter().enumerate() {
            let cell = row.get_ref(index).map_err(|_| UNAVAILABLE)?;
            object.insert((*column).to_owned(), cell_value(cell)?);
        }
        rows.push(Value::Object(object));
    }
    Ok(LocalRows { rows, has_legacy })
}

fn cell_value(cell: ValueRef<'_>) -> Result<Value, &'static str> {
    Ok(match cell {
        ValueRef::Integer(value) => Value::from(value),
        ValueRef::Text(text) => Value::from(
            std::str::from_utf8(text).map_err(|_| "native_policy_integrity_store_unavailable")?,
        ),
        ValueRef::Null | ValueRef::Real(_) | ValueRef::Blob(_) => Value::Null,
    })
}

#[cfg(test)]
#[path = "policy_integrity_generation_tests.rs"]
mod tests;
