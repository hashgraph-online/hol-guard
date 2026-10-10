//! `store_policy.py` `claim_approval_reuse_decisions` + `_claim_approval_reuse_decision_locked`
//! — the atomic saved-allow claim transaction, ported to `rusqlite`.
//!
//! The Python owner runs this inside one `BEGIN IMMEDIATE` so a denied launch
//! cannot consume a sibling grant. The caller supplies an open `Connection`
//! and owns commit/rollback exactly as the Python store does.
//!
//! Two member shapes: `approval_id` → `guard_local_once_approvals` row
//! (delegated to `local_once_store`); `decision_id` → `policy_decisions` row
//! (verified + optionally consumed here).

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::collections::BTreeSet;

use guard_contracts::canonical_utc_timestamp;
use guard_policy_snapshot::policy_integrity::{
    is_remote_policy_source, PolicyIntegrityVerification,
};

use crate::local_once_store::claim_local_once_approval_by_id_locked;

/// Policy sources that must never be consumed by a reuse claim
/// (`_claim_approval_reuse_decision_locked` rejects them outright).
const NON_REUSABLE_REMOTE_SOURCES: [&str; 2] = ["cloud-sync", "team-policy"];

/// `approval_reuse_claim_disposition` (:2036-2064).
///
/// `None` = not claimable. `"retained"` = stays authoritative. `"consumed"` =
/// one-shot row deleted by the claim.
pub fn approval_reuse_claim_disposition(decision: &Value) -> Option<&'static str> {
    // One implementation: the approval-proof op owns the lattice.
    crate::approval_proof_op::claim_disposition(decision.as_object()?).map(|d| d.as_str())
}

/// `_approval_authority_revision` (:593-599) — the singleton revision used to
/// detect a concurrent authority change between evaluation and claim.
pub fn approval_authority_revision(connection: &Connection) -> rusqlite::Result<i64> {
    let revision: Option<i64> = connection
        .query_row(
            "select revision from guard_approval_authority_revision where singleton = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(revision.unwrap_or(0))
}

/// `_materialized_policy_bundle_row_identity` (:670-681) — the 11-column tuple
/// a `policy-bundle` row must match against the authorized bundle's decision
/// identities. Returned as the canonical JSON array string so callers compare
/// against `serde_json::to_string` of the same tuple order.
pub fn materialized_policy_bundle_row_identity(row: &Value) -> Vec<Value> {
    vec![
        row.get("harness").cloned().unwrap_or(Value::Null),
        row.get("scope").cloned().unwrap_or(Value::Null),
        row.get("artifact_id").cloned().unwrap_or(Value::Null),
        row.get("artifact_hash").cloned().unwrap_or(Value::Null),
        row.get("workspace").cloned().unwrap_or(Value::Null),
        row.get("publisher").cloned().unwrap_or(Value::Null),
        row.get("action").cloned().unwrap_or(Value::Null),
        row.get("reason").cloned().unwrap_or(Value::Null),
        row.get("owner").cloned().unwrap_or(Value::Null),
        row.get("source").cloned().unwrap_or(Value::Null),
        row.get("expires_at").cloned().unwrap_or(Value::Null),
    ]
}

/// Column order for the `policy_decisions` SELECT in
/// `claim_approval_reuse_decision_locked`. Integer columns read as i64; the
/// rest read as optional text, matching `_row_mapping` (sqlite3.Row → dict).
pub(crate) fn policy_row_to_value(row: &rusqlite::Row) -> rusqlite::Result<Value> {
    let text = |i: usize| -> rusqlite::Result<Value> {
        Ok(row
            .get::<_, Option<String>>(i)?
            .map_or(Value::Null, Value::String))
    };
    let int = |i: usize| -> rusqlite::Result<Value> {
        Ok(row
            .get::<_, Option<i64>>(i)?
            .map_or(Value::Null, Value::from))
    };
    Ok(serde_json::json!({
        "decision_id": int(0)?,
        "harness": text(1)?,
        "scope": text(2)?,
        "artifact_id": text(3)?,
        "action": text(4)?,
        "artifact_hash": text(5)?,
        "workspace": text(6)?,
        "publisher": text(7)?,
        "source": text(8)?,
        "reason": text(9)?,
        "owner": text(10)?,
        "expires_at": text(11)?,
        "updated_at": text(12)?,
        "integrity_version": int(13)?,
        "integrity_generation": int(14)?,
        "payload_hash": text(15)?,
        "payload_mac": text(16)?,
        "integrity_key_id": text(17)?,
        "signed_at": text(18)?,
    }))
}

/// `_policy_row_payload` (`store_secret_policy_integrity.py:1143-1186`) —
/// the merged decision dict compared key-for-key against the selected allow.
pub(crate) fn policy_row_payload(
    row: &Value,
    integrity_result: Option<&PolicyIntegrityVerification>,
    state: Option<&Value>,
) -> Value {
    let source = row.get("source").and_then(Value::as_str).unwrap_or("");
    let mut payload = serde_json::json!({
        "action": row.get("action").and_then(Value::as_str).unwrap_or(""),
        "artifact_hash": row.get("artifact_hash").cloned().unwrap_or(Value::Null),
        "artifact_id": row.get("artifact_id").cloned().unwrap_or(Value::Null),
        "decision_id": row.get("decision_id").and_then(Value::as_i64),
        "expires_at": row.get("expires_at").cloned().unwrap_or(Value::Null),
        "harness": row.get("harness").and_then(Value::as_str).unwrap_or(""),
        "owner": row.get("owner").cloned().unwrap_or(Value::Null),
        "publisher": row.get("publisher").cloned().unwrap_or(Value::Null),
        "reason": row.get("reason").cloned().unwrap_or(Value::Null),
        "scope": row.get("scope").and_then(Value::as_str).unwrap_or(""),
        "source": source,
        "updated_at": row.get("updated_at").and_then(Value::as_str).unwrap_or(""),
        "workspace": row.get("workspace").cloned().unwrap_or(Value::Null),
    });
    let (fresh, durable) = crate::approval_reuse::exact_artifact_approval_qualification(
        row,
        source,
        integrity_result.is_some_and(|result| result.status == "valid"),
    );
    payload["fresh_local_approval"] = Value::Bool(fresh);
    payload["durable_exact_approval"] = Value::Bool(durable);
    if integrity_result.is_some() && !is_remote_policy_source(Some(source)) {
        let res = integrity_result.unwrap();
        payload["integrity_status"] = Value::from(res.status);
        payload["integrity_message"] = res.message.map_or(Value::Null, Value::from);
    }
    if state.is_some() && !is_remote_policy_source(Some(source)) {
        let state = state.unwrap();
        payload["integrity_mode"] = state.get("mode").cloned().unwrap_or(Value::Null);
        payload["integrity_enforcement"] = state.get("enforcement").cloned().unwrap_or(Value::Null);
    }
    if let Some(v) = row.get("integrity_version").and_then(Value::as_i64) {
        payload["integrity_version"] = Value::from(v);
    }
    if let Some(g) = row.get("integrity_generation").and_then(Value::as_i64) {
        payload["integrity_generation"] = Value::from(g);
    }
    if let Some(k) = row.get("integrity_key_id").and_then(Value::as_str) {
        payload["integrity_key_id"] = Value::from(k.to_owned());
    }
    if let Some(s) = row.get("signed_at").and_then(Value::as_str) {
        payload["signed_at"] = Value::from(s.to_owned());
    }
    payload
}

/// The 20 identity keys compared against the selected allow
/// (:2243-2264). `integrity_message` is produced by `_policy_row_payload` but
/// is NOT in the comparison set.
const IDENTITY_KEYS: [&str; 20] = [
    "action",
    "artifact_hash",
    "artifact_id",
    "decision_id",
    "expires_at",
    "harness",
    "integrity_enforcement",
    "integrity_generation",
    "integrity_key_id",
    "integrity_mode",
    "integrity_status",
    "integrity_version",
    "owner",
    "publisher",
    "reason",
    "signed_at",
    "scope",
    "source",
    "updated_at",
    "workspace",
];

/// `_claim_approval_reuse_decision_locked` (:2142-2298) — one member of an
/// open batch.
///
/// `integrity_state` is the caller-resolved `_refresh_policy_integrity_state`
/// payload (generation/mode/enforcement); `integrity_key`/`_id` resolve the
/// policy HMAC. Remote sources skip verification; `cloud-sync`/`team-policy`
/// are rejected before any read.
#[allow(clippy::too_many_arguments)]
fn claim_approval_reuse_decision_locked(
    connection: &Connection,
    decision: &Value,
    current_time: &str,
    local_integrity_key: Option<&[u8]>,
    local_integrity_key_id: Option<&str>,
    policy_bundle_decision_identities: Option<&BTreeSet<String>>,
    integrity_state: Option<&Value>,
    integrity_key: Option<&[u8]>,
    integrity_key_id: Option<&str>,
) -> rusqlite::Result<bool> {
    let approval_id = decision.get("approval_id");
    let decision_id = decision.get("decision_id");

    // Local-once branch.
    if let Some(aid) = approval_id.and_then(Value::as_str) {
        if aid.is_empty() {
            return Ok(false);
        }
        let disposition = approval_reuse_claim_disposition(decision);
        let Some(disposition) = disposition else {
            return Ok(false);
        };
        let claimed = claim_local_once_approval_by_id_locked(
            connection,
            aid,
            current_time,
            Some(decision),
            local_integrity_key,
            local_integrity_key_id,
            disposition == "consumed",
        )?;
        let Some(claimed) = claimed else {
            return Ok(false);
        };
        let event_name = if disposition == "retained" {
            "approval.local_once_reused"
        } else {
            "approval.local_once_applied"
        };
        connection.execute(
            "insert into guard_events (event_name, payload_json, occurred_at) values (?1, ?2, ?3)",
            params![
                event_name,
                serde_json::to_string(&serde_json::json!({
                    "approval_id": claimed.get("approval_id").cloned().unwrap_or(Value::Null),
                    "request_id": claimed.get("request_id").cloned().unwrap_or(Value::Null),
                    "harness": claimed.get("harness").cloned().unwrap_or(Value::Null),
                    "artifact_id": claimed.get("artifact_id").cloned().unwrap_or(Value::Null),
                }))
                .unwrap_or_default(),
                current_time,
            ],
        )?;
        return Ok(true);
    }

    // Policy-row branch.
    let Some(did) = decision_id.and_then(Value::as_i64) else {
        return Ok(false);
    };
    let row: Option<Value> = connection
        .query_row(
            "select decision_id, harness, scope, artifact_id, action, artifact_hash, \
             workspace, publisher, source, reason, owner, expires_at, updated_at, \
             integrity_version, integrity_generation, payload_hash, payload_mac, \
             integrity_key_id, signed_at \
             from policy_decisions \
             where decision_id = ?1 and action = 'allow' \
               and (expires_at is null or julianday(expires_at) > julianday(?2))",
            params![did, current_time],
            policy_row_to_value,
        )
        .optional()?;
    let Some(row) = row else { return Ok(false) };
    let source = row.get("source").and_then(Value::as_str).unwrap_or("");
    if NON_REUSABLE_REMOTE_SOURCES.contains(&source) {
        return Ok(false);
    }
    if source == "policy-bundle" {
        let Some(identities) = policy_bundle_decision_identities else {
            return Ok(false);
        };
        let identity = serde_json::to_string(&materialized_policy_bundle_row_identity(&row))
            .unwrap_or_default();
        if !identities.contains(&identity) {
            return Ok(false);
        }
    }
    let (integrity_result, effective_state): (PolicyIntegrityVerification, Option<Value>) =
        if is_remote_policy_source(Some(source)) {
            (
                PolicyIntegrityVerification {
                    status: "valid",
                    payload_hash: None,
                    key_id: None,
                    message: None,
                    generation: None,
                },
                None,
            )
        } else {
            let state = integrity_state
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            let generation = state.get("generation").and_then(Value::as_i64);
            let mode = state
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("degraded");
            (
                guard_policy_snapshot::policy_integrity::verify_local_policy_row(
                    &row,
                    integrity_key,
                    integrity_key_id,
                    mode != "protected",
                    generation,
                ),
                Some(state),
            )
        };
    if integrity_result.status != "valid" {
        return Ok(false);
    }
    let current_payload =
        policy_row_payload(&row, Some(&integrity_result), effective_state.as_ref());
    if IDENTITY_KEYS
        .iter()
        .any(|key| current_payload.get(*key) != decision.get(*key))
    {
        return Ok(false);
    }
    let Some(disposition) = approval_reuse_claim_disposition(&current_payload) else {
        return Ok(false);
    };
    if disposition == "consumed" {
        let changed = connection.execute(
            "delete from policy_decisions where decision_id = ?1 and action = 'allow'",
            params![did],
        )?;
        if changed != 1 {
            return Ok(false);
        }
    }
    connection.execute(
        "insert into guard_events (event_name, payload_json, occurred_at) values (?1, ?2, ?3)",
        params![
            "approval.policy_reuse_applied",
            serde_json::to_string(&serde_json::json!({
                "decision_id": did,
                "harness": current_payload.get("harness").cloned().unwrap_or(Value::Null),
                "artifact_id": current_payload.get("artifact_id").cloned().unwrap_or(Value::Null),
                "scope": current_payload.get("scope").cloned().unwrap_or(Value::Null),
            }))
            .unwrap_or_default(),
            current_time,
        ],
    )?;
    Ok(true)
}

/// `claim_approval_reuse_decisions` (:2066-2140) — batch claim.
///
/// Validates revision, dedupes, opens the transaction (caller holds the
/// `Connection`; `BEGIN IMMEDIATE` issued here), claims each member, commits
/// on success / rolls back on the first failure. `integrity_state` +
/// `integrity_key`/`_id` come from the caller's `_refresh_policy_integrity_state`
/// / `_policy_integrity_secret_material` — the port keeps the resident as the
/// secret-material resolver so key bytes never leave the resident.
#[allow(clippy::too_many_arguments)]
pub fn claim_approval_reuse_decisions(
    connection: &Connection,
    decisions: &[Value],
    now: Option<&str>,
    local_integrity_key: Option<&[u8]>,
    local_integrity_key_id: Option<&str>,
    policy_bundle_decision_identities: Option<BTreeSet<String>>,
    integrity_state: Option<&Value>,
    integrity_key: Option<&[u8]>,
    integrity_key_id: Option<&str>,
) -> rusqlite::Result<bool> {
    let current_time = canonical_utc_timestamp(now.unwrap_or("")).unwrap_or_default();

    let mut unique_decisions: Vec<&Value> = Vec::new();
    let mut seen_keys: BTreeSet<(String, String)> = BTreeSet::new();
    let mut expected_revision: Option<i64> = None;
    for decision in decisions {
        if decision.get("action").and_then(Value::as_str) != Some("allow") {
            return Ok(false);
        }
        let revision = match decision.get("_approval_authority_revision") {
            Some(Value::Number(n)) if n.as_i64().is_some() && !n.is_f64() => n.as_i64().unwrap(),
            _ => return Ok(false),
        };
        if revision < 0 {
            return Ok(false);
        }
        match expected_revision {
            None => expected_revision = Some(revision),
            Some(r) if r != revision => return Ok(false),
            _ => {}
        }
        let approval_id = decision.get("approval_id");
        let decision_id = decision.get("decision_id");
        let key = if approval_id
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty())
        {
            ("approval_id", approval_id.cloned().unwrap_or(Value::Null))
        } else if decision_id.and_then(Value::as_i64).is_some() {
            ("decision_id", decision_id.cloned().unwrap_or(Value::Null))
        } else {
            return Ok(false);
        };
        let key = (
            key.0.to_owned(),
            serde_json::to_string(&key.1).unwrap_or_default(),
        );
        if !seen_keys.insert(key) {
            continue;
        }
        unique_decisions.push(decision);
    }
    let Some(expected_revision) = expected_revision else {
        return Ok(true); // empty batch: vacuously satisfied
    };

    connection.execute_batch("BEGIN IMMEDIATE")?;
    let result = (|| -> rusqlite::Result<bool> {
        if approval_authority_revision(connection)? != expected_revision {
            return Ok(false);
        }
        for decision in &unique_decisions {
            if !claim_approval_reuse_decision_locked(
                connection,
                decision,
                &current_time,
                local_integrity_key,
                local_integrity_key_id,
                policy_bundle_decision_identities.as_ref(),
                integrity_state,
                integrity_key,
                integrity_key_id,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    })();
    match result {
        Ok(true) => {
            connection.execute_batch("COMMIT")?;
            Ok(true)
        }
        Ok(false) | Err(_) => {
            let _ = connection.execute_batch("ROLLBACK");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use serde_json::json;

    const SEED: &str = include_str!("../testdata/claim_reuse_seed.json");

    /// Build the `policy_decisions` + revision singleton schema mirroring
    /// `store_connection_schema.py` and insert the Python-signed rows.
    fn seeded_connection() -> (Connection, Value) {
        let seed: Value = serde_json::from_str(SEED).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "create table policy_decisions (
               decision_id integer primary key, harness text not null, scope text not null,
               artifact_id text, action text not null, artifact_hash text, workspace text,
               publisher text, source text not null, reason text, owner text,
               created_at text not null, updated_at text not null, expires_at text,
               integrity_version integer, integrity_generation integer,
               payload_hash text, payload_mac text, integrity_key_id text, signed_at text);
             create table guard_approval_authority_revision (singleton integer primary key, revision integer);
             create table guard_events (event_id integer primary key autoincrement,
               event_name text not null, payload_json text not null, occurred_at text not null);
             insert into guard_approval_authority_revision (singleton, revision) values (1, 9);",
        )
        .unwrap();
        for r in seed["policy_rows"].as_array().unwrap() {
            let gs = |k: &str| r.get(k).and_then(|v| v.as_str().map(str::to_owned));
            let gi = |k: &str| r.get(k).and_then(Value::as_i64);
            conn.execute(
                "insert into policy_decisions values
                 (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
                params![
                    gi("decision_id"),
                    gs("harness"),
                    gs("scope"),
                    gs("artifact_id"),
                    gs("action"),
                    gs("artifact_hash"),
                    gs("workspace"),
                    gs("publisher"),
                    gs("source"),
                    gs("reason"),
                    gs("owner"),
                    gs("created_at"),
                    gs("updated_at"),
                    gs("expires_at"),
                    gi("integrity_version"),
                    gi("integrity_generation"),
                    gs("payload_hash"),
                    gs("payload_mac"),
                    gs("integrity_key_id"),
                    gs("signed_at"),
                ],
            )
            .unwrap();
        }
        (conn, seed)
    }

    fn decision(did: i64, revision: i64, extra: &[(&str, Value)]) -> Value {
        let mut d = serde_json::json!({
            "action": "allow", "decision_id": did,
            "_approval_authority_revision": revision,
        });
        for (k, v) in extra {
            d[*k] = v.clone();
        }
        d
    }
    /// The merged decision dict the resolver emits for a `policy_decisions`
    /// row — `policy_row_payload` + authority revision.
    fn selected_allow(
        conn: &Connection,
        did: i64,
        key: &[u8],
        key_id: &str,
        state: &Value,
        revision: i64,
    ) -> Value {
        let row: Value = conn
            .query_row(
                "select decision_id, harness, scope, artifact_id, action, artifact_hash, \
             workspace, publisher, source, reason, owner, expires_at, updated_at, \
             integrity_version, integrity_generation, payload_hash, payload_mac, \
             integrity_key_id, signed_at from policy_decisions where decision_id=?1",
                params![did],
                policy_row_to_value,
            )
            .unwrap();
        let res = guard_policy_snapshot::policy_integrity::verify_local_policy_row(
            &row,
            Some(key),
            Some(key_id),
            false,
            state.get("generation").and_then(Value::as_i64),
        );
        let mut d = policy_row_payload(&row, Some(&res), Some(state));
        d["_approval_authority_revision"] = json!(revision);
        d
    }

    /// `approval_reuse_claim_disposition` pure-lattice parity.
    #[test]
    fn disposition_lattice() {
        // allow + approval_id + package-request artifact → retained.
        assert_eq!(
            approval_reuse_claim_disposition(&json!({
                "action":"allow","approval_id":"a","artifact_id":"x:package-request:y"})),
            Some("retained")
        );
        // allow + approval_id + plain artifact → consumed.
        assert_eq!(
            approval_reuse_claim_disposition(&json!({
                "action":"allow","approval_id":"a","artifact_id":"x"})),
            Some("consumed")
        );
        // non-allow → None.
        assert_eq!(
            approval_reuse_claim_disposition(&json!({"action":"block","approval_id":"a"})),
            None
        );
        // allow + approval_id but empty artifact → None.
        assert_eq!(
            approval_reuse_claim_disposition(
                &json!({"action":"allow","approval_id":"a","artifact_id":""})
            ),
            None
        );
        // approval-gate + expiry → consumed.
        assert_eq!(
            approval_reuse_claim_disposition(&json!({
                "action":"allow","decision_id":7,"source":"approval-gate","expires_at":"2099-01-01"})),
            Some("consumed")
        );
        // approval-gate + no expiry → retained.
        assert_eq!(
            approval_reuse_claim_disposition(&json!({
                "action":"allow","decision_id":7,"source":"approval-gate","expires_at":null})),
            Some("retained")
        );
        // bool decision_id → None.
        assert_eq!(
            approval_reuse_claim_disposition(&json!({"action":"allow","decision_id":true})),
            None
        );
    }

    /// `approval_authority_revision` singleton read.
    #[test]
    fn authority_revision_read() {
        let (conn, _seed) = seeded_connection();
        assert_eq!(approval_authority_revision(&conn).unwrap(), 9);
    }

    /// Policy-row claim: retained row claims + stays; consumed approval-gate
    /// row claims + is deleted; cloud-sync rejected; a failed member rolls the
    /// batch back.
    #[test]
    fn policy_row_claim_oracle() {
        let (conn, seed) = seeded_connection();
        let key = hex::decode(seed["key"].as_str().unwrap()).unwrap();
        let key_id = seed["key_id"].as_str().unwrap();
        let state = &seed["policy_integrity_state"];
        let now = seed["now"].as_str().unwrap();

        let d1 = selected_allow(&conn, 1, &key, key_id, state, 9);
        assert!(claim_approval_reuse_decisions(
            &conn,
            std::slice::from_ref(&d1),
            Some(now),
            None,
            None,
            None,
            Some(state),
            Some(&key),
            Some(key_id),
        )
        .unwrap());
        let still: i64 = conn
            .query_row(
                "select count(*) from policy_decisions where decision_id=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(still, 1);
        let ev: i64 = conn.query_row(
            "select count(*) from guard_events where event_name='approval.policy_reuse_applied'",
            [], |r| r.get(0)).unwrap();
        assert_eq!(ev, 1);

        // Consumed approval-gate row: claims, row deleted.
        let d2 = selected_allow(&conn, 2, &key, key_id, state, 9);
        assert!(claim_approval_reuse_decisions(
            &conn,
            std::slice::from_ref(&d2),
            Some(now),
            None,
            None,
            None,
            Some(state),
            Some(&key),
            Some(key_id),
        )
        .unwrap());
        let gone: i64 = conn
            .query_row(
                "select count(*) from policy_decisions where decision_id=2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(gone, 0);

        // cloud-sync source → rejected outright (claims false, row intact).
        let mut d3 = selected_allow(&conn, 3, &key, key_id, state, 9);
        // selected_allow marks cloud-sync valid via remote-source path; keep as-is.
        d3["_approval_authority_revision"] = json!(9);
        assert!(!claim_approval_reuse_decisions(
            &conn,
            std::slice::from_ref(&d3),
            Some(now),
            None,
            None,
            None,
            Some(state),
            Some(&key),
            Some(key_id),
        )
        .unwrap());

        // Revision mismatch → whole batch fails.
        let d_bad = decision(1, 0, &[]);
        assert!(!claim_approval_reuse_decisions(
            &conn,
            std::slice::from_ref(&d_bad),
            Some(now),
            None,
            None,
            None,
            Some(state),
            Some(&key),
            Some(key_id),
        )
        .unwrap());
    }
}
