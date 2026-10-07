//! `store_event_receipts.py` `StoreEventReceiptsMixin` local-once claim paths
//! ported to `rusqlite`. The caller supplies an open `Connection`; the
//! public `claim_local_once_approval` wrapper owns `BEGIN IMMEDIATE`.
//!
//! SQL text is byte-identical to the Python source — same column lists, same
//! `julianday(expires_at) > julianday(?)` filters (see `utc_timestamp` for
//! the JDN parity semantics), same `rowcount == 1` consume guard.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use guard_contracts::timestamp_has_expired;
use guard_policy_snapshot::local_authority_integrity::{
    sign_local_authority_payload, verify_local_authority_payload,
};

pub const LOCAL_ONCE_INTEGRITY_PURPOSE: &str = "guard-local-once-approval";

/// `_local_once_approval_is_reusable` (:28-29).
pub(crate) fn local_once_approval_is_reusable(artifact_id: &str) -> bool {
    artifact_id.contains(":package-request:")
}

/// `_workspace_policy_key` (`store_base.py:1371-1376`); callers that pass a
/// raw workspace path get the stored `guard-workspace-policy:<sha256>` form.
#[allow(dead_code)]
pub fn workspace_policy_key(workspace: &str) -> Option<String> {
    let trimmed = workspace.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = normalized_workspace_path(trimmed);
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut hasher, normalized.as_bytes());
    let digest = sha2::Digest::finalize(hasher);
    Some(format!("guard-workspace-policy:{}", hex::encode(digest)))
}

#[allow(dead_code)]
fn normalized_workspace_path(workspace: &str) -> String {
    // `_normalized_workspace_path` resolves the path; preserve the Python
    // "trailing-slash stripped absolute" contract minimally here.
    workspace.trim_end_matches('/').to_owned()
}

/// `_row_value` — `NULL` → `Value::Null`.
fn row_value(row: &Value, key: &str) -> Value {
    row.get(key).cloned().unwrap_or(Value::Null)
}

/// `_local_once_approval_signed_payload` (:385-396) — the 11 signed columns.
fn local_once_approval_signed_payload(row: &Value) -> Value {
    serde_json::json!({
        "approval_id": row_value(row, "approval_id"),
        "request_id": row_value(row, "request_id"),
        "harness": row_value(row, "harness"),
        "artifact_id": row_value(row, "artifact_id"),
        "artifact_hash": row_value(row, "artifact_hash"),
        "workspace": row_value(row, "workspace"),
        "publisher": row_value(row, "publisher"),
        "action": row_value(row, "action"),
        "created_at": row_value(row, "created_at"),
        "expires_at": row_value(row, "expires_at"),
        "claimed_at": row_value(row, "claimed_at"),
    })
}

/// `_local_once_approval_integrity` (:398-405).
fn local_once_approval_integrity(row: &Value) -> Value {
    serde_json::json!({
        "integrity_version": row_value(row, "integrity_version"),
        "payload_hash": row_value(row, "payload_hash"),
        "payload_mac": row_value(row, "payload_mac"),
        "integrity_key_id": row_value(row, "integrity_key_id"),
        "signed_at": row_value(row, "signed_at"),
    })
}

/// `_verify_local_once_approval` (:411-424).
fn verify_local_once_approval<'a>(
    row: &Value,
    key: Option<&'a [u8]>,
    key_id: Option<&'a str>,
) -> guard_policy_snapshot::local_authority_integrity::LocalAuthorityVerification {
    verify_local_authority_payload(
        &local_once_approval_signed_payload(row),
        &local_once_approval_integrity(row),
        key,
        key_id,
        LOCAL_ONCE_INTEGRITY_PURPOSE,
    )
}

/// `_local_once_approval_integrity_failure` (:426-441).
#[allow(dead_code)]
fn local_once_approval_integrity_failure(
    row: &Value,
    result: &guard_policy_snapshot::local_authority_integrity::LocalAuthorityVerification,
) -> Value {
    let mut failure = serde_json::json!({
        "action": row_value(row, "action"),
        "approval_id": row_value(row, "approval_id"),
        "harness": row_value(row, "harness"),
        "integrity_status": result.status,
        "integrity_message": result.message,
        "integrity_payload_hash": result.payload_hash,
        "integrity_key_id": result.key_id,
        "publisher": row_value(row, "publisher"),
        "request_id": row_value(row, "request_id"),
        "source": "approval-gate-once",
        "workspace": row_value(row, "workspace"),
    });
    if let Some(integrity_version) = row_value(row, "integrity_version").as_i64() {
        failure["integrity_version"] = Value::from(integrity_version);
    }
    failure
}

/// `_local_once_approval_payload` (:443-467) — the decision dict surfaced to
/// callers.
fn local_once_approval_payload(row: &Value) -> Value {
    serde_json::json!({
        "action": row_value(row, "action"),
        "approval_id": row_value(row, "approval_id"),
        "artifact_hash": row_value(row, "artifact_hash"),
        "artifact_id": row_value(row, "artifact_id"),
        "decision_id": Value::Null,
        "expires_at": row_value(row, "expires_at"),
        "harness": row_value(row, "harness"),
        "integrity_key_id": row_value(row, "integrity_key_id"),
        "integrity_status": "valid",
        "integrity_version": row_value(row, "integrity_version"),
        "owner": Value::Null,
        "publisher": row_value(row, "publisher"),
        "reason": "approved once in review",
        "request_id": row_value(row, "request_id"),
        "scope": "artifact",
        "source": "approval-gate-once",
        "signed_at": row_value(row, "signed_at"),
        "updated_at": row_value(row, "created_at"),
        "workspace": row_value(row, "workspace"),
    })
}

/// The 15 `identity_keys` gate fields (:169-185).
const IDENTITY_KEYS: [&str; 15] = [
    "action",
    "approval_id",
    "artifact_hash",
    "artifact_id",
    "expires_at",
    "harness",
    "integrity_key_id",
    "integrity_status",
    "integrity_version",
    "publisher",
    "request_id",
    "source",
    "signed_at",
    "updated_at",
    "workspace",
];

/// Column list shared by the claim SELECT and the lookup SELECT.
const CLAIM_COLUMNS: &str = "approval_id, request_id, harness, artifact_id, artifact_hash, \
     workspace, publisher, action, created_at, expires_at, claimed_at, \
     integrity_version, payload_hash, payload_mac, integrity_key_id, signed_at";

/// Convert a `rusqlite::Row` into the `Value` object the helpers consume.
/// Column order must match `CLAIM_COLUMNS`.
pub(crate) fn row_to_value(row: &rusqlite::Row) -> rusqlite::Result<Value> {
    let get = |i: usize| -> rusqlite::Result<Value> {
        let v: Option<Value> = row.get::<_, Option<String>>(i)?.map(Value::String);
        Ok(v.unwrap_or(Value::Null))
    };
    // Column order per CLAIM_COLUMNS.
    Ok(serde_json::json!({
        "approval_id": get(0)?,
        "request_id": get(1)?,
        "harness": get(2)?,
        "artifact_id": get(3)?,
        "artifact_hash": get(4)?,
        "workspace": get(5)?,
        "publisher": get(6)?,
        "action": get(7)?,
        "created_at": get(8)?,
        "expires_at": get(9)?,
        "claimed_at": get(10)?,
        "integrity_version": row.get::<_, Option<i64>>(11)?.map(Value::from).unwrap_or(Value::Null),
        "payload_hash": get(12)?,
        "payload_mac": get(13)?,
        "integrity_key_id": get(14)?,
        "signed_at": get(15)?,
    }))
}

/// `_claim_local_once_approval_by_id_locked` (:137-217).
///
/// `now` must already be `_canonical_utc_timestamp`-normalized by the caller.
/// `consume=false` performs the non-destructive peek-by-id.
#[allow(clippy::too_many_arguments)]
pub fn claim_local_once_approval_by_id_locked(
    connection: &Connection,
    approval_id: &str,
    now: &str,
    expected_decision: Option<&Value>,
    integrity_key: Option<&[u8]>,
    integrity_key_id: Option<&str>,
    consume: bool,
) -> rusqlite::Result<Option<Value>> {
    let sql = format!(
        "select {CLAIM_COLUMNS} from guard_local_once_approvals \
         where approval_id = ?1 and claimed_at is null \
           and julianday(expires_at) > julianday(?2)"
    );
    let row = connection
        .query_row(&sql, params![approval_id, now], row_to_value)
        .optional()?;
    let row = match row {
        Some(r) => r,
        None => return Ok(None),
    };
    // `julianday` NULL (malformed expires_at) already filtered the row; belt-
    // and-suspenders re-check keeps the port honest if the SELECT list ever
    // drifts to include a claimed/expired row.
    if timestamp_has_expired(row_value(&row, "expires_at").as_str().unwrap_or(""), now) {
        return Ok(None);
    }
    let integrity_result = verify_local_once_approval(&row, integrity_key, integrity_key_id);
    if integrity_result.status != "valid" || integrity_key.is_none() || integrity_key_id.is_none() {
        return Ok(None);
    }
    let decision = local_once_approval_payload(&row);
    if let Some(expected) = expected_decision {
        if IDENTITY_KEYS
            .iter()
            .any(|key| decision.get(*key) != expected.get(*key))
        {
            return Ok(None);
        }
    }
    if !consume {
        return Ok(Some(decision));
    }
    let mut claimed_row = local_once_approval_signed_payload(&row);
    claimed_row["claimed_at"] = Value::String(now.to_owned());
    let claimed_integrity = match sign_local_authority_payload(
        &claimed_row,
        integrity_key.unwrap(),
        integrity_key_id.unwrap(),
        LOCAL_ONCE_INTEGRITY_PURPOSE,
        now,
    ) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };
    let changed = connection.execute(
        "update guard_local_once_approvals \
         set claimed_at = ?1, integrity_version = ?2, payload_hash = ?3, \
             payload_mac = ?4, integrity_key_id = ?5, signed_at = ?6 \
         where approval_id = ?7 and claimed_at is null",
        params![
            now,
            claimed_integrity.integrity_version,
            claimed_integrity.payload_hash,
            claimed_integrity.payload_mac,
            claimed_integrity.integrity_key_id,
            claimed_integrity.signed_at,
            approval_id,
        ],
    )?;
    if changed != 1 {
        return Ok(None);
    }
    Ok(Some(decision))
}

/// `_peek_local_once_approval_lookup_locked` (:74-109).
///
/// Returns `(decision, integrity_failure)`; at most one is `Some`. The
/// `artist` SELECT order is byte-identical to Python (`order by created_at
/// desc, approval_id desc, limit 1`).
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn peek_local_once_approval_lookup_locked(
    connection: &Connection,
    harness: &str,
    artifact_id: Option<&str>,
    artifact_hash: Option<&str>,
    workspace: Option<&str>,
    publisher: Option<&str>,
    now: &str,
    integrity_key: Option<&[u8]>,
    integrity_key_id: Option<&str>,
) -> rusqlite::Result<(Option<Value>, Option<Value>)> {
    let now = guard_contracts::canonical_utc_timestamp(now).unwrap_or_else(|| now.to_owned());
    let artist = artifact_id.map(str::to_owned);
    let artist_hash = artifact_hash.map(str::to_owned);
    let ws_key = workspace.and_then(workspace_policy_key);

    let run_query = |artifact_col: &str,
                     artifact_val: Option<&str>,
                     publisher_filter: Option<&str>|
     -> rusqlite::Result<Option<Value>> {
        let artifact_val = match artifact_val {
            Some(v) => v,
            None => return Ok(None),
        };
        let sql = format!(
            "select {CLAIM_COLUMNS} from guard_local_once_approvals \
             where claimed_at is null and harness = ?1 and {artifact_col} = ?2 \
               and julianday(expires_at) > julianday(?3){} \
             order by created_at desc, approval_id desc limit 1",
            publisher_filter.unwrap_or(""),
        );
        let mut stmt = connection.prepare(&sql)?;
        let row = match publisher {
            Some(p) => stmt
                .query_row(params![harness, artifact_val, now, p], row_to_value)
                .optional(),
            None => stmt
                .query_row(params![harness, artifact_val, now], row_to_value)
                .optional(),
        }?;
        Ok(row)
    };

    // artifact_id then artifact_hash (two passes), then workspace-key hash.
    for (col, val) in [
        ("artifact_id", artist.as_deref()),
        ("artifact_hash", artist_hash.as_deref()),
        ("artifact_hash", ws_key.as_deref()),
    ] {
        if val.is_none() {
            continue;
        }
        let row = run_query(
            col,
            val,
            if publisher.is_some() {
                Some(" and publisher = ?4")
            } else {
                None
            },
        )?;
        let Some(row) = row else { continue };
        let integrity_result = verify_local_once_approval(&row, integrity_key, integrity_key_id);
        if integrity_result.status == "valid" {
            return Ok((Some(local_once_approval_payload(&row)), None));
        }
        return Ok((
            None,
            Some(local_once_approval_integrity_failure(
                &row,
                &integrity_result,
            )),
        ));
    }
    Ok((None, None))
}

/// `_peek_local_once_approval_locked` (:110-134).
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn peek_local_once_approval_locked(
    connection: &Connection,
    harness: &str,
    artifact_id: Option<&str>,
    artifact_hash: Option<&str>,
    workspace: Option<&str>,
    publisher: Option<&str>,
    now: &str,
    integrity_key: Option<&[u8]>,
    integrity_key_id: Option<&str>,
) -> rusqlite::Result<Option<Value>> {
    Ok(peek_local_once_approval_lookup_locked(
        connection,
        harness,
        artifact_id,
        artifact_hash,
        workspace,
        publisher,
        now,
        integrity_key,
        integrity_key_id,
    )?
    .0)
}

/// `_claim_local_once_approval_locked` (:219-256) — legacy replay path.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn claim_local_once_approval_locked(
    connection: &Connection,
    harness: &str,
    artifact_id: Option<&str>,
    artifact_hash: Option<&str>,
    workspace: Option<&str>,
    publisher: Option<&str>,
    now: &str,
    integrity_key: Option<&[u8]>,
    integrity_key_id: Option<&str>,
) -> rusqlite::Result<Option<Value>> {
    let decision = peek_local_once_approval_locked(
        connection,
        harness,
        artifact_id,
        artifact_hash,
        workspace,
        publisher,
        now,
        integrity_key,
        integrity_key_id,
    )?;
    let Some(decision) = decision else {
        return Ok(None);
    };
    if let Some(decision_artifact_id) = decision.get("artifact_id").and_then(Value::as_str) {
        if local_once_approval_is_reusable(decision_artifact_id) {
            return Ok(Some(decision));
        }
    }
    claim_local_once_approval_by_id_locked(
        connection,
        decision
            .get("approval_id")
            .and_then(Value::as_str)
            .unwrap_or(""),
        now,
        None,
        integrity_key,
        integrity_key_id,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    const SEED: &str = include_str!("../testdata/local_once_claim_seed.json");

    fn seeded_connection() -> (Connection, Value) {
        let seed: Value = serde_json::from_str(SEED).unwrap();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "create table guard_local_once_approvals (
               approval_id text primary key, request_id text not null, harness text not null,
               artifact_id text not null, artifact_hash text not null, workspace text,
               publisher text, action text not null, created_at text not null,
               expires_at text not null, claimed_at text,
               integrity_version integer, payload_hash text, payload_mac text,
               integrity_key_id text, signed_at text);
             create table guard_events (event_id integer primary key autoincrement,
               event_name text not null, payload_json text not null, occurred_at text not null);",
        )
        .unwrap();
        for row in seed["seeded"].as_array().unwrap() {
            let gs = |k: &str| -> Option<String> {
                row.get(k).and_then(|v| v.as_str().map(str::to_owned))
            };
            let gi = |k: &str| -> Option<i64> { row.get(k).and_then(|v| v.as_i64()) };
            conn.execute(
                "insert into guard_local_once_approvals values
                 (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
                params![
                    gs("approval_id"),
                    gs("request_id"),
                    gs("harness"),
                    gs("artifact_id"),
                    gs("artifact_hash"),
                    gs("workspace"),
                    gs("publisher"),
                    gs("action"),
                    gs("created_at"),
                    gs("expires_at"),
                    gs("claimed_at"),
                    gi("integrity_version"),
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

    /// Byte-parity with `_claim_local_once_approval_by_id_locked`: a-1 claims
    /// (decision populated, claimed_at=now, integrity re-signed), a-2 expired→
    /// None, a-3 already-claimed→None.
    #[test]
    fn claim_local_once_python_oracle() {
        let (conn, seed) = seeded_connection();
        let key = hex::decode(seed["key"].as_str().unwrap()).unwrap();
        let key_id = seed["key_id"].as_str().unwrap();
        let now = seed["now"].as_str().unwrap();

        // a-1: valid unclaimed → decision + consume.
        let decision = claim_local_once_approval_by_id_locked(
            &conn,
            "a-1",
            now,
            None,
            Some(&key),
            Some(key_id),
            true,
        )
        .unwrap()
        .expect("a-1 claim");
        assert_eq!(decision["action"].as_str().unwrap(), "allow");
        assert_eq!(decision["approval_id"].as_str().unwrap(), "a-1");
        assert_eq!(decision["source"].as_str().unwrap(), "approval-gate-once");
        assert_eq!(decision["integrity_status"].as_str().unwrap(), "valid");
        assert_eq!(decision["request_id"].as_str().unwrap(), "req-a-1");

        // Post-claim row: claimed_at=now, integrity re-signed.
        let sql = "select approval_id, request_id, harness, artifact_id, artifact_hash,              workspace, publisher, action, created_at, expires_at, claimed_at,              integrity_version, payload_hash, payload_mac, integrity_key_id, signed_at              from guard_local_once_approvals where approval_id='a-1'";
        let row = conn.query_row(sql, [], row_to_value).unwrap();
        assert_eq!(row["claimed_at"].as_str().unwrap(), now);
        assert_ne!(row["claimed_at"], Value::Null);
        // signed_at on the re-sign equals `now`.
        assert_eq!(row["signed_at"].as_str().unwrap(), now);

        // a-2: expired (julianday filter) → None.
        assert!(claim_local_once_approval_by_id_locked(
            &conn,
            "a-2",
            now,
            None,
            Some(&key),
            Some(key_id),
            true
        )
        .unwrap()
        .is_none());
        // a-3: already claimed → None.
        assert!(claim_local_once_approval_by_id_locked(
            &conn,
            "a-3",
            now,
            None,
            Some(&key),
            Some(key_id),
            true
        )
        .unwrap()
        .is_none());
    }

    /// `expected_decision` gate: matching → claim; any of the 15 identity
    /// fields differing → None (no consume).
    #[test]
    fn claim_expected_decision_gate() {
        let (conn, seed) = seeded_connection();
        let key = hex::decode(seed["key"].as_str().unwrap()).unwrap();
        let key_id = seed["key_id"].as_str().unwrap();
        let now = seed["now"].as_str().unwrap();

        // Peek (consume=false) to obtain the decision shape, then claim-by-id
        // with it as expected_decision.
        let peek = claim_local_once_approval_by_id_locked(
            &conn,
            "a-1",
            now,
            None,
            Some(&key),
            Some(key_id),
            false,
        )
        .unwrap()
        .expect("peek");
        // matching expected → claim succeeds.
        let claimed = claim_local_once_approval_by_id_locked(
            &conn,
            "a-1",
            now,
            Some(&peek),
            Some(&key),
            Some(key_id),
            true,
        )
        .unwrap();
        assert!(claimed.is_some());

        // Re-seed a-1 (unclaim) and test a mismatching expected action → None.
        conn.execute("update guard_local_once_approvals set claimed_at=null                       where approval_id='a-1'", []).unwrap();
        let mut bad = peek.clone();
        bad["action"] = Value::String("block".into());
        assert!(claim_local_once_approval_by_id_locked(
            &conn,
            "a-1",
            now,
            Some(&bad),
            Some(&key),
            Some(key_id),
            true
        )
        .unwrap()
        .is_none());
    }

    /// Wrong integrity key → None (verify fails before consume).
    #[test]
    fn claim_rejects_wrong_integrity_key() {
        let (conn, seed) = seeded_connection();
        let wrong = [b'X'; 32];
        let key_id = seed["key_id"].as_str().unwrap();
        let now = seed["now"].as_str().unwrap();
        assert!(claim_local_once_approval_by_id_locked(
            &conn,
            "a-1",
            now,
            None,
            Some(&wrong),
            Some(key_id),
            true
        )
        .unwrap()
        .is_none());
        // Missing key → None.
        assert!(
            claim_local_once_approval_by_id_locked(&conn, "a-1", now, None, None, None, true)
                .unwrap()
                .is_none()
        );
    }
}
