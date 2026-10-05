//! `ClaimApprovalReuseDecisions` — resident op that claims a batch of
//! prevalidated policy/local-once reuse decisions under one SQLite
//! `BEGIN IMMEDIATE` transaction.
//!
//! IO op (unlike `ApprovalReuseDecide`): opens `store_path`, resolves
//! policy-integrity secret material + integrity state from `guard_home` via
//! `policy_integrity_resolver`, then calls
//! `claim_reuse::claim_approval_reuse_decisions`. Key bytes never cross the
//! wire — the resident derives them from the local secret store.

use std::path::PathBuf;

use guard_contracts::{
    ClaimApprovalReuseDecisionsRequestV1, ClaimApprovalReuseDecisionsResultV1,
    CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA, CLAIM_APPROVAL_REUSE_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::Value;

use super::context_digest_json::write_canonical_json_with_limit;

fn request_digest(request: &ClaimApprovalReuseDecisionsRequestV1) -> Result<String, &'static str> {
    let material =
        serde_json::to_value(request).map_err(|_| "native_claim_approval_reuse_invalid")?;
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_claim_approval_reuse_invalid")?;
    Ok(format!("sha256:{}", digest_bytes(&bytes)))
}

pub(crate) fn evaluate_claim_approval_reuse_request(
    request: &ClaimApprovalReuseDecisionsRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request).map_err(str::to_owned)?;
    let result = evaluate(request);
    let (status, code, payload) = match result {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    let result = ClaimApprovalReuseDecisionsResultV1 {
        schema: CLAIM_APPROVAL_REUSE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    };
    crate::encode_response(&result)
}

fn evaluate(request: &ClaimApprovalReuseDecisionsRequestV1) -> Result<Value, String> {
    if request.schema != CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA {
        return Err("native_claim_approval_reuse_schema_mismatch".to_owned());
    }
    // Resolve the policy-integrity secret + steady-state integrity state from
    // the guard home. `EncryptedFileSecretStore` is the portable backend; the
    // yolo/docker path defaults to it. The local_once table reuses the SAME
    // material (purpose-derived inside local_authority_integrity).
    let guard_home = PathBuf::from(&request.guard_home);
    let resolved_home = std::fs::canonicalize(&guard_home).unwrap_or_else(|_| guard_home.clone());
    let mut secret_store =
        crate::encrypted_secret_store::EncryptedFileSecretStore::new(&resolved_home);
    let (material, integrity_state) = crate::policy_integrity_resolver::resolve_integrity_state(
        &mut secret_store,
        &resolved_home,
    );
    let (local_integrity_key, local_integrity_key_id) = match material.as_ref() {
        Some(m) => (Some(m.raw_key.as_slice()), Some(m.key_id.as_str())),
        None => (None, None),
    };

    let connection = rusqlite::Connection::open(&request.store_path)
        .map_err(|_| "native_claim_approval_reuse_store_unavailable".to_owned())?;
    connection
        .busy_timeout(std::time::Duration::from_millis(5000))
        .map_err(|_| "native_claim_approval_reuse_store_unavailable".to_owned())?;

    let identities: Option<std::collections::BTreeSet<String>> = request
        .policy_bundle_decision_identities
        .as_ref()
        .map(|list| {
            list.iter()
                .map(|v| serde_json::to_string(&Value::Array(v.clone())).unwrap_or_default())
                .collect()
        });

    let claimed = crate::claim_reuse::claim_approval_reuse_decisions(
        &connection,
        &request.decisions,
        Some(request.now.as_str()),
        local_integrity_key,
        local_integrity_key_id,
        identities,
        Some(&integrity_state),
        local_integrity_key,
        local_integrity_key_id,
    )
    .map_err(|_| "native_claim_approval_reuse_store_error".to_owned())?;

    Ok(serde_json::json!({ "claimed": claimed }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    use serde_json::json;

    fn b64url(b: &[u8]) -> String {
        use base64ct::{Base64UrlUnpadded, Encoding};
        let mut buf = vec![0u8; Base64UrlUnpadded::encoded_len(b)];
        let n = Base64UrlUnpadded::encode(b, &mut buf).unwrap().len();
        buf.truncate(n);
        String::from_utf8(buf).unwrap()
    }

    const SEED: &str = include_str!("../testdata/claim_reuse_seed.json");

    fn seed_store(path: &std::path::Path) -> Value {
        let seed: Value = serde_json::from_str(SEED).unwrap();
        let conn = rusqlite::Connection::open(path).unwrap();
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
        seed
    }

    /// The merged decision dict (`policy_row_payload` + integrity fields +
    /// authority revision) the resolver emits for a selected allow.
    #[allow(dead_code)]
    fn selected_allow(conn: &rusqlite::Connection, did: i64, seed: &Value) -> Value {
        let key = hex::decode(seed["key"].as_str().unwrap()).unwrap();
        let key_id = seed["key_id"].as_str().unwrap();
        let state = &seed["policy_integrity_state"];
        let row: Value = conn
            .query_row(
                "select decision_id, harness, scope, artifact_id, action, artifact_hash, \
             workspace, publisher, source, reason, owner, expires_at, updated_at, \
             integrity_version, integrity_generation, payload_hash, payload_mac, \
             integrity_key_id, signed_at from policy_decisions where decision_id=?1",
                params![did],
                crate::claim_reuse::policy_row_to_value,
            )
            .unwrap();
        let res = guard_policy_snapshot::policy_integrity::verify_local_policy_row(
            &row,
            Some(&key),
            Some(key_id),
            false,
            state.get("generation").and_then(Value::as_i64),
        );
        let mut d = crate::claim_reuse::policy_row_payload(&row, Some(&res), Some(state));
        d["_approval_authority_revision"] = json!(9);
        d
    }

    /// End-to-end resident op: store on disk, material resolved from a real
    /// guard-home secret store, a fresh row signed under the RESOLVED key_id is
    /// claimed + emits the applied event. Proves the full chain: scoped ref →
    /// secret → key_id → sign/verify → claim.
    #[test]
    fn resident_claim_op_end_to_end() {
        let dir = std::env::temp_dir().join(format!("hg-op-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let home = dir.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let resolved_home = home.canonicalize().unwrap();
        let store_path = dir.join("guard.sqlite");
        let seed = seed_store(&store_path);
        let now = seed["now"].as_str().unwrap().to_owned();

        // Plant the policy-integrity secret under the scoped ref.
        let mut secret_store =
            crate::encrypted_secret_store::EncryptedFileSecretStore::new(&resolved_home);
        let key_ref = crate::policy_integrity_resolver::build_scoped_secret_ref(
            crate::policy_integrity_resolver::POLICY_INTEGRITY_KEY_REF,
            &resolved_home,
        );
        let control_ref = crate::policy_integrity_resolver::build_scoped_secret_ref(
            crate::policy_integrity_resolver::POLICY_INTEGRITY_CONTROL_REF,
            &resolved_home,
        );
        // The seed `key` is a human label, not 32 bytes — the op derives a real
        // 32-byte signing key; we sign under whatever material resolves.
        let raw = [7u8; 32];
        secret_store.set_secret(&key_ref, &b64url(&raw)).unwrap();
        secret_store
            .set_secret(
                &control_ref,
                &serde_json::json!({
                    "version": 1, "generation": 3,
                    "pending_generation": null, "cutover_complete": true,
                })
                .to_string(),
            )
            .unwrap();

        // Resolve the material exactly as the op does, then sign a fresh
        // local row under the resolved key_id so verify succeeds.
        let (material, _state) = crate::policy_integrity_resolver::resolve_integrity_state(
            &mut secret_store,
            &resolved_home,
        );
        let material = material.unwrap();
        let conn = rusqlite::Connection::open(&store_path).unwrap();
        let base = json!({
            "decision_id": 9,
            "harness":"codex","scope":"artifact","artifact_id":"com.hol:op",
            "action":"allow","artifact_hash":"bb".repeat(32),"workspace":"/w",
            "publisher":"hol","reason":"ok","owner":"bob","source":"local",
            "expires_at":null,"created_at":"2026-01-01T00:00:00+00:00",
            "updated_at":"2026-01-01T00:00:00+00:00",
        });
        let overlay = guard_policy_snapshot::policy_integrity::sign_local_policy_row(
            &base,
            &material.raw_key,
            &material.key_id,
            &now,
            3,
        )
        .unwrap();
        let mut signed = base.clone();
        for (k, v) in overlay.as_object().unwrap() {
            signed[k] = v.clone();
        }
        let gs = |k: &str| signed.get(k).and_then(Value::as_str).map(str::to_owned);
        conn.execute(
            "insert into policy_decisions values
             (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
            params![
                9i64,
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
                None::<String>,
                signed["integrity_version"].as_i64(),
                signed["integrity_generation"].as_i64(),
                gs("payload_hash"),
                gs("payload_mac"),
                gs("integrity_key_id"),
                gs("signed_at"),
            ],
        )
        .unwrap();
        drop(conn);

        let request = ClaimApprovalReuseDecisionsRequestV1 {
            schema: CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA.to_owned(),
            request_id: "req-claim".to_owned(),
            store_path: store_path.to_string_lossy().to_string(),
            guard_home: resolved_home.to_string_lossy().to_string(),
            decisions: vec![{
                // The claim path re-verifies the stored row against the FULL
                // emitted decision (20-key identity compare). Rebuild it the way
                // the resolver emits: policy_row_payload + integrity fields.
                let conn3 = rusqlite::Connection::open(&store_path).unwrap();
                let row: Value = conn3.query_row(
                    "select decision_id, harness, scope, artifact_id, action, artifact_hash,                      workspace, publisher, source, reason, owner, expires_at, updated_at,                      integrity_version, integrity_generation, payload_hash, payload_mac,                      integrity_key_id, signed_at from policy_decisions where decision_id=9",
                    [], crate::claim_reuse::policy_row_to_value).unwrap();
                drop(conn3);
                let res = guard_policy_snapshot::policy_integrity::verify_local_policy_row(
                    &row,
                    Some(&material.raw_key),
                    Some(&material.key_id),
                    false,
                    Some(3),
                );
                let mut d = crate::claim_reuse::policy_row_payload(&row, Some(&res), Some(&_state));
                d["_approval_authority_revision"] = json!(9);
                d
            }],
            now: now.clone(),
            policy_bundle_decision_identities: None,
        };
        let bytes = evaluate_claim_approval_reuse_request(&request).unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["status"].as_str().unwrap(), "ok");
        assert_eq!(result["code"].as_str().unwrap(), "ok");
        assert_eq!(result["request_id"].as_str().unwrap(), "req-claim");
        assert_eq!(
            result["schema"].as_str().unwrap(),
            CLAIM_APPROVAL_REUSE_RESULT_SCHEMA
        );
        assert!(result["payload"]["claimed"].as_bool().unwrap());
        // source="local", expires_at=null -> disposition "retained": the row is
        // NOT deleted (retained rows stay for re-claim); the applied event fires.
        let conn2 = rusqlite::Connection::open(&store_path).unwrap();
        let remaining: i64 = conn2
            .query_row(
                "select count(*) from policy_decisions where decision_id=9",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 1, "retained decision row remains");
        let events: i64 = conn2
            .query_row("select count(*) from guard_events where event_name='approval.policy_reuse_applied'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(events, 1, "applied event recorded");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Schema mismatch → error envelope, no panic.
    #[test]
    fn schema_mismatch_rejects() {
        let request = ClaimApprovalReuseDecisionsRequestV1 {
            schema: "wrong".to_owned(),
            request_id: String::new(),
            store_path: String::new(),
            guard_home: String::new(),
            decisions: vec![],
            now: String::new(),
            policy_bundle_decision_identities: None,
        };
        let bytes = evaluate_claim_approval_reuse_request(&request).unwrap();
        let result: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(result["status"].as_str().unwrap(), "error");
        assert_eq!(
            result["code"].as_str().unwrap(),
            "native_claim_approval_reuse_schema_mismatch"
        );
    }
}
