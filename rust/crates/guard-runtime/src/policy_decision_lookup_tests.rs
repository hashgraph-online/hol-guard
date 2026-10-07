use super::*;
use std::path::PathBuf;

fn tmp_store(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hg-pdl-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("guard.db")
}

/// Minimal `guard.db` schema matching the columns the op selects/inserts.
fn seed_store(path: &std::path::Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch(
        "create table policy_decisions (
           decision_id integer primary key, harness text not null, scope text not null,
           artifact_id text, action text not null, artifact_hash text, workspace text,
           publisher text, source text not null, reason text, owner text,
           created_at text not null, updated_at text not null, expires_at text,
           integrity_version integer, integrity_generation integer,
           payload_hash text, payload_mac text, integrity_key_id text, signed_at text);
         create table guard_approval_authority_revision (singleton integer primary key, revision integer);
         create table guard_local_once_approvals (
           approval_id text primary key, request_id text, harness text, artifact_id text,
           artifact_hash text, workspace text, publisher text, action text, created_at text,
           expires_at text, claimed_at text, integrity_version integer, payload_hash text,
           payload_mac text, integrity_key_id text, signed_at text, authority_kind text);
         create table guard_events (event_id integer primary key autoincrement,
           event_name text not null, payload_json text not null, occurred_at text not null);
         create index idx_policy_decisions_lookup_artifact
           on policy_decisions (artifact_id, harness, artifact_hash, updated_at desc, decision_id desc)
           where scope = 'artifact';
         create index idx_policy_decisions_lookup_workspace
           on policy_decisions (workspace, harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
           where scope = 'workspace';
         create index idx_policy_decisions_lookup_publisher
           on policy_decisions (publisher, harness, artifact_hash, updated_at desc, decision_id desc)
           where scope = 'publisher';
         create index idx_policy_decisions_lookup_publisher_legacy
           on policy_decisions (publisher, harness, artifact_hash, updated_at desc, decision_id desc)
           where scope = 'publisher' and artifact_hash is not null
             and artifact_hash not like 'guard-approval-context:v1:%';
         create index idx_policy_decisions_lookup_harness
           on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
           where scope = 'harness';
         create index idx_policy_decisions_lookup_harness_legacy
           on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
           where scope = 'harness' and artifact_hash is not null
             and artifact_hash not like 'guard-approval-context:v1:%';
         create index idx_policy_decisions_lookup_global
           on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
           where scope = 'global';
         create index idx_policy_decisions_lookup_global_legacy
           on policy_decisions (harness, artifact_id, artifact_hash, updated_at desc, decision_id desc)
           where scope = 'global' and artifact_hash is not null
             and artifact_hash not like 'guard-approval-context:v1:%';
         insert into guard_approval_authority_revision (singleton, revision) values (1, 5);",
    )
    .unwrap();
}

fn base_request(store_path: &std::path::Path) -> PolicyDecisionLookupRequestV1 {
    PolicyDecisionLookupRequestV1 {
        schema: POLICY_DECISION_LOOKUP_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        store_path: store_path.to_string_lossy().into_owned(),
        guard_home: "/tmp/gh".to_owned(),
        harness: "codex".to_owned(),
        artifact_id: Some("npm:lodash".to_owned()),
        artifact_hash: Some("sha256:abc".to_owned()),
        workspace: None,
        publisher: None,
        now: "2030-01-01T00:00:00+00:00".to_owned(),
        runtime_exact_match_context: None,
        consume_one_shot: true,
        // Matches `_refresh_policy_integrity_state` output shape (backend set).
        integrity_state: Some(json!({
            "backend": "encrypted-file",
            "mode": "protected",
            "generation": 1,
            "enforcement": "enforce",
            "degraded_reasons": [],
        })),
        integrity_key_b64: None,
        integrity_key_id: None,
        local_once_integrity_key_b64: None,
        local_once_integrity_key_id: None,
        policy_bundle_decision_identities: None,
    }
}

/// No matching rows → decision null, no local-integrity, result `ok`.
#[test]
fn empty_store_returns_null_decision() {
    let store = tmp_store("empty");
    seed_store(&store);
    let req = base_request(&store);
    let bytes = evaluate_policy_decision_lookup_request(&req).unwrap();
    let result: PolicyDecisionLookupResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    let payload = result.payload.unwrap();
    assert_eq!(payload["decision"], Value::Null);
    assert_eq!(payload["ignored_local_integrity"], Value::Null);
}

/// Schema mismatch → error result, no panic.
#[test]
fn schema_mismatch_is_terminal_error() {
    let store = tmp_store("schema");
    seed_store(&store);
    let mut req = base_request(&store);
    req.schema = "wrong.v0".to_owned();
    let bytes = evaluate_policy_decision_lookup_request(&req).unwrap();
    let result: PolicyDecisionLookupResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.status, "error");
    assert_eq!(result.code, "native_policy_decision_lookup_schema_mismatch");
    assert!(result.payload.is_none());
}

/// A valid remote row short-circuits integrity (`valid`) and wins selection.
#[test]
fn remote_row_is_selected() {
    let store = tmp_store("remote");
    seed_store(&store);
    {
        let conn = Connection::open(&store).unwrap();
        conn.execute(
            "insert into policy_decisions values
             (1,'codex','artifact','npm:lodash','block','sha256:abc',NULL,NULL,
              'cloud-signed-memory','policy block',NULL,'2029-01-01T00:00:00+00:00','2030-01-01T00:00:00+00:00',
              '2031-01-01T00:00:00+00:00',1,NULL,'h','m','k','s')",
            [],
        )
        .unwrap();
    }
    let req = base_request(&store);
    let bytes = evaluate_policy_decision_lookup_request(&req).unwrap();
    let result: PolicyDecisionLookupResultV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result.status, "ok");
    let payload = result.payload.unwrap();
    let decision = &payload["decision"];
    assert_eq!(decision["decision_id"], json!(1));
    assert_eq!(decision["action"], json!("block"));
    // Remote rows omit local-integrity fields (Python parity).
    assert_eq!(decision["integrity_status"], Value::Null);
    // `trust_status` = Python `TrustStatus.from_policy_integrity_state(state)`
    // for `{backend:"encrypted-file", mode:"protected", degraded_reasons:[]}`.
    // Matches the baseline harness TRUST output byte-for-byte.
    assert_eq!(
        payload["trust_status"],
        json!({
            "runtime_protection": "protected",
            "remembered_rules": "enforced",
            "cloud_policies": "available",
            "backend": "encrypted-file",
            "degraded_reasons": [],
            "degraded_reason_labels": {},
            "setup_available": false,
            "last_proof": null,
        })
    );
    assert_eq!(payload["ignored_local_integrity"], Value::Null);
    // Remote one-shot consume emits `policy.cloud.applied` with the row identity.
    {
        let conn = Connection::open(&store).unwrap();
        let event: String = conn
            .query_row(
                "select payload_json from guard_events where event_name='policy.cloud.applied'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let event: Value = serde_json::from_str(&event).unwrap();
        assert_eq!(event["decision_id"], json!(1));
        assert_eq!(event["source"], json!("cloud-signed-memory"));
    }
}

#[test]
fn trust_status_matches_python_derivation() {
    // protected mode → protected/enforced, no setup → cloud_policies "available"
    // (Python default when setup_available is false).
    let ts = trust_status_from_state(&json!({"mode": "protected", "generation": 1}));
    assert_eq!(ts["runtime_protection"], json!("protected"));
    assert_eq!(ts["remembered_rules"], json!("enforced"));
    assert_eq!(ts["cloud_policies"], json!("available"));

    // degraded mode + known reason → labels map + setup_available promoted.
    let ts = trust_status_from_state(&json!({
        "mode": "degraded",
        "degraded_reasons": ["guard_db_permissions"],
        "backend": "encrypted-file",
    }));
    assert_eq!(ts["runtime_protection"], json!("degraded"));
    assert_eq!(ts["remembered_rules"], json!("disabled_degraded"));
    // Known reason promotes setup_available (Python `any(reason in LABELS)`).
    assert_eq!(ts["setup_available"], json!(true));
    assert_eq!(ts["cloud_policies"], json!("setup_unavailable"));
    assert_eq!(
        ts["degraded_reason_labels"]["guard_db_permissions"],
        json!("Guard database permissions are too broad")
    );
    assert_eq!(ts["backend"], json!("encrypted-file"));

    // Explicit overrides win; unknown reasons → generic label; absent mode →
    // unknown/unknown; empty backend → "unknown".
    let ts = trust_status_from_state(&json!({
        "mode": "degraded",
        "runtime_protection": "unknown",
        "remembered_rules": "enforced",
        "cloud_policies": "unknown",
        "setup_available": true,
        "backend": "",
        "degraded_reasons": ["nonstandard_reason"],
    }));
    assert_eq!(ts["runtime_protection"], json!("unknown"));
    assert_eq!(ts["remembered_rules"], json!("enforced"));
    assert_eq!(ts["cloud_policies"], json!("unknown"));
    assert_eq!(ts["backend"], json!("unknown"));
    assert_eq!(
        ts["degraded_reason_labels"]["nonstandard_reason"],
        json!("Guard trust check degraded")
    );
}

fn seed_one_shot(tag: &str) -> (PathBuf, PolicyDecisionLookupRequestV1) {
    let store = tmp_store(tag);
    seed_store(&store);
    let conn = Connection::open(&store).unwrap();
    conn.execute(
        "insert into policy_decisions
         (decision_id,harness,scope,artifact_id,action,artifact_hash,source,created_at,updated_at,expires_at)
         values (1,'codex','artifact','npm:lodash','allow','sha256:abc','approval-gate',
                 '2029-01-01T00:00:00+00:00','2029-01-01T00:00:00+00:00','2031-01-01T00:00:00+00:00')",
        [],
    ).unwrap();
    let row = conn
        .query_row(
            &format!("select {POLICY_LOOKUP_COLUMNS} from policy_decisions where decision_id = 1"),
            [],
            policy_row_to_json,
        )
        .unwrap();
    let key = [7u8; 32];
    let signed = guard_policy_snapshot::policy_integrity::sign_local_policy_row(
        &row,
        &key,
        "test-policy-key",
        "2029-01-01T00:00:00+00:00",
        1,
    )
    .unwrap();
    conn.execute(
        "update policy_decisions set integrity_version=?1, integrity_generation=?2,
         payload_hash=?3, payload_mac=?4, integrity_key_id=?5, signed_at=?6 where decision_id=1",
        params![
            signed["integrity_version"].as_i64(),
            signed["integrity_generation"].as_i64(),
            signed["payload_hash"].as_str(),
            signed["payload_mac"].as_str(),
            signed["integrity_key_id"].as_str(),
            signed["signed_at"].as_str()
        ],
    )
    .unwrap();
    let mut request = base_request(&store);
    request.integrity_key_b64 = Some("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".to_owned());
    request.integrity_key_id = Some("test-policy-key".to_owned());
    (store, request)
}

#[test]
fn consuming_one_shot_is_atomic_across_connections() {
    let (store, request) = seed_one_shot("concurrent-consume");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let request = request.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                evaluate(&request).unwrap()
            })
        })
        .collect();
    let decisions: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(
        decisions
            .iter()
            .filter(|r| r["decision"]["action"] == "allow")
            .count(),
        1
    );
    let conn = Connection::open(store).unwrap();
    let remaining: i64 = conn
        .query_row("select count(*) from policy_decisions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(remaining, 0);
}

#[test]
fn zero_row_delete_cannot_authorize_a_one_shot() {
    let (store, request) = seed_one_shot("zero-delete");
    let conn = Connection::open(&store).unwrap();
    conn.execute_batch(
        "create trigger prevent_delete before delete on policy_decisions
                        begin select raise(ignore); end;",
    )
    .unwrap();
    let result = evaluate(&request).unwrap();
    assert!(result["decision"].is_null());
    let remaining: i64 = conn
        .query_row("select count(*) from policy_decisions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(remaining, 1);
}

#[test]
fn audit_failure_rolls_back_one_shot_consumption() {
    let (store, request) = seed_one_shot("audit-rollback");
    let conn = Connection::open(&store).unwrap();
    // A malformed local-once candidate requires an integrity audit event
    // while the separate approval-gate row has a valid native signature.
    conn.execute_batch(
        "insert into guard_local_once_approvals
         (approval_id,request_id,harness,artifact_id,artifact_hash,action,created_at,expires_at,authority_kind)
         values ('invalid','request','codex','npm:lodash','sha256:abc','allow',
                 '2029-01-01T00:00:00+00:00','2031-01-01T00:00:00+00:00','legacy');
         create trigger reject_audit before insert on guard_events
         begin select raise(abort, 'audit unavailable'); end;"
    ).unwrap();
    assert_eq!(
        evaluate(&request).unwrap_err(),
        "native_policy_decision_lookup_write_failed"
    );
    let remaining: i64 = conn
        .query_row("select count(*) from policy_decisions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(remaining, 1);
    conn.execute_batch("drop trigger reject_audit;").unwrap();
    assert_eq!(evaluate(&request).unwrap()["decision"]["action"], "allow");
    let events: i64 = conn
        .query_row("select count(*) from guard_events", [], |r| r.get(0))
        .unwrap();
    assert!(events > 0);
}

#[test]
fn consuming_harness_lookup_includes_exact_artifact_blocks() {
    let store = tmp_store("harness-exact");
    seed_store(&store);
    let conn = Connection::open(&store).unwrap();
    conn.execute(
        "insert into policy_decisions
         (decision_id,harness,scope,artifact_id,action,source,created_at,updated_at)
         values (1,'codex','harness','npm:lodash','block','cloud-signed-memory',
                 '2029-01-01T00:00:00+00:00','2029-01-01T00:00:00+00:00')",
        [],
    )
    .unwrap();
    let result = evaluate(&base_request(&store)).unwrap();
    assert_eq!(result["decision"]["decision_id"], 1);
    assert_eq!(result["decision"]["action"], "block");
}

/// `artifact_family_key` uses the third segment of `harness:scope:family:…`.
/// Regression: the native port read `parts[1]` (the scope) so `family:mcp`
/// rows never resolved a concrete `codex:project:mcp:*` lookup.
#[test]
fn scoped_artifact_family_uses_third_segment() {
    assert_eq!(
        artifact_family_key(Some("codex:project:mcp:safe-read")).as_deref(),
        Some("family:mcp")
    );
    assert_eq!(
        artifact_family_key(Some("family:mcp")).as_deref(),
        Some("family:mcp")
    );
    // Not an approval family → no family key (never shadows a `family:*` row).
    assert_eq!(artifact_family_key(Some("codex:project:other:op")), None);
    // `mcp` is approval-scoped but not runtime-exact → no exact-match key, so a
    // `family:mcp` row stays eligible for a concrete `*:mcp:*` lookup.
    assert_eq!(
        runtime_scoped_exact_match_key(Some("codex:project:mcp:safe-read"), None),
        None
    );
    assert_ne!(
        runtime_scoped_exact_match_key(Some("codex:project:tool-action:run"), None),
        None
    );
}

/// A `family:mcp` row must remain eligible for `codex:project:mcp:safe-read`
/// (no exact-match requirement when the family isn't runtime-exact).
#[test]
fn family_scoped_row_is_eligible_for_concrete_lookup() {
    let row = json!({
        "decision_id": 1, "harness": "codex", "scope": "harness",
        "artifact_id": "family:mcp", "artifact_hash": Value::Null,
        "action": "allow", "source": "policy-yaml-import",
    });
    assert!(runtime_policy_row_is_eligible(
        &row,
        &[],
        Some("codex:project:mcp:safe-read"),
        None,
        None,
        None,
        None
    ));
}
