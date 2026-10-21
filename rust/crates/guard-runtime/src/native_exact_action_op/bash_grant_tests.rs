//! Native launch plus the existing authenticated SQLite once authority.
//! These are local owner tests, not host-adapter or installed-runtime proof.

use super::super::super::bash_grant;
use super::*;
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::{
    ClaimApprovalReuseDecisionsRequestV1, GuardHookEnvelopeV2, GuardHookSourceMetadataV2,
};
use guard_policy_snapshot::{
    integrity_mac, policy_digest, verifier_key_id, POLICY_SNAPSHOT_PUSH_SCHEMA,
};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::sync::atomic::AtomicBool;

#[path = "bash_grant_journal_tests.rs"]
mod journal_tests;
#[path = "bash_grant_lifecycle_tests.rs"]
mod lifecycle_tests;
#[path = "bash_queue_scope_tests.rs"]
mod queue_scope_tests;
#[path = "bash_grant_review_fixture.rs"]
mod review_fixture;
#[path = "bash_grant_route_tests.rs"]
mod route_tests;
use review_fixture::{run_operation, seed_once_review};

fn policy_store(request: &NativeBashCaptureV1) -> (PolicySnapshotStore, GuardHookEnvelopeV2) {
    let root = Path::new(&request.guard_home);
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = [37u8; 32];
    let key_path = root.join(crate::policy_store::VERIFIER_KEY_FILE_NAME);
    std::fs::write(&key_path, key).unwrap();
    std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let store = PolicySnapshotStore::new(root, &"a".repeat(64)).unwrap();
    let mut snapshot = crate::policy_enforcement::tests::snapshot(
        crate::policy_enforcement::tests::policy("allow"),
    );
    snapshot.runtime_identity = "a".repeat(64);
    snapshot.rule_digest = guard_rule_contract::rule_digest();
    snapshot.config_digest =
        guard_policy_snapshot::config_digest(&snapshot.effective_policy).unwrap();
    snapshot.scope_contract.scope_digest = crate::policy_store::scope_digest_for_test(root);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    snapshot.issued_at_ms = now - 1;
    snapshot.expires_at_ms = now + 3_600_000;
    snapshot.integrity.key_id = verifier_key_id(&key);
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &key).unwrap();
    store
        .push(&json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,"snapshot":snapshot}))
        .unwrap();
    let envelope = GuardHookEnvelopeV2 {
        schema: guard_contracts::GUARD_HOOK_ENVELOPE_V2_SCHEMA.into(),
        request_id: Some("launch-once-test".into()),
        harness: request.harness.clone(),
        event: "PreToolUse".into(),
        raw_payload: json!({"tool_name":"bash","tool_input":{"command":request.command}}),
        deadline_budget_ms: Some(5000),
        policy_generation: snapshot.generation,
        policy_snapshot: serde_json::to_value(snapshot).unwrap(),
        source: GuardHookSourceMetadataV2 {
            cwd: Some(request.cwd.clone()),
            home_dir: request.home_dir.clone(),
            guard_home: request.guard_home.clone(),
            source_ref_external_allowed: false,
            execution_environment: Some(request.execution_environment.clone()),
        },
        recording_only: false,
    };
    (store, envelope)
}

fn once(
    request: &NativeBashCaptureV1,
    store: &PolicySnapshotStore,
    expires: &str,
) -> ClaimApprovalReuseDecisionsRequestV1 {
    use crate::store_vectors_support_tests::{decode_key, gunzip_json, seeded_store};
    let document = gunzip_json(include_bytes!("../../tests/fixtures/claim_vectors.json.gz"));
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == crate::claim_reuse_then_tests::ONE_SHOT)
        .unwrap();
    let connection = seeded_store(&document["schema_sql"], &vector["seed"]);
    // The production store always has the request table. These older claim
    // vectors intentionally contain only grant tables, so supply that read
    // surface explicitly instead of treating missing schema as no decision.
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS approval_requests(request_id TEXT PRIMARY KEY,
         status TEXT, resolution_action TEXT, action_envelope_json TEXT, harness TEXT,
         artifact_id TEXT, artifact_hash TEXT, workspace TEXT)",
        )
        .unwrap();
    let mut wire = vector["request"].clone();
    wire["schema"] = json!(guard_contracts::CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA);
    wire["guard_home"] = json!(request.guard_home);
    wire["store_path"] = json!(Path::new(&request.guard_home).join("guard.db"));
    let mut claim: ClaimApprovalReuseDecisionsRequestV1 = serde_json::from_value(wire).unwrap();
    claim.guard_home = request.guard_home.clone();
    claim.store_path = Path::new(&request.guard_home)
        .join("guard.db")
        .to_str()
        .unwrap()
        .into();
    claim.now = "1900-01-01T00:00:00+00:00".into(); // Not a launch-time clock.
    let captured =
        capture_for_launch(request, &store.current_admitted_snapshot().unwrap()).unwrap();
    let binding = bash_grant::binding(
        &captured.subject,
        &store.current_admitted_snapshot().unwrap(),
    )
    .unwrap();
    let id = claim.decisions[0]["approval_id"]
        .as_str()
        .unwrap()
        .to_owned();
    connection
        .execute(
            "update guard_local_once_approvals set artifact_id=?6, \
         artifact_hash=?1, harness=?2, workspace=?3, expires_at=?4 where approval_id=?5",
            params![
                binding,
                request.harness,
                crate::policy_decision_lookup_op::computed_workspace_policy_key(Some(
                    &request.workspace
                ))
                .unwrap(),
                expires,
                id,
                bash_grant::ARTIFACT
            ],
        )
        .unwrap();
    let sql = format!(
        "select {} from guard_local_once_approvals where approval_id=?1",
        crate::policy_decision_lookup_op::LOCAL_ONCE_CLAIM_COLUMNS
    );
    let row = connection
        .query_row(
            &sql,
            [&id],
            crate::policy_decision_lookup_op::local_once_row_to_json,
        )
        .unwrap();
    let fields = [
        "approval_id",
        "request_id",
        "harness",
        "artifact_id",
        "artifact_hash",
        "workspace",
        "publisher",
        "action",
        "created_at",
        "expires_at",
        "claimed_at",
        "authority_kind",
    ];
    let payload: serde_json::Map<String, Value> = fields
        .iter()
        .map(|field| ((*field).into(), row[*field].clone()))
        .collect();
    let key = decode_key(&json!(claim.local_once_integrity_key_b64)).unwrap();
    let key_id = claim.local_once_integrity_key_id.as_deref().unwrap();
    let signed = guard_policy_snapshot::local_authority_integrity::sign_local_authority_payload(
        &Value::Object(payload),
        &key,
        key_id,
        "guard-local-once-approval",
        row["signed_at"].as_str().unwrap(),
    )
    .unwrap();
    connection.execute(
        "update guard_local_once_approvals set payload_hash=?1,payload_mac=?2 where approval_id=?3",
        params![signed.payload_hash,signed.payload_mac,id],
    ).unwrap();
    let now = "1900-01-01T00:00:00+00:00";
    let mut decision = crate::policy_decision_lookup_op::claim_local_once_by_id(
        &connection,
        &id,
        now,
        Some(&key),
        Some(key_id),
        false,
        None,
    )
    .unwrap()
    .unwrap();
    decision["_approval_authority_revision"] =
        json!(crate::claim_reuse::approval_authority_revision(&connection).unwrap());
    claim.decisions = vec![decision];
    connection.execute(
        "INSERT INTO approval_requests(request_id,status,resolution_action,action_envelope_json,
         harness,artifact_id,artifact_hash,workspace) VALUES(?1,'resolved','allow',?2,?3,?4,?5,?6)",
        params![claim.decisions[0]["request_id"].as_str().unwrap(),
            json!({"native_bash":{"schema":guard_contracts::NATIVE_BASH_REVIEW_DESCRIPTOR_SCHEMA,
                "artifact_id":bash_grant::ARTIFACT,"artifact_hash":binding,"subject":captured.subject}}).to_string(),
            request.harness,bash_grant::ARTIFACT,binding,request.workspace],
    ).unwrap();
    connection
        .execute("vacuum into ?1", [&claim.store_path])
        .unwrap();
    claim
}

fn run(
    request: &NativeBashCaptureV1,
    store: &PolicySnapshotStore,
    envelope: &GuardHookEnvelopeV2,
    claim: &ClaimApprovalReuseDecisionsRequestV1,
) -> std::io::Result<guard_contained_process::CapturedOutput> {
    run_operation(
        request,
        store,
        envelope,
        claim,
        &format!("test-intent-{:016x}", next_intent()),
    )
}

fn next_intent() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

fn persistent(
    request: &NativeBashCaptureV1,
    store: &PolicySnapshotStore,
) -> ClaimApprovalReuseDecisionsRequestV1 {
    use crate::store_vectors_support_tests::{decode_key, gunzip_json, seeded_store};
    use guard_policy_snapshot::policy_integrity::{sign_local_policy_row, verify_local_policy_row};
    let document = gunzip_json(include_bytes!("../../tests/fixtures/claim_vectors.json.gz"));
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == crate::claim_reuse_then_tests::LOCAL_POLICY)
        .unwrap();
    let connection = seeded_store(&document["schema_sql"], &vector["seed"]);
    let mut wire = vector["request"].clone();
    wire["schema"] = json!(guard_contracts::CLAIM_APPROVAL_REUSE_REQUEST_SCHEMA);
    wire["guard_home"] = json!(request.guard_home);
    wire["store_path"] = json!(Path::new(&request.guard_home).join("guard.db"));
    let mut claim: ClaimApprovalReuseDecisionsRequestV1 = serde_json::from_value(wire).unwrap();
    claim.evidence_binding = Some(Default::default());
    let captured =
        capture_for_launch(request, &store.current_admitted_snapshot().unwrap()).unwrap();
    let binding = bash_grant::binding(
        &captured.subject,
        &store.current_admitted_snapshot().unwrap(),
    )
    .unwrap();
    let id = claim.decisions[0]["decision_id"].as_i64().unwrap();
    connection.execute(
        "update policy_decisions set artifact_id=?4,artifact_hash=?1, \
         harness=?2,workspace=null,scope='artifact',source='approval-gate',expires_at=null where decision_id=?3",
        params![binding,request.harness,id,bash_grant::ARTIFACT],
    ).unwrap();
    let sql = format!(
        "select {} from policy_decisions where decision_id=?1",
        crate::policy_decision_lookup_op::POLICY_LOOKUP_COLUMNS
    );
    let row = connection
        .query_row(
            &sql,
            [id],
            crate::policy_decision_lookup_op::policy_row_to_json,
        )
        .unwrap();
    let key = decode_key(&json!(claim.integrity_key_b64)).unwrap();
    let key_id = claim.integrity_key_id.as_deref().unwrap();
    let state = claim.integrity_state.as_ref().unwrap();
    let generation = state["generation"].as_i64().unwrap();
    let signed = sign_local_policy_row(
        &row,
        &key,
        key_id,
        row["signed_at"].as_str().unwrap(),
        generation,
    )
    .unwrap();
    connection.execute(
        "update policy_decisions set integrity_version=?1,integrity_generation=?2,payload_hash=?3, \
         payload_mac=?4,integrity_key_id=?5,signed_at=?6 where decision_id=?7",
        params![signed["integrity_version"].as_i64(),generation,signed["payload_hash"].as_str(),
            signed["payload_mac"].as_str(),key_id,signed["signed_at"].as_str(),id],
    ).unwrap();
    let row = connection
        .query_row(
            &sql,
            [id],
            crate::policy_decision_lookup_op::policy_row_to_json,
        )
        .unwrap();
    let verified = verify_local_policy_row(&row, Some(&key), Some(key_id), false, Some(generation));
    assert_eq!(verified.status, "valid");
    let mut decision =
        crate::policy_decision_lookup_op::policy_row_payload(&row, Some(&verified), Some(state));
    decision["_approval_authority_revision"] =
        json!(crate::claim_reuse::approval_authority_revision(&connection).unwrap());
    claim.decisions = vec![decision];
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null)",
        )
        .unwrap();
    connection
        .execute(
            "insert into sync_state values ('policy_integrity',?1)",
            [state.to_string()],
        )
        .unwrap();
    connection
        .execute("vacuum into ?1", [&claim.store_path])
        .unwrap();
    claim
}

#[test]
fn bash_saved_persistent_grant_runs_ten_times_across_resident_restarts() {
    let (_root, request) = tests::fixture();
    let (mut store, envelope) = policy_store(&request);
    let claim = persistent(&request, &store);
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    let mut expected = None;
    for _ in 0..10 {
        let result = run(&request, &store, &envelope, &claim).unwrap();
        assert_eq!(
            result.exit_code,
            Some(0),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let actual = std::fs::read(&report).unwrap();
        if let Some(expected) = &expected {
            assert_eq!(&actual, expected);
        }
        expected = Some(actual);
        drop(store);
        store = PolicySnapshotStore::new(Path::new(&request.guard_home), &"a".repeat(64)).unwrap();
    }
    let connection = Connection::open(&claim.store_path).unwrap();
    let events: i64 = connection
        .query_row(
            "select count(*) from guard_events where event_name='approval.policy_reuse_applied'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(events, 10);
    assert_eq!(
        connection
            .query_row("select count(*) from policy_decisions", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn bash_saved_once_claim_runs_exactly_one_actual_launch() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let report = Path::new(&request.home_dir).join("maintenance-report.tsv");
    assert!(!report.exists());
    let first = run(&request, &store, &envelope, &claim).unwrap();
    assert_eq!(
        first.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let reviewed = std::fs::read(&report).unwrap();
    assert!(!reviewed.is_empty());
    assert!(run(&request, &store, &envelope, &claim).is_err());
    assert_eq!(
        std::fs::read(&report).unwrap(),
        reviewed,
        "no second truncation"
    );
    let connection = Connection::open(&claim.store_path).unwrap();
    let events: i64 = connection
        .query_row(
            "select count(*) from guard_events where event_name='approval.local_once_applied'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(events, 1);
}

#[test]
fn bash_changed_helper_does_not_spend_the_saved_once_grant() {
    let (_root, request) = tests::fixture();
    let (store, envelope) = policy_store(&request);
    let claim = once(&request, &store, "2050-01-01T00:00:00+00:00");
    let helper = Path::new(&request.cwd).join("fixture-registry");
    let original = std::fs::read(&helper).unwrap();
    std::fs::write(&helper, "#!/bin/bash\nprintf changed\n").unwrap();
    assert!(run_operation(
        &request,
        &store,
        &envelope,
        &claim,
        "helper-reissued-operation-0001"
    )
    .is_err());
    assert!(!Path::new(&request.home_dir)
        .join("maintenance-report.tsv")
        .exists());
    std::fs::write(&helper, original).unwrap();
    assert_eq!(
        run_operation(
            &request,
            &store,
            &envelope,
            &claim,
            "helper-reissued-operation-0001"
        )
        .unwrap()
        .exit_code,
        Some(0)
    );
}

#[test]
fn bash_expired_or_tampered_once_never_opens_the_report() {
    for expired in [false, true] {
        let (_root, request) = tests::fixture();
        let (store, envelope) = policy_store(&request);
        let claim = once(
            &request,
            &store,
            if expired {
                "2000-01-01T00:00:00+00:00"
            } else {
                "2050-01-01T00:00:00+00:00"
            },
        );
        if !expired {
            Connection::open(&claim.store_path)
                .unwrap()
                .execute(
                    "update guard_local_once_approvals set payload_mac=?1",
                    ["0".repeat(64)],
                )
                .unwrap();
        }
        assert!(run(&request, &store, &envelope, &claim).is_err());
        assert!(!Path::new(&request.home_dir)
            .join("maintenance-report.tsv")
            .exists());
    }
}
