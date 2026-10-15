use super::*;
use crate::local_store_read::schema_checksum;
use crate::policy_decision_lookup_op::tests::{seed_store, tmp_store};
use crate::policy_decision_lookup_op::{policy_row_to_json, POLICY_LOOKUP_COLUMNS};
use crate::policy_store::policy_store_direct_lane::DirectLaneIntegrityKey;
use guard_contracts::NativeExactActionQueryV1;
use guard_policy_snapshot::{DirectLaneEnvironmentV1, DirectLanePolicyIntegrityStateV1};
use rusqlite::params;
use std::collections::BTreeMap;

const VECTORS: &str = include_str!("../tests/fixtures/hook_direct_saved_decision_vectors.json");
const KEY: [u8; 32] = [7u8; 32];
const KEY_ID: &str = "test-policy-key";
pub(super) const SIGNED_AT: &str = "2026-01-01T00:00:00+00:00";

pub(super) fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("saved-decision vectors parse")
}

#[test]
fn verdicts_match_the_daemon_vectors() {
    let vectors = vectors();
    let artifact_id = vectors["artifact_id"].as_str().unwrap();
    let token = vectors["token"].as_str().unwrap();
    let cases = vectors["verdicts"].as_array().unwrap();
    assert!(cases.len() >= 24);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let result = case["result"].as_object().unwrap();
        let actual = saved_verdict(result, &case["lookup"], artifact_id, token)
            .map(|(verdict, status)| json!({"verdict": Value::Object(verdict), "status": status}));
        assert_eq!(actual.unwrap_or(Value::Null), case["expected"], "{name}");
    }
}

#[test]
fn truthy_follows_python() {
    for value in [
        json!(true),
        json!(1),
        json!(-0.5),
        json!("x"),
        json!([0]),
        json!({"a": 0}),
    ] {
        assert!(truthy(Some(&value)), "{value}");
    }
    for value in [
        json!(null),
        json!(false),
        json!(0),
        json!(0.0),
        json!(""),
        json!([]),
        json!({}),
    ] {
        assert!(!truthy(Some(&value)), "{value}");
    }
    assert!(!truthy(None));
}

#[test]
fn an_unhashable_action_type_is_never_overridable() {
    let mut result: Object = serde_json::from_value(json!({
        "policy_action": "review",
        "minimum_action": "require-reapproval",
        "action": {"action_type": "shell"},
    }))
    .unwrap();
    assert!(overridable(&result));
    for action_type in [json!(["shell"]), json!({"kind": "shell"}), json!("package")] {
        result.insert("action".to_owned(), json!({"action_type": action_type}));
        assert!(!overridable(&result), "{action_type}");
    }
    result.insert("action".to_owned(), json!({"action_type": 7}));
    assert!(overridable(&result));
}

#[test]
fn render_marks_the_reuse_status_and_refuses_an_oversize_verdict() {
    let verdict: Object = serde_json::from_value(json!({
        "decision": "allow",
        "policy_action": "allow",
        "minimum_action": "allow",
        "reason": "Saved.",
    }))
    .unwrap();
    let response = render("claude-code", &verdict, "accepted").unwrap();
    assert_eq!(response["approval_reuse_status"], json!("accepted"));
    let mut oversize = verdict.clone();
    oversize.insert(
        "reason".to_owned(),
        json!("x".repeat(HOOK_RENDER_MAX_BYTES / ESCAPE_FACTOR)),
    );
    assert!(render("claude-code", &oversize, "accepted").is_none());
}

fn integrity_state() -> DirectLanePolicyIntegrityStateV1 {
    DirectLanePolicyIntegrityStateV1 {
        backend: "encrypted-file".to_owned(),
        cutover_complete: true,
        degraded_reasons: Vec::new(),
        enforcement: "enforce".to_owned(),
        generation: Some(1),
        key_id: Some(KEY_ID.to_owned()),
        mode: "protected".to_owned(),
    }
}

/// A store with the schema marker, the published integrity state and no
/// decisions.
pub(super) fn local_store(tag: &str) -> (std::path::PathBuf, Connection) {
    let path = tmp_store(&format!("saved-{tag}"));
    let _ = std::fs::remove_file(&path);
    seed_store(&path);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null,
               updated_at text not null);
             create table local_cli_schema_migration (singleton integer primary key,
               version integer not null, checksum text not null);",
        )
        .unwrap();
    connection
        .execute(
            "insert into local_cli_schema_migration (singleton, version, checksum) values (1, ?1, ?2)",
            params![SUPPORTED_SCHEMA_VERSION, schema_checksum(SUPPORTED_SCHEMA_VERSION)],
        )
        .unwrap();
    let state = serde_json::to_string(&integrity_state()).unwrap();
    connection
        .execute(
            "insert into sync_state (state_key, payload_json, updated_at)
             values ('policy_integrity', ?1, ?2)",
            params![state, SIGNED_AT],
        )
        .unwrap();
    (path, connection)
}

/// Insert a signed exact decision and return its row id.
fn insert_decision(
    connection: &Connection,
    harness: &str,
    artifact_id: &str,
    token: &str,
    action: &str,
    source: &str,
) -> i64 {
    connection
        .execute(
            "insert into policy_decisions
             (harness, scope, artifact_id, action, artifact_hash, source, created_at, updated_at)
             values (?1, 'artifact', ?2, ?3, ?4, ?5, ?6, ?6)",
            params![harness, artifact_id, action, token, source, SIGNED_AT],
        )
        .unwrap();
    let id = connection.last_insert_rowid();
    sign_decision(connection, id);
    id
}

/// Sign the decision `id` with the published integrity key.
pub(super) fn sign_decision(connection: &Connection, id: i64) {
    let row = connection
        .query_row(
            &format!("select {POLICY_LOOKUP_COLUMNS} from policy_decisions where decision_id = ?1"),
            params![id],
            policy_row_to_json,
        )
        .unwrap();
    let signed = guard_policy_snapshot::policy_integrity::sign_local_policy_row(
        &row, &KEY, KEY_ID, SIGNED_AT, 1,
    )
    .unwrap();
    connection
        .execute(
            "update policy_decisions set integrity_version = ?1, integrity_generation = ?2,
             payload_hash = ?3, payload_mac = ?4, integrity_key_id = ?5, signed_at = ?6
             where decision_id = ?7",
            params![
                signed["integrity_version"].as_i64(),
                signed["integrity_generation"].as_i64(),
                signed["payload_hash"].as_str(),
                signed["payload_mac"].as_str(),
                signed["integrity_key_id"].as_str(),
                signed["signed_at"].as_str(),
                id
            ],
        )
        .unwrap();
}

pub(super) const ARTIFACT: &str = "claude-code:native-pretool:Read";
pub(super) const TOKEN: &str =
    "guard-exact-action:v1:0000000000000000000000000000000000000000000000000000000000000000";

fn shape(connection: &Connection) -> StoreShape<'_> {
    StoreShape {
        connection,
        harness: "claude-code",
        artifact_id: ARTIFACT,
    }
}

fn published() -> Value {
    serde_json::to_value(integrity_state()).unwrap()
}

#[test]
fn a_local_store_with_the_decision_is_read() {
    let (_path, connection) = local_store("local");
    assert!(shape(&connection).supported().unwrap());
    assert!(!shape(&connection).grants().unwrap());
    assert_eq!(
        shape(&connection).readable(&published()).unwrap(),
        Some(false)
    );
    assert!(!shape(&connection).decided(Some(TOKEN)).unwrap());
    insert_decision(
        &connection,
        "claude-code",
        ARTIFACT,
        TOKEN,
        "allow",
        "approval-gate",
    );
    assert_eq!(
        shape(&connection).readable(&published()).unwrap(),
        Some(true)
    );
    assert!(shape(&connection).decided(Some(TOKEN)).unwrap());
    // A remote decision is read alongside, with the same evidence.
    connection
        .execute_batch(
            "insert into policy_decisions (harness, scope, action, source, created_at, updated_at)
             values ('*', 'global', 'block', 'team-policy', 'x', 'x');",
        )
        .unwrap();
    assert_eq!(
        shape(&connection).readable(&published()).unwrap(),
        Some(true)
    );
    // A cached bundle with no policy-bundle row for its identities to match
    // leaves every lookup as it was.
    connection
        .execute_batch("insert into sync_state values ('policy_bundle', '{}', 'x');")
        .unwrap();
    assert_eq!(
        shape(&connection).readable(&published()).unwrap(),
        Some(true)
    );
}

#[test]
fn a_store_the_lookup_reads_differently_defers() {
    let cases: [(&str, &str); 4] = [
        (
            "grant",
            "create table local_cli_grant (grant_id text); insert into local_cli_grant values ('g');",
        ),
        (
            "bundle",
            "insert into sync_state values ('policy_bundle', '{}', 'x');
             insert into policy_decisions (harness, scope, action, source, created_at, updated_at)
             values ('*', 'global', 'block', 'policy-bundle', 'x', 'x');",
        ),
        (
            "state",
            "update sync_state set payload_json = '{\"mode\": \"degraded\"}'
             where state_key = 'policy_integrity';",
        ),
        ("schema", "delete from local_cli_schema_migration;"),
    ];
    for (tag, change) in cases {
        let (_path, connection) = local_store(tag);
        insert_decision(
            &connection,
            "claude-code",
            ARTIFACT,
            TOKEN,
            "allow",
            "approval-gate",
        );
        connection.execute_batch(change).unwrap();
        let store = shape(&connection);
        assert!(
            !(store.supported().unwrap()
                && !store.grants().unwrap()
                && store.readable(&published()).unwrap().is_some()),
            "{tag}"
        );
    }
}

#[test]
fn a_damaged_schema_marker_defers() {
    let (_path, connection) = local_store("damaged");
    insert_decision(
        &connection,
        "claude-code",
        ARTIFACT,
        TOKEN,
        "allow",
        "approval-gate",
    );
    connection
        .execute("update local_cli_schema_migration set checksum = 'x'", [])
        .unwrap();
    assert!(matches!(
        shape(&connection).supported(),
        Err(HookDirectDefer::SavedDecision)
    ));
}

#[test]
fn a_decision_for_another_token_defers() {
    let (_path, connection) = local_store("other-token");
    insert_decision(
        &connection,
        "*",
        ARTIFACT,
        "guard-exact-action:v1:other",
        "allow",
        "approval-gate",
    );
    let store = shape(&connection);
    assert!(!store.decided(Some(TOKEN)).unwrap());
    // A token the resident could not derive may be the other one.
    assert!(store.decided(None).unwrap());
    insert_decision(&connection, "*", ARTIFACT, TOKEN, "block", "approval-gate");
    assert!(store.decided(Some(TOKEN)).unwrap());
}

pub(super) fn binding() -> DirectLaneBinding {
    let vectors = vectors();
    let mut binding = DirectLaneBinding::empty_for_tests();
    binding.exact_action_environment = Some(DirectLaneEnvironmentV1(
        serde_json::from_value::<BTreeMap<String, String>>(vectors["environment"].clone()).unwrap(),
    ));
    binding.exact_action_control_digest =
        Some(vectors["control_digest"].as_str().unwrap().to_owned());
    binding.policy_integrity_state = Some(integrity_state());
    binding.integrity_key = Some(DirectLaneIntegrityKey {
        key: Zeroizing::new(KEY.to_vec()),
        key_id: KEY_ID.to_owned(),
    });
    binding
}

/// A real workspace for the read vector, whose token resolves its target.
pub(super) fn workspace(tag: &str) -> String {
    let root =
        std::env::temp_dir().join(format!("hg-saved-workspace-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/a.py"), b"print(1)\n").unwrap();
    root.canonicalize().unwrap().to_str().unwrap().to_owned()
}

/// The edge, payload and token of the bound `Read` vector in `workspace`.
fn bound_request(
    binding: &DirectLaneBinding,
    workspace: &str,
) -> (Vec<u8>, Map<String, Value>, String, String) {
    let (edge, payload, artifact_id, exact) = bound_query(binding, workspace);
    let token = crate::native_exact_action_op::exact_action_token(&exact).unwrap();
    (edge, payload, artifact_id, token)
}

/// The edge, payload, artifact id and exact-action query of the bound
/// `Read` vector in `workspace`.
pub(super) fn bound_query(
    binding: &DirectLaneBinding,
    workspace: &str,
) -> (
    Vec<u8>,
    Map<String, Value>,
    String,
    NativeExactActionQueryV1,
) {
    let vectors = vectors();
    let case = vectors["queries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "camel-case-read")
        .unwrap()
        .clone();
    let payload = case["payload"].as_object().unwrap().clone();
    let result = case["result"].as_object().unwrap().clone();
    let input = query::QueryInput {
        harness: "claude-code",
        payload: &payload,
        workspace,
        home_dir: vectors["home_dir"].as_str().unwrap(),
        environment: &binding.exact_action_environment.as_ref().unwrap().0,
        control_digest: binding.exact_action_control_digest.as_deref().unwrap(),
    };
    let (artifact_id, exact) = query::exact_action(&input, &result, case.get("receipt"))
        .unwrap_or_else(|_| panic!("bound vector deferred"));
    let edge = serde_json::to_vec(&json!({
        "event_name": PRE_TOOL_USE,
        "result": result,
        "receipt": case["receipt"],
        "harness_response": {"hookSpecificOutput": {"permissionDecision": "ask"}},
    }))
    .unwrap();
    (edge, payload, artifact_id, exact)
}

fn answer_with(
    tag: &str,
    action: &str,
    answering: &DirectLaneBinding,
) -> Result<Value, HookDirectDefer> {
    seeded::answer_in(tag, action, answering, "")
}

#[test]
fn a_saved_allow_answers_the_review() {
    let answered = answer_with("answer-allow", "allow", &binding()).unwrap();
    let response = &answered["harness_response"];
    assert_eq!(response["approval_reuse_status"], json!("accepted"));
}

#[test]
fn a_saved_block_answers_the_review() {
    let answered = answer_with("answer-block", "block", &binding()).unwrap();
    let response = &answered["harness_response"];
    assert_eq!(response["approval_reuse_status"], json!("blocked"));
}

#[test]
fn a_binding_without_the_published_state_defers() {
    let mut degraded = binding();
    degraded.policy_integrity_state = Some(DirectLanePolicyIntegrityStateV1 {
        degraded_reasons: vec!["keyring_unavailable".to_owned()],
        ..integrity_state()
    });
    assert!(matches!(
        answer_with("answer-degraded", "allow", &degraded),
        Err(HookDirectDefer::SavedDecision)
    ));
    let mut unbound = binding();
    unbound.exact_action_control_digest = None;
    assert!(matches!(
        answer_with("answer-unbound", "allow", &unbound),
        Err(HookDirectDefer::NotAllow)
    ));
    let mut other_key = binding();
    other_key.integrity_key = Some(DirectLaneIntegrityKey {
        key: Zeroizing::new(vec![9u8; 32]),
        key_id: KEY_ID.to_owned(),
    });
    assert!(matches!(
        answer_with("answer-other-key", "allow", &other_key),
        Err(HookDirectDefer::SavedDecision)
    ));
}

#[path = "hook_direct_saved_subdirectory_tests.rs"]
mod subdirectory;

#[path = "hook_direct_saved_seeded_tests.rs"]
mod seeded;
