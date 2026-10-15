use super::super::store;
use super::*;
use crate::local_store_read::{schema_checksum, SUPPORTED_SCHEMA_VERSION};
use crate::policy_decision_lookup_op::tests::{seed_store, tmp_store};
use crate::policy_decision_lookup_op::{policy_row_to_json, POLICY_LOOKUP_COLUMNS};
use crate::policy_store::policy_store_direct_lane::{DirectLaneBinding, DirectLaneIntegrityKey};
use guard_policy_snapshot::DirectLanePolicyIntegrityStateV1;
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const KEY: [u8; 32] = [7u8; 32];
const KEY_ID: &str = "test-policy-key";
const SIGNED_AT: &str = "2026-01-01T00:00:00+00:00";
const HARNESS: &str = "codex";
const ARTIFACT: &str = "codex:project:files:read";
const HASH: &str = "sha256:relay";

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

pub(in crate::mcp_relay_decide) fn binding() -> DirectLaneBinding {
    let mut binding = DirectLaneBinding::empty_for_tests();
    binding.policy_integrity_state = Some(integrity_state());
    binding.integrity_key = Some(DirectLaneIntegrityKey {
        key: Zeroizing::new(KEY.to_vec()),
        key_id: KEY_ID.to_owned(),
    });
    binding
}

/// A guard home whose store holds the schema marker, the diagnostic indexes,
/// the published integrity state and no saved rows; the writable connection
/// seeds it.
pub(in crate::mcp_relay_decide) fn guard_home(tag: &str) -> (PathBuf, Connection) {
    let path = tmp_store(&format!("mcp-relay-{tag}"));
    let _ = std::fs::remove_file(&path);
    seed_store(&path);
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null,
               updated_at text not null);
             create table local_cli_schema_migration (singleton integer primary key,
               version integer not null, checksum text not null);
             create index idx_guard_local_once_diagnostic_artifact
               on guard_local_once_approvals (harness, artifact_id, created_at desc, approval_id desc)
               where claimed_at is null and action = 'allow';
             create index idx_guard_local_once_diagnostic_hash
               on guard_local_once_approvals (harness, artifact_hash, created_at desc, approval_id desc)
               where claimed_at is null and action = 'allow';
             create index idx_policy_decisions_reuse_artifact
               on policy_decisions (action, harness, artifact_id, updated_at desc, decision_id desc);
             create index idx_policy_decisions_reuse_hash
               on policy_decisions (action, harness, artifact_hash, updated_at desc, decision_id desc);
             create index idx_policy_decisions_reuse_publisher
               on policy_decisions (action, harness, publisher, updated_at desc, decision_id desc);
             create index idx_policy_decisions_diagnostic_harness_broad
               on policy_decisions (harness, updated_at desc, decision_id desc)
               where scope = 'harness' and action = 'allow' and artifact_id is null;
             create index idx_policy_decisions_diagnostic_global_broad
               on policy_decisions (harness, updated_at desc, decision_id desc)
               where scope = 'global' and action = 'allow' and artifact_id is null;
             create index idx_policy_decisions_diagnostic_publisher
               on policy_decisions (harness, publisher, updated_at desc, decision_id desc)
               where scope = 'publisher' and action = 'allow';",
        )
        .unwrap();
    connection
        .execute(
            "insert into local_cli_schema_migration (singleton, version, checksum) values (1, ?1, ?2)",
            params![SUPPORTED_SCHEMA_VERSION, schema_checksum(SUPPORTED_SCHEMA_VERSION)],
        )
        .unwrap();
    let state = serde_json::to_string(&integrity_state()).unwrap();
    sync_state(&connection, "policy_integrity", &state);
    (path.parent().unwrap().to_path_buf(), connection)
}

pub(in crate::mcp_relay_decide) fn sync_state(connection: &Connection, key: &str, payload: &str) {
    connection
        .execute(
            "insert or replace into sync_state (state_key, payload_json, updated_at)
             values (?1, ?2, ?3)",
            params![key, payload, SIGNED_AT],
        )
        .unwrap();
}

/// Insert a signed decision.
pub(in crate::mcp_relay_decide) fn decide(
    connection: &Connection,
    scope: &str,
    action: &str,
    workspace: Option<&str>,
    source: &str,
) {
    connection
        .execute(
            "insert into policy_decisions
             (harness, scope, artifact_id, action, artifact_hash, workspace, source,
              created_at, updated_at)
             values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
            params![HARNESS, scope, ARTIFACT, action, HASH, workspace, source, SIGNED_AT],
        )
        .unwrap();
    let id = connection.last_insert_rowid();
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

/// What `saved` makes of the store at `home`, on the read-only connection
/// the relay opens.
fn read<T>(
    home: &Path,
    binding: &DirectLaneBinding,
    then: impl FnOnce(Option<&Saved<'_>>) -> T,
) -> Result<T, &'static str> {
    let connection = store::open(home)?.expect("store");
    let saved = store::saved(&connection, binding, home.to_str().unwrap())?;
    Ok(then(saved.as_ref()))
}

fn policy_need(artifact_id: &str, workspace: Option<&str>) -> Value {
    json!({
        "kind": "policy_lookup",
        "harness": HARNESS,
        "artifact_id": artifact_id,
        "artifact_hash": HASH,
        "workspace": workspace,
        "publisher": null,
        "runtime_exact_match_context": null,
        "memory_command": null,
        "memory_artifact_type": null,
        "memory_artifact_name": null,
    })
}

#[test]
fn a_missing_or_newer_store_is_read_as_the_proxy_reads_it() {
    let absent = std::env::temp_dir().join(format!("mcp-relay-absent-{}", std::process::id()));
    std::fs::create_dir_all(&absent).unwrap();
    assert!(store::open(&absent).unwrap().is_none());
    let (newer, connection) = guard_home("newer");
    connection
        .execute(
            "update local_cli_schema_migration set version = ?1",
            params![SUPPORTED_SCHEMA_VERSION + 1],
        )
        .unwrap();
    assert!(matches!(store::open(&newer), Err(STORE_UNREADABLE)));
}

#[test]
fn a_store_without_saved_rows_answers_as_empty() {
    let (home, _connection) = guard_home("empty");
    assert!(read(&home, &binding(), |saved| saved.is_none()).unwrap());
}

#[test]
fn a_cached_bundle_defers_and_remote_rows_are_read() {
    let (home, connection) = guard_home("bundle");
    sync_state(&connection, "policy_bundle", "{}");
    // Without a policy-bundle row, the bundle's identities match nothing.
    assert!(read(&home, &binding(), |saved| saved.is_none()).unwrap());
    decide(&connection, "artifact", "block", None, "policy-bundle");
    let deferred = read(&home, &binding(), |_| ()).err();
    assert_eq!(deferred, Some("mcp_relay_saved_remote_policy"));
    // The lookup never serves a cloud-sync row, and serves a signed memory
    // row without local integrity evidence.
    let (home, connection) = guard_home("remote");
    decide(&connection, "artifact", "allow", None, "cloud-sync");
    let answer = |home: &Path| {
        read(home, &binding(), |saved| {
            let saved = saved.expect("remote rows");
            assert!(!saved.has_local_policy);
            saved.answer(&policy_need(ARTIFACT, None)).unwrap()
        })
        .unwrap()
    };
    assert_eq!(answer(&home)["decision"], Value::Null);
    decide(
        &connection,
        "artifact",
        "block",
        None,
        "cloud-signed-memory",
    );
    assert_eq!(answer(&home)["decision"]["action"], "block");
}

#[test]
fn an_unpublished_or_moved_integrity_state_defers() {
    let (home, connection) = guard_home("unverifiable");
    decide(&connection, "artifact", "block", None, "approval-gate");
    let mut unbound = binding();
    unbound.integrity_key = None;
    let mut degraded = binding();
    if let Some(state) = degraded.policy_integrity_state.as_mut() {
        state.degraded_reasons.push("keyring".to_owned());
    }
    for binding in [unbound, degraded] {
        assert_eq!(
            read(&home, &binding, |_| ()).err(),
            Some("mcp_relay_saved_policy_unverifiable")
        );
    }
    let mut moved = integrity_state();
    moved.generation = Some(2);
    sync_state(
        &connection,
        "policy_integrity",
        &serde_json::to_string(&moved).unwrap(),
    );
    assert_eq!(
        read(&home, &binding(), |_| ()).err(),
        Some("mcp_relay_saved_policy_unverifiable")
    );
}

#[test]
fn a_saved_block_answers_the_lookups() {
    let (home, connection) = guard_home("block");
    decide(&connection, "artifact", "block", None, "approval-gate");
    let (policy, grant) = read(&home, &binding(), |saved| {
        let saved = saved.expect("saved rows");
        let policy = saved.answer(&policy_need(ARTIFACT, None)).unwrap();
        let grant = saved
            .answer(&json!({"kind": "grant_lookup", "harness": HARNESS, "selector": ARTIFACT}))
            .unwrap();
        (policy, grant)
    })
    .unwrap();
    assert_eq!(policy["decision"]["action"], "block");
    assert_eq!(policy["ignored_local_integrity"], false);
    assert!(policy.get("reuse_diagnostic").is_none());
    assert!(grant
        .as_object()
        .is_some_and(|fields| fields.len() == 1 && fields.contains_key("decision")));
}

#[test]
fn a_miss_carries_the_reuse_diagnostic() {
    let (home, connection) = guard_home("miss");
    decide(&connection, "artifact", "block", None, "approval-gate");
    let policy = read(&home, &binding(), |saved| {
        saved
            .expect("saved rows")
            .answer(&policy_need("codex:project:files:write", None))
            .unwrap()
    })
    .unwrap();
    assert_eq!(policy["decision"], Value::Null);
    assert_eq!(policy["ignored_local_integrity"], false);
    assert!(policy["reuse_diagnostic"]
        .as_object()
        .is_some_and(|diagnostic| diagnostic.contains_key("reason")));
}

/// A fresh canonical directory, a Git checkout cloned from `remote` when
/// one is named.
#[cfg(unix)]
fn directory(tag: &str, remote: Option<&str>) -> String {
    let path = std::env::temp_dir().join(format!("mcp-relay-ws-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    if let Some(remote) = remote {
        let git = path.join(".git");
        std::fs::create_dir_all(git.join("logs")).unwrap();
        let config = format!("[remote \"origin\"]\n\turl = {remote}\n");
        std::fs::write(git.join("config"), config).unwrap();
        let zeros = "0".repeat(40);
        let head = "1".repeat(40);
        let log = format!("{zeros} {head} G <g@example.invalid> 1 +0000\tclone: from {remote}\n");
        std::fs::write(git.join("logs/HEAD"), log).unwrap();
    }
    let path = std::fs::canonicalize(&path).unwrap();
    path.to_str().unwrap().to_owned()
}

#[cfg(unix)]
#[test]
fn a_workspace_row_bound_elsewhere_defers_a_workspace_lookup() {
    let (home, connection) = guard_home("elsewhere");
    let workspace = directory("elsewhere", None);
    let other = workspace_policy_key(Some("/elsewhere")).unwrap();
    decide(
        &connection,
        "workspace",
        "block",
        Some(&other),
        "approval-gate",
    );
    let answers = read(&home, &binding(), |saved| {
        let saved = saved.expect("saved rows");
        (
            saved.answer(&policy_need(ARTIFACT, Some(&workspace))),
            saved.answer(&policy_need(ARTIFACT, None)).is_ok(),
        )
    })
    .unwrap();
    assert_eq!(answers.0, Err(SAVED_PORTABLE));
    assert!(answers.1);
}

#[cfg(unix)]
#[test]
fn a_confined_workspace_row_answers_a_workspace_lookup() {
    let (home, connection) = guard_home("confined");
    let workspace = directory("confined", None);
    let key = workspace_policy_key(Some(&workspace)).unwrap();
    decide(
        &connection,
        "workspace",
        "block",
        Some(&key),
        "approval-gate",
    );
    let answers = read(&home, &binding(), |saved| {
        let saved = saved.expect("saved rows");
        (
            saved.answer(&policy_need(ARTIFACT, Some(&workspace))),
            // A workspace whose identity is not resolved exactly defers.
            saved.answer(&policy_need(ARTIFACT, Some("relative/work"))),
        )
    })
    .unwrap();
    assert_eq!(answers.0.unwrap()["decision"]["action"], "block");
    assert_eq!(answers.1, Err(SAVED_PORTABLE));
}

#[cfg(unix)]
#[test]
fn a_portable_row_answers_only_the_workspace_resolving_to_it() {
    let (home, connection) = guard_home("portable");
    let repository = directory("repository", Some("https://github.com/example/relay.git"));
    let plain = directory("plain", None);
    let crate::project_identity::PortableIdentity::Identity(identity) =
        crate::project_identity::resolve(&repository)
    else {
        panic!("the checkout resolves");
    };
    decide(
        &connection,
        "workspace",
        "block",
        Some(&identity),
        "approval-gate",
    );
    let grant = json!({"kind": "grant_lookup", "harness": HARNESS, "selector": ARTIFACT});
    let answers = read(&home, &binding(), |saved| {
        let saved = saved.expect("saved rows");
        (
            saved.answer(&policy_need(ARTIFACT, Some(&repository))),
            saved.answer(&policy_need(ARTIFACT, Some(&plain))),
            saved.answer(&policy_need(ARTIFACT, None)),
            saved.answer(&grant),
        )
    })
    .unwrap();
    // The portable block outranks the local miss, as the proxy composes it.
    assert_eq!(answers.0.unwrap()["decision"]["action"], "block");
    for answer in [answers.1, answers.2, answers.3] {
        assert_eq!(answer, Err("mcp_relay_saved_remote_policy"));
    }
    // A row under another identity defers the checkout's lookup too.
    let other = format!("{PORTABLE_PROJECT_IDENTITY_PREFIX}{}", "f".repeat(64));
    decide(
        &connection,
        "workspace",
        "block",
        Some(&other),
        "approval-gate",
    );
    let answer = read(&home, &binding(), |saved| {
        saved
            .expect("saved rows")
            .answer(&policy_need(ARTIFACT, Some(&repository)))
    })
    .unwrap();
    assert_eq!(answer, Err("mcp_relay_saved_remote_policy"));
}

/// The claim's fresh resolve (`after_claim`) reads saved lookups through
/// `store::saved` on the claim's write transaction, query-only, so a
/// portable block saved after the decision outranks the claimed local allow
/// there, and `postclaim` answers the fresh block instead of forwarding.
#[cfg(unix)]
#[test]
fn a_portable_block_saved_before_the_claim_outranks_the_claimed_allow() {
    let (home, connection) = guard_home("claim");
    let repository = directory("claim", Some("https://github.com/example/claim.git"));
    let key = workspace_policy_key(Some(&repository)).unwrap();
    decide(
        &connection,
        "workspace",
        "allow",
        Some(&key),
        "approval-gate",
    );
    let need = policy_need(ARTIFACT, Some(&repository));
    let decided = read(&home, &binding(), |saved| {
        saved.expect("saved rows").answer(&need)
    });
    assert_eq!(decided.unwrap().unwrap()["decision"]["action"], "allow");
    let crate::project_identity::PortableIdentity::Identity(identity) =
        crate::project_identity::resolve(&repository)
    else {
        panic!("the checkout resolves");
    };
    decide(
        &connection,
        "workspace",
        "block",
        Some(&identity),
        "approval-gate",
    );
    let claim = Connection::open(home.join(crate::local_store_read::STORE_FILE_NAME)).unwrap();
    let transaction = claim.unchecked_transaction().unwrap();
    claim.execute_batch("PRAGMA query_only = ON").unwrap();
    let saved = store::saved(&claim, &binding(), home.to_str().unwrap())
        .unwrap()
        .expect("saved rows");
    let fresh = saved.answer(&need).unwrap();
    assert_eq!(fresh["decision"]["action"], "block");
    drop(saved);
    drop(transaction);
}

#[cfg(unix)]
#[test]
fn a_portable_allow_never_lowers_enforcement() {
    let (home, connection) = guard_home("portable-allow");
    let repository = directory("allow", Some("git@github.com:example/allow.git"));
    let crate::project_identity::PortableIdentity::Identity(identity) =
        crate::project_identity::resolve(&repository)
    else {
        panic!("the checkout resolves");
    };
    decide(
        &connection,
        "workspace",
        "allow",
        Some(&identity),
        "approval-gate",
    );
    let policy = read(&home, &binding(), |saved| {
        saved
            .expect("saved rows")
            .answer(&policy_need(ARTIFACT, Some(&repository)))
    })
    .unwrap()
    .unwrap();
    assert_eq!(policy["decision"], Value::Null);
}

#[test]
fn a_need_the_proxy_would_reject_fails() {
    let (home, connection) = guard_home("need");
    decide(&connection, "artifact", "block", None, "approval-gate");
    let mut need = policy_need(ARTIFACT, None);
    need.as_object_mut().unwrap().remove("publisher");
    let answer = read(&home, &binding(), |saved| {
        saved.expect("saved rows").answer(&need)
    });
    assert_eq!(answer.unwrap(), Err(POLICY_NEED));
}
