//! What the relay resolves for a package call, and which store defers it.

use super::super::saved::tests::{binding, decide, guard_home};
// The rows only a store the tests write to carries, which Windows never reaches.
#[cfg(unix)]
use super::super::saved::tests::{decide_row, sync_state, Row};
use super::super::store;
use super::*;

use guard_command::package_intent_common::build_package_request_artifact;
use guard_command::package_intent_parser::parse_package_intent;
#[cfg(unix)]
use rusqlite::params;
use rusqlite::Connection;
use std::path::Path;

const HARNESS: &str = "codex";

/// The policy view the bound harness hydrates, with no override of its own, so
/// the composed action is the evaluation's.
fn view() -> HarnessView {
    let config = json!({
        "mode": "enforce",
        "default_action": "warn",
        "artifact_actions": Value::Null,
        "publisher_actions": Value::Null,
        "harness_actions": Value::Null,
        "risk_actions": {},
        "harness_risk_actions": {},
        "security_level": "balanced",
        "protection_posture": "balanced",
        "protection_posture_explicit": false,
        "managed_locked_settings": [],
    });
    let config = config.as_object().expect("object").clone();
    let mut hash_config = config.clone();
    hash_config.insert("managed_policy_hash".to_owned(), json!("sha256:abc"));
    hash_config.insert("managed_policy_status".to_owned(), json!("enforced"));
    hash_config.insert("sandbox_analysis".to_owned(), json!("audit"));
    HarnessView {
        mode: "enforce".to_owned(),
        config,
        hash_config,
        layers: Vec::new(),
        receipt_redaction_level: None,
    }
}

fn artifact() -> GuardArtifact {
    let intent = parse_package_intent("npm install left-pad", None, None, None, None)
        .expect("the command carries an intent");
    build_package_request_artifact(HARNESS, &intent, "/home/dev/.mcp.json", "project")
}

/// The evaluation the package lane settles before the policy is resolved: a
/// package request the policy holds for review, which a saved allow is read
/// against (`evaluate_approval_reuse`).
fn evaluation() -> Map<String, Value> {
    json!({
        "bundle_version": Value::Null,
        "decision": "review",
        "enforcement": "enforce",
        "entitlement_state": Value::Null,
        "exception_id": Value::Null,
        "matched_rule_id": Value::Null,
        "packages": [{"name": "left-pad", "ecosystem": "npm"}],
        "policy_action": "review",
        "policy_version": "1",
        // Every reason the package lane settles is a mapping, which the
        // resolution's strict parse requires and whose first entry carries the
        // reuse evidence a saved approval adds.
        "reasons": [{"code": "package_request"}],
    })
    .as_object()
    .expect("object")
    .clone()
}

fn environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("HOME".to_owned(), "/home/dev".to_owned()),
    ])
}

/// The advisory cache the approval hash reads, which the real store always
/// carries and `seed_store` does not.
fn publisher_cache(connection: &Connection) {
    connection
        .execute_batch(
            "create table publisher_cache (publisher_key text primary key,
               payload_json text not null, updated_at text not null);",
        )
        .unwrap();
}

/// A home whose store holds the advisory cache and one saved row, so every
/// lookup reads the rows rather than finding nothing saved at all.
fn home(tag: &str) -> (std::path::PathBuf, Connection) {
    let (home, connection) = guard_home(tag);
    publisher_cache(&connection);
    decide(&connection, "artifact", "block", None, "approval-gate");
    (home, connection)
}

/// The directory the relaying process reports, as `resolve(strict=False)`
/// leaves it, so the scope token the package lane probes resolves under it
/// rather than deferring on a directory Python would rewrite.
fn process_cwd(home: &Path) -> String {
    std::fs::canonicalize(home)
        .expect("the home exists")
        .to_str()
        .expect("the path is text")
        .to_owned()
}

/// What the relay resolves for the package call, on the read-only snapshot.
fn resolve(home: &Path, evaluation: &Map<String, Value>) -> Result<PackagePolicy, &'static str> {
    let connection = store::open(home)?.expect("store");
    let saved = store::saved(&connection, &binding(), home.to_str().unwrap(), HARNESS)?
        .expect("saved rows");
    let environment = environment();
    let cwd = process_cwd(home);
    package_policy(
        &saved,
        &view(),
        &artifact(),
        evaluation,
        "sha256:control",
        home.to_str().unwrap(),
        &ProcessFacts {
            environment: &environment,
            cwd: &cwd,
            home: "/home/dev",
        },
    )
}

#[cfg(unix)]
#[test]
fn a_saved_allow_for_the_bound_identity_is_reported_as_reused() {
    let (home, connection) = home("pkg-policy-allow");

    let miss = resolve(&home, &evaluation()).expect("the store is readable");
    assert!(miss.artifact_hash.starts_with("guard-approval-context:v1:"));
    assert!(miss.policy_workspace.is_some());
    assert!(miss.reused_decision.is_none());
    assert_eq!(miss.evaluation["packages"][0]["name"], "left-pad");

    // The durable artifact approval the proxy would read, bound to the token
    // the relay derived for this call.
    let artifact = artifact();
    decide_row(
        &connection,
        &Row {
            artifact_id: &artifact.artifact_id,
            artifact_hash: Some(&miss.artifact_hash),
            action: "allow",
            ..Row::default()
        },
    );
    let reused = resolve(&home, &evaluation()).expect("the store is readable");
    assert_eq!(reused.artifact_hash, miss.artifact_hash);
    assert_eq!(
        reused
            .reused_decision
            .as_ref()
            .and_then(|row| row["action"].as_str()),
        Some("allow")
    );
    assert_eq!(reused.evaluation["policy_action"], "allow");
    // Nothing was claimed: a relayed call reports the saved approval and the
    // row stays for the proxy to claim.
    assert_eq!(reused.claim_disposition.as_deref(), Some("retained"));
}

#[cfg(unix)]
#[test]
fn a_row_the_lookup_ignores_for_local_integrity_defers() {
    let (home, connection) = home("pkg-policy-ignored");
    let hash = resolve(&home, &evaluation())
        .expect("the store is readable")
        .artifact_hash;

    let artifact = artifact();
    decide_row(
        &connection,
        &Row {
            artifact_id: &artifact.artifact_id,
            artifact_hash: Some(&hash),
            action: "allow",
            unsigned: true,
            ..Row::default()
        },
    );
    // The proxy records the integrity violation as it reads the row, which the
    // read-only snapshot cannot write, so the lookup itself defers before the
    // resolution could answer in the daemon authority's place.
    assert_eq!(
        resolve(&home, &evaluation()).err(),
        Some("mcp_relay_saved_lookup_failed")
    );
}

#[cfg(unix)]
#[test]
fn an_evaluation_the_proxy_would_not_send_defers() {
    let (home, _connection) = home("pkg-policy-evaluation");
    let mut incomplete = evaluation();
    incomplete.remove("packages");
    assert_eq!(resolve(&home, &incomplete).err(), Some(EVALUATION_INVALID));
}

#[cfg(unix)]
#[test]
fn the_cached_advisory_feed_binds_the_approval_token() {
    let (home, connection) = home("pkg-policy-feed");
    let unbound = resolve(&home, &evaluation())
        .expect("the store is readable")
        .artifact_hash;

    connection
        .execute_batch(
            "create table guard_supply_chain_bundle_cache (workspace_id text primary key,
               response_json text not null, cached_at text not null);",
        )
        .unwrap();
    sync_state(
        &connection,
        "oauth_local_credentials",
        &json!({"workspace_id": "ws-1"}).to_string(),
    );
    connection
        .execute(
            "insert into guard_supply_chain_bundle_cache (workspace_id, response_json, cached_at)
             values (?1, ?2, ?3)",
            params![
                "ws-1",
                json!({"bundle": {"feedSnapshotHash": "sha256:feed"}}).to_string(),
                "2026-01-01T00:00:00+00:00"
            ],
        )
        .unwrap();

    let bound = resolve(&home, &evaluation())
        .expect("the store is readable")
        .artifact_hash;
    assert_ne!(bound, unbound);
}

#[test]
fn the_metadata_the_context_binds_is_read_by_type() {
    let facts = metadata_facts(&json!({
        "package_manager": "npm",
        "package_executable": 7,
        "flags": ["--force", 3, Value::Null],
        "manifest_paths": "package.json",
    }));
    assert_eq!(facts.package_manager.as_deref(), Some("npm"));
    // A key of the wrong type is read as absent, never coerced.
    assert_eq!(facts.package_executable, None);
    assert_eq!(facts.flags, vec!["--force".to_owned()]);
    assert!(facts.manifest_paths.is_empty());
    assert!(facts.lockfile_paths.is_empty());
}

#[cfg(unix)]
#[test]
fn a_malformed_cached_bundle_defers_rather_than_dropping_the_feed_binding() {
    let (home, connection) = home("pkg-policy-feed-malformed");
    connection
        .execute_batch(
            "create table guard_supply_chain_bundle_cache (workspace_id text primary key,
               response_json text not null, cached_at text not null);",
        )
        .unwrap();
    sync_state(
        &connection,
        "oauth_local_credentials",
        &json!({"workspace_id": "ws-1"}).to_string(),
    );
    connection
        .execute(
            "insert into guard_supply_chain_bundle_cache (workspace_id, response_json, cached_at)
             values (?1, ?2, ?3)",
            params!["ws-1", "{not json", "2026-01-01T00:00:00+00:00"],
        )
        .unwrap();

    // `get_supply_chain_bundle` raises on this row, so a context token composed
    // without the feed snapshot is not the one the proxy would bind.
    assert_eq!(resolve(&home, &evaluation()).err(), Some(RESOLVE_FAILED));
}

#[cfg(unix)]
#[test]
fn a_malformed_credential_payload_defers() {
    let (home, connection) = home("pkg-policy-credentials-malformed");
    sync_state(&connection, "oauth_local_credentials", "{not json");
    assert_eq!(resolve(&home, &evaluation()).err(), Some(RESOLVE_FAILED));
}
