//! The claim must refuse evidence gathered before the write lock whose
//! sources changed before the claim committed. Each case starts from a
//! recorded vector that claims successfully, binds the evidence to the store the
//! way a caller does, then moves exactly one source.

use guard_contracts::{ClaimDeviceBindingV1, ClaimEvidenceBindingV1};
use guard_policy_snapshot::digest_bytes;
use rusqlite::{params, Connection};
use serde_json::Value;

use crate::claim_reuse::{claim_approval_reuse_decisions, ClaimEvidence};
use crate::claim_reuse_binding::{evidence_is_bound, BUNDLE_STATE_KEYS};
use crate::store_vectors_support_tests::{decode_key, dump_store, gunzip_json, seeded_store};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/claim_vectors.json.gz");
const LOCAL_POLICY: &str = "pol-basic-approval-gate-False";
const BUNDLE_POLICY: &str = "remote-bundle-identity-match-True";

struct Case {
    connection: Connection,
    request: Value,
    binding: ClaimEvidenceBindingV1,
}

fn put_state(connection: &Connection, key: &str, payload: &str) {
    connection
        .execute(
            "insert or replace into sync_state (state_key, payload_json) values (?1, ?2)",
            params![key, payload],
        )
        .unwrap();
}

fn case(id: &str) -> Case {
    let document = gunzip_json(VECTORS);
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["id"] == id)
        .unwrap_or_else(|| panic!("vector {id} missing"))
        .clone();
    assert_eq!(vector["expected"]["claimed"], Value::Bool(true));
    let connection = seeded_store(&document["schema_sql"], &vector["seed"]);
    connection
        .execute_batch(
            "create table sync_state (state_key text primary key, payload_json text not null);
             create table guard_devices (
               device_key text primary key, installation_id text not null, device_label text not null
             );
             insert into guard_devices values ('local-device', 'install-1', 'laptop');",
        )
        .unwrap();
    let request = vector["request"].clone();
    let mut binding = ClaimEvidenceBindingV1::default();
    if !request["integrity_state"].is_null() {
        put_state(
            &connection,
            "policy_integrity",
            &request["integrity_state"].to_string(),
        );
    }
    if request["policy_bundle_decision_identities"].is_array() {
        for key in BUNDLE_STATE_KEYS {
            let payload = format!("{{\"{key}\":1}}");
            put_state(&connection, key, &payload);
            binding
                .sync_state_sha256
                .insert(key.to_owned(), Some(digest_bytes(payload.as_bytes())));
        }
        put_state(
            &connection,
            "oauth_local_credentials",
            r#"{"workspace_id":"workspace-1"}"#,
        );
        binding.cloud_workspace_id = Some("workspace-1".to_owned());
        binding.device = Some(ClaimDeviceBindingV1 {
            installation_id: "install-1".to_owned(),
            device_label: "laptop".to_owned(),
        });
    }
    Case {
        connection,
        request,
        binding,
    }
}

/// Run the claim the way the op does, with the supplied binding.
fn claim(case: &Case, binding: Option<&ClaimEvidenceBindingV1>) -> bool {
    let request = &case.request;
    let policy_key = decode_key(&request["integrity_key_b64"]);
    let local_key = decode_key(&request["local_once_integrity_key_b64"]);
    let identities: Option<Vec<Vec<Value>>> = request["policy_bundle_decision_identities"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|row| row.as_array().cloned().unwrap_or_default())
                .collect()
        });
    let state = (!request["integrity_state"].is_null()).then(|| request["integrity_state"].clone());
    let evidence = ClaimEvidence {
        integrity_state: state.as_ref(),
        integrity_key: policy_key.as_deref(),
        integrity_key_id: request["integrity_key_id"].as_str(),
        local_once_key: local_key.as_deref(),
        local_once_key_id: request["local_once_integrity_key_id"].as_str(),
        policy_bundle_identities: identities.as_deref(),
    };
    let now = guard_contracts::canonical_utc_timestamp(request["now"].as_str().unwrap())
        .expect("recorded now must canonicalize");
    claim_approval_reuse_decisions(
        &case.connection,
        request["decisions"].as_array().unwrap(),
        &now,
        &evidence,
        &|connection, members| evidence_is_bound(connection, members, &evidence, binding),
    )
    .unwrap()
}

/// A refused claim must leave the single-use authority exactly as it was.
fn assert_refused_and_untouched(case: &Case, binding: Option<&ClaimEvidenceBindingV1>) {
    let before = dump_store(&case.connection);
    assert!(!claim(case, binding), "claim must be refused");
    assert_eq!(
        dump_store(&case.connection),
        before,
        "refusal must not write"
    );
}

#[test]
fn unchanged_sources_still_claim() {
    let local = case(LOCAL_POLICY);
    assert!(claim(&local, Some(&local.binding)));
    let bundle = case(BUNDLE_POLICY);
    assert!(claim(&bundle, Some(&bundle.binding)));
}

#[test]
fn evidence_without_a_binding_is_never_trusted() {
    assert_refused_and_untouched(&case(LOCAL_POLICY), None);
    assert_refused_and_untouched(&case(BUNDLE_POLICY), None);
}

#[test]
fn integrity_state_changed_after_gathering_refuses_the_claim() {
    let local = case(LOCAL_POLICY);
    let mut moved = local.request["integrity_state"].clone();
    moved["generation"] = Value::from(moved["generation"].as_i64().unwrap_or(0) + 1);
    put_state(&local.connection, "policy_integrity", &moved.to_string());
    assert_refused_and_untouched(&local, Some(&local.binding));
}

#[test]
fn integrity_state_that_vanished_refuses_the_claim() {
    let local = case(LOCAL_POLICY);
    local
        .connection
        .execute(
            "delete from sync_state where state_key = 'policy_integrity'",
            [],
        )
        .unwrap();
    assert_refused_and_untouched(&local, Some(&local.binding));
}

#[test]
fn key_that_does_not_match_its_identity_refuses_the_claim() {
    let mut local = case(LOCAL_POLICY);
    // A different key under the identity the state still names.
    local.request["integrity_key_b64"] = Value::from("A".repeat(43));
    assert_refused_and_untouched(&local, Some(&local.binding));
}

#[test]
fn key_identity_that_disagrees_with_the_persisted_state_refuses_the_claim() {
    let mut local = case(LOCAL_POLICY);
    // The state is still the persisted one, but names another key than the one shipped.
    local.request["integrity_state"]["key_id"] =
        Value::from("guard-policy-integrity-key:other:0000000000000000");
    put_state(
        &local.connection,
        "policy_integrity",
        &local.request["integrity_state"].to_string(),
    );
    assert_refused_and_untouched(&local, Some(&local.binding));
}

#[test]
fn every_bundle_source_changed_after_gathering_refuses_the_claim() {
    for key in BUNDLE_STATE_KEYS {
        let bundle = case(BUNDLE_POLICY);
        put_state(&bundle.connection, key, r#"{"swapped":true}"#);
        assert_refused_and_untouched(&bundle, Some(&bundle.binding));
    }
}

#[test]
fn bundle_source_that_vanished_refuses_the_claim() {
    for key in BUNDLE_STATE_KEYS {
        let bundle = case(BUNDLE_POLICY);
        bundle
            .connection
            .execute("delete from sync_state where state_key = ?1", params![key])
            .unwrap();
        assert_refused_and_untouched(&bundle, Some(&bundle.binding));
    }
}

#[test]
fn bundle_workspace_or_device_changed_after_gathering_refuses_the_claim() {
    let workspace = case(BUNDLE_POLICY);
    put_state(
        &workspace.connection,
        "oauth_local_credentials",
        r#"{"workspace_id":"workspace-2"}"#,
    );
    assert_refused_and_untouched(&workspace, Some(&workspace.binding));

    let device = case(BUNDLE_POLICY);
    device
        .connection
        .execute("update guard_devices set installation_id = 'install-2'", [])
        .unwrap();
    assert_refused_and_untouched(&device, Some(&device.binding));
}

#[test]
fn binding_that_omits_a_required_bundle_source_refuses_the_claim() {
    for key in BUNDLE_STATE_KEYS {
        let bundle = case(BUNDLE_POLICY);
        let mut partial = bundle.binding.clone();
        partial.sync_state_sha256.remove(key);
        assert_refused_and_untouched(&bundle, Some(&partial));
    }
}
