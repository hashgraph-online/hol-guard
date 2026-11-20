//! Pins `write_anchor`: the vault moves onto a prepared row only while that
//! row carries no authority of its own, and onto the committed head only
//! when the vault already names it. Everything else is refused with the
//! vault untouched.

use guard_contracts::ExtensionControlAuthorityRequestV1;
use rusqlite::params;
use serde_json::{json, Value};

use super::super::resume::{anchor_ref, resolved_home};
use super::super::seals::LAST_GOOD_FILE_NAME;
use super::super::tests::{anchor, catalog, local, run, Home};
use crate::encrypted_secret_store::EncryptedFileSecretStore;

fn snapshot_digest(home: &Home, revision: i64) -> String {
    home.db
        .query_row(
            "select snapshot_digest from extension_control_authority_transition where revision = ?",
            params![revision],
            |row| row.get(0),
        )
        .unwrap()
}

fn vault_anchor(home: &Home) -> Option<String> {
    let resolved = resolved_home(&home.root.to_string_lossy());
    EncryptedFileSecretStore::new(&resolved).get_secret(&anchor_ref(&resolved))
}

fn write(
    home: &Home,
    current: Option<String>,
    revision: i64,
    digest: &str,
    phase: &str,
) -> ExtensionControlAuthorityRequestV1 {
    ExtensionControlAuthorityRequestV1 {
        anchor_json: current,
        revision: Some(revision),
        snapshot_digest: Some(digest.to_owned()),
        phase: Some(phase.to_owned()),
        ..home.request("write_anchor", &catalog('a'))
    }
}

fn parse(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn refusal(result: &Value) -> &str {
    assert_eq!(result["fault"], json!("tampered"), "{result}");
    result["reason"].as_str().unwrap()
}

/// Revision 1 committed and revision 2 prepared above it.
fn prepared() -> (Home, String) {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    (home, head)
}

#[test]
fn the_vault_moves_onto_a_prepared_row_the_committed_head_still_pins() {
    let (home, head) = prepared();
    let digest = snapshot_digest(&home, 2);
    let reply = run(&write(&home, Some(head), 2, &digest, "anchored"));
    let sealed = reply["anchor_json"].as_str().unwrap().to_owned();
    assert_eq!(parse(&sealed), parse(&anchor(2, &digest, "anchored")));
    assert_eq!(vault_anchor(&home), Some(sealed));
    assert!(!home.root.join(LAST_GOOD_FILE_NAME).exists());
}

#[test]
fn the_vault_commits_the_head_it_already_names() {
    let home = Home::new();
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let digest = snapshot_digest(&home, 1);
    let current = anchor(1, &digest, "anchored");
    let reply = run(&write(&home, Some(current), 1, &digest, "committed"));
    let sealed = reply["anchor_json"].as_str().unwrap().to_owned();
    assert_eq!(parse(&sealed), parse(&anchor(1, &digest, "committed")));
    assert_eq!(vault_anchor(&home), Some(sealed));
    assert!(home.root.join(LAST_GOOD_FILE_NAME).is_file());
}

#[test]
fn an_anchor_the_store_has_not_earned_is_refused_with_the_vault_untouched() {
    let (home, head) = prepared();
    let digest = snapshot_digest(&home, 2);
    let head_digest = snapshot_digest(&home, 1);
    let moved = anchor(2, &digest, "anchored");
    for request in [
        // Another snapshot than the prepared row seals.
        write(&home, Some(head.clone()), 2, &catalog('d'), "anchored"),
        // No row at that revision.
        write(&home, Some(head.clone()), 3, &digest, "anchored"),
        // A prepared anchor is never written.
        write(&home, Some(head.clone()), 2, &digest, "prepared"),
        // The vault already moved past the committed head.
        write(&home, Some(moved.clone()), 2, &digest, "anchored"),
        // The vault does not name the committed head.
        write(&home, None, 2, &digest, "anchored"),
        // The prepared row is not the committed head.
        write(&home, Some(moved), 2, &digest, "committed"),
        // The committed head, but the vault names nothing.
        write(&home, None, 1, &head_digest, "committed"),
        // The committed revision with another snapshot.
        write(&home, Some(head), 1, &catalog('d'), "committed"),
    ] {
        let result = run(&request);
        assert_eq!(
            refusal(&result),
            "extension control anchor not earned",
            "{request:?}"
        );
    }
    assert_eq!(vault_anchor(&home), None);
}

#[test]
fn a_malformed_anchor_request_is_refused() {
    let (home, head) = prepared();
    let digest = snapshot_digest(&home, 2);
    let request = write(&home, Some(head), 2, &digest, "anchored");
    for bad in [
        ExtensionControlAuthorityRequestV1 {
            phase: Some("finished".to_owned()),
            ..request.clone()
        },
        ExtensionControlAuthorityRequestV1 {
            revision: Some(-1),
            ..request.clone()
        },
        ExtensionControlAuthorityRequestV1 {
            snapshot_digest: Some("short".to_owned()),
            ..request.clone()
        },
    ] {
        assert_eq!(refusal(&run(&bad)), "invalid authority anchor");
    }
    let keyless = ExtensionControlAuthorityRequestV1 {
        key_b64: None,
        ..request
    };
    assert_eq!(
        refusal(&run(&keyless)),
        "extension control authentication key missing"
    );
    assert_eq!(vault_anchor(&home), None);
}
