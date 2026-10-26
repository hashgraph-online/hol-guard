//! An install records one authority transition per policy save, so the chain
//! the migration has to walk outgrows a single native request long before the
//! install is retired. These cover the spilled transport that carries it.
use super::super::{decode, migration};
use super::{installed, legacy_envelope, legacy_pending};
use serde_json::{json, Value};
use std::io::Write;

const REVISIONS: u64 = 520;

/// A chain of packless control edits on top of one pack-bearing commit, with
/// records the size the shipped daemon actually writes.
fn chain() -> (Value, Vec<Value>) {
    let authority = [8u8; 32];
    let filler = "l".repeat(13_000);
    let mut request = legacy_pending();
    request["legacy_activation"] = request["legacy_pending"]["activation"].clone();
    request["legacy_pending"] = Value::Null;
    let mut chain = vec![request["legacy_next_snapshot"].clone()];
    for revision in 2..=REVISIONS {
        let previous = chain.last().unwrap()["digest"].clone();
        chain.push(legacy_envelope(
            json!({"revision":revision,"previous_digest":previous,"layers_json":filler}),
            &authority,
            "extension-control.snapshot",
        ));
    }
    let head = chain.pop().unwrap();
    request["legacy_anchor"] = legacy_envelope(
        json!({"revision":REVISIONS,"snapshot_digest":head["digest"],"phase":"committed"}),
        &authority,
        "extension-control.anchor",
    );
    request["legacy_snapshot"] = head;
    request["legacy_history"] = json!([]);
    chain.reverse();
    (request, chain)
}

fn spill(directory: &std::path::Path, history: &[Value]) -> String {
    let path = directory.join("legacy-history.jsonl");
    let mut file = std::fs::File::create(&path).unwrap();
    for record in history {
        writeln!(file, "{}", serde_json::to_string(record).unwrap()).unwrap();
    }
    path.to_str().unwrap().to_string()
}

#[test]
fn a_history_too_large_to_inline_still_migrates_from_a_spilled_chain() {
    let key = [7u8; 32];
    let (mut request, history) = chain();
    let mut inline = request.clone();
    inline["legacy_history"] = json!(history);
    // Before the spill, this request was the whole migration: an install with
    // this much history could never state it, so the floor stayed missing and
    // every later refresh failed with it.
    assert!(
        serde_json::to_string(&inline).unwrap().len() > guard_contracts::MAX_NATIVE_REQUEST_BYTES
    );
    let directory = tempfile::tempdir().unwrap();
    request["legacy_history_path"] = json!(spill(directory.path(), &history));
    let migrated = migration::admit(&request, &key, installed()).unwrap();
    assert_eq!(
        decode(migrated["record"].as_str().unwrap(), &key)
            .unwrap()
            .remote
            .unwrap()
            .version,
        "100.7"
    );
}

#[test]
fn a_spilled_chain_still_has_to_authenticate_and_link_every_record() {
    let key = [7u8; 32];
    let directory = tempfile::tempdir().unwrap();
    let (request, history) = chain();
    let reject = |history: &[Value]| {
        let mut request = request.clone();
        request["legacy_history_path"] = json!(spill(directory.path(), history));
        migration::admit(&request, &key, installed()).unwrap_err()
    };
    let mut gap = history.clone();
    gap.remove(1);
    assert_eq!(reject(&gap), "pack_lifecycle_legacy_anchor_mismatch");
    let mut reordered = history.clone();
    reordered.swap(1, 2);
    assert_eq!(reordered.len(), history.len());
    assert_eq!(reject(&reordered), "pack_lifecycle_legacy_anchor_mismatch");
    let mut forged = history.clone();
    forged[1]["mac"] = json!("0".repeat(64));
    assert_eq!(
        reject(&forged),
        "pack_lifecycle_legacy_authentication_failed"
    );
    // A truncated chain never reaches the pack-bearing commit.
    assert_eq!(
        reject(&history[..history.len() - 1]),
        "pack_lifecycle_legacy_anchor_mismatch"
    );
    let mut request = request.clone();
    request["legacy_history_path"] = json!(directory.path().join("absent.jsonl").to_str().unwrap());
    assert_eq!(
        migration::admit(&request, &key, installed()).unwrap_err(),
        "pack_lifecycle_legacy_invalid"
    );
}
