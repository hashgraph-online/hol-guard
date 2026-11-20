use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use super::{answer, parse_record};

#[path = "installation_continuity_verify_tests.rs"]
mod verify;

const MACHINE: &str = "0123456789abcdef0123456789abcdef";
const GENERATION: &str = "fedcba9876543210fedcba9876543210";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn uninitialized() -> Value {
    json!({
        "schemaVersion": "hol-guard-installation-continuity.v1",
        "machineInstallationId": MACHINE,
        "installationGeneration": GENERATION,
        "generationCreatedAt": "2026-10-31T12:00:00.123456+00:00",
        "keyIdAtGenerationCreation": "active-key",
        "lastIssuedSequence": 0,
        "lastLeaseDigest": null,
        "lastLeaseBootSessionId": null,
        "lastLeaseMonotonicUptimeNs": null,
        "lastLeaseKeyId": null,
        "updatedAt": "2026-10-31T12:00:00.123456+00:00",
    })
}

fn issued(sequence: u64, boot: &str, uptime: u64) -> Value {
    let mut record = uninitialized();
    record["lastIssuedSequence"] = json!(sequence);
    record["lastLeaseDigest"] = json!(DIGEST);
    record["lastLeaseBootSessionId"] = json!(boot);
    record["lastLeaseMonotonicUptimeNs"] = json!(uptime);
    record["lastLeaseKeyId"] = json!("active-key");
    record
}

fn encoded(record: &Value) -> String {
    STANDARD.encode(serde_json::to_vec(record).expect("record"))
}

fn run(mut request: Value) -> Value {
    request["schema"] = json!("installation-continuity.v1");
    answer(&serde_json::to_vec(&request).expect("request")).expect("request is well formed")
}

fn parsed(record: &Value) -> Value {
    run(json!({"op": "parse", "content": encoded(record)}))
}

fn is_invalid(record: &Value) -> bool {
    parsed(record) == json!({"ok": false, "error": "installation_identity_invalid"})
}

fn keys(ids: &[&str]) -> Value {
    json!({"ids": ids})
}

fn raised(kind: &str, error: &str) -> Value {
    json!({"kind": kind, "error": error})
}

fn boot(id: &str, uptime: u64) -> Value {
    json!({"boot_session_id": id, "monotonic_uptime_ns": uptime})
}

fn verified(record: &Value, key: Value, observation: Value) -> Value {
    run(json!({"op": "verify", "content": encoded(record), "key": key, "boot": observation}))
}

/// `(state, identity reason, lease reason, carries the record, observed)`.
fn outcome(answer: &Value) -> (&str, &str, &str, bool, bool) {
    (
        answer["state"].as_str().expect("state"),
        answer["identity_reason_code"].as_str().expect("identity"),
        answer["lease_reason_code"].as_str().expect("lease"),
        !answer["record"].is_null(),
        answer["observed"].as_bool().expect("observed"),
    )
}

#[test]
fn an_uninitialized_record_parses_with_the_dataclass_field_names() {
    let answer = parsed(&uninitialized());
    assert_eq!(answer["ok"], json!(true));
    assert_eq!(
        answer["record"],
        json!({
            "machine_installation_id": MACHINE,
            "installation_generation": GENERATION,
            "generation_created_at": "2026-10-31T12:00:00.123456+00:00",
            "key_id_at_generation_creation": "active-key",
            "last_issued_sequence": 0,
            "last_lease_digest": null,
            "last_lease_boot_session_id": null,
            "last_lease_monotonic_uptime_ns": null,
            "updated_at": "2026-10-31T12:00:00.123456+00:00",
            "last_lease_key_id": null,
        })
    );
}

#[test]
fn an_issued_record_keeps_every_lease_field() {
    let answer = parsed(&issued(u64::MAX, "boot-a", 7));
    assert_eq!(answer["record"]["last_issued_sequence"], json!(u64::MAX));
    assert_eq!(answer["record"]["last_lease_digest"], json!(DIGEST));
    assert_eq!(
        answer["record"]["last_lease_boot_session_id"],
        json!("boot-a")
    );
    assert_eq!(answer["record"]["last_lease_monotonic_uptime_ns"], json!(7));
    assert_eq!(answer["record"]["last_lease_key_id"], json!("active-key"));
}

#[test]
fn a_v1_record_without_the_lease_key_field_stays_readable() {
    let mut record = uninitialized();
    record
        .as_object_mut()
        .expect("object")
        .remove("lastLeaseKeyId");
    assert_eq!(parsed(&record)["ok"], json!(true));
}

#[test]
fn unknown_keys_are_ignored_and_the_last_duplicate_wins() {
    let mut record = uninitialized();
    record["futureField"] = json!([1, 2]);
    assert_eq!(parsed(&record)["ok"], json!(true));
    let text = serde_json::to_string(&uninitialized())
        .expect("record")
        .replacen('{', "{\"lastIssuedSequence\":-1,", 1);
    let answer = run(json!({"op": "parse", "content": STANDARD.encode(text)}));
    assert_eq!(answer["record"]["last_issued_sequence"], json!(0));
}

#[test]
fn malformed_documents_are_invalid() {
    let payloads: [&[u8]; 5] = [
        b"",
        b"not json",
        b"[]",
        b"\xff\xfe",
        b"{\"schemaVersion\": \"hol-guard-installation-continuity.v1\"}",
    ];
    for payload in payloads {
        assert!(parse_record(payload).is_none());
    }
    assert!(parse_record(&vec![b' '; 64 * 1024 + 1]).is_none());
}

#[test]
fn every_field_is_checked_like_the_python_reader() {
    let cases: Vec<(&str, Value)> = vec![
        ("schemaVersion", json!("wrong")),
        ("schemaVersion", Value::Null),
        ("lastIssuedSequence", json!(-1)),
        ("lastIssuedSequence", json!(1.0)),
        ("lastIssuedSequence", json!(true)),
        ("lastIssuedSequence", json!("0")),
        ("lastIssuedSequence", Value::Null),
        (
            "machineInstallationId",
            json!("0123456789ABCDEF0123456789ABCDEF"),
        ),
        ("machineInstallationId", json!("0123")),
        ("machineInstallationId", Value::Null),
        (
            "installationGeneration",
            json!(GENERATION.replace('f', "g")),
        ),
        ("generationCreatedAt", json!("2026-10-31T12:00:00")),
        ("generationCreatedAt", json!("not a time")),
        ("generationCreatedAt", json!(12)),
        (
            "updatedAt",
            json!(format!("2026-10-31T12:00:00+00:00{}", " ".repeat(40))),
        ),
        ("keyIdAtGenerationCreation", json!("")),
        ("keyIdAtGenerationCreation", json!("k".repeat(257))),
        ("keyIdAtGenerationCreation", json!(7)),
        ("keyIdAtGenerationCreation", Value::Null),
    ];
    for (key, value) in cases {
        let mut record = uninitialized();
        record[key] = value.clone();
        assert!(is_invalid(&record), "{key} = {value}");
    }
}

#[test]
fn timestamps_accept_any_aware_isoformat_within_the_bound() {
    for text in [
        "2026-10-31T12:00:00Z",
        "2026-10-31T12:00:00-07:00",
        "2026-10-31T12:00:00.123+05:30",
    ] {
        let mut record = uninitialized();
        record["updatedAt"] = json!(text);
        assert_eq!(parsed(&record)["record"]["updated_at"], json!(text));
    }
}

#[test]
fn bounded_strings_count_characters_not_bytes() {
    let mut record = uninitialized();
    record["keyIdAtGenerationCreation"] = json!("é".repeat(256));
    assert_eq!(parsed(&record)["ok"], json!(true));
    record["keyIdAtGenerationCreation"] = json!("é".repeat(257));
    assert!(is_invalid(&record));
}

#[test]
fn lease_fields_must_match_the_sequence() {
    for key in [
        "lastLeaseDigest",
        "lastLeaseBootSessionId",
        "lastLeaseMonotonicUptimeNs",
        "lastLeaseKeyId",
    ] {
        let mut record = issued(3, "boot-a", 9);
        record[key] = Value::Null;
        assert!(is_invalid(&record), "issued without {key}");
        let mut record = uninitialized();
        record[key] = issued(3, "boot-a", 9)[key].clone();
        assert!(is_invalid(&record), "uninitialized with {key}");
    }
}

#[test]
fn lease_values_are_bounded_and_typed() {
    let cases: Vec<(&str, Value)> = vec![
        ("lastLeaseDigest", json!("A".repeat(64))),
        ("lastLeaseDigest", json!("a".repeat(63))),
        ("lastLeaseDigest", json!("")),
        ("lastLeaseBootSessionId", json!("")),
        ("lastLeaseBootSessionId", json!("b".repeat(257))),
        ("lastLeaseBootSessionId", json!(4)),
        ("lastLeaseMonotonicUptimeNs", json!(-1)),
        ("lastLeaseMonotonicUptimeNs", json!("9")),
        ("lastLeaseKeyId", json!([])),
    ];
    for (key, value) in cases {
        let mut record = issued(3, "boot-a", 9);
        record[key] = value.clone();
        assert!(is_invalid(&record), "{key} = {value}");
    }
    let text = serde_json::to_string(&issued(3, "boot-a", 9))
        .expect("record")
        .replace(
            "\"lastLeaseMonotonicUptimeNs\":9",
            "\"lastLeaseMonotonicUptimeNs\":18446744073709551616",
        );
    assert!(parse_record(text.as_bytes()).is_none());
}
