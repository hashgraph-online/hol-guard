use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::encoding::{der_encode, utc_instant, P256_HALF_ORDER, P256_ORDER};
use super::run_command;
use crate::health_snapshot_binding::tests::snapshot;

const KEY_ID: &str = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk";
const LOW: [u8; 32] = [0x11; 32];
const HIGH_BIT: [u8; 32] = [0x90; 32];

/// The smallest `s` a lease may not carry: one past half the group order.
fn high_s() -> [u8; 32] {
    let mut high = P256_HALF_ORDER;
    high[31] += 1;
    high
}

fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    guard_contracts::write_canonical_json(value, &mut bytes).expect("canonical");
    bytes
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn snapshot_bytes() -> Vec<u8> {
    canonical(&snapshot())
}

/// Health lease claims bound to the shared test snapshot.
fn health_claims() -> Value {
    json!({
        "schemaVersion": "hol-guard-health-lease.v1",
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "machineInstallationId": "1".repeat(32),
        "installationGeneration": "2".repeat(32),
        "sequence": 1,
        "issuedAt": "2026-07-18T14:00:00Z",
        "leaseExpiresAt": "2026-07-18T14:30:00Z",
        "snapshotSchemaVersion": "local-integrity-snapshot.v1",
        "snapshotDigest": sha256_hex(&snapshot_bytes()),
        "previousLeaseDigest": null,
        "previousLeaseKeyId": null,
        "signingKeyId": KEY_ID,
    })
}

fn challenge() -> Value {
    json!({
        "challengeId": "challenge-1",
        "issuedAt": "2026-07-18T13:59:50.5Z",
        "nonce": "n".repeat(32),
        "validForSeconds": 60,
    })
}

fn protection_claims() -> Value {
    json!({
        "workspaceId": "workspace-a",
        "deviceId": "device-a",
        "machineInstallationId": "1".repeat(32),
        "installationGeneration": "2".repeat(32),
        "sequence": 1,
        "issuedAt": "2026-07-18T14:00:00Z",
        "validForSeconds": 600,
        "snapshotSchemaVersion": "local-integrity-snapshot.v1",
        "snapshotDigest": sha256_hex(&snapshot_bytes()),
        "previousLeaseDigest": null,
        "signingKeyId": KEY_ID,
        "challenge": challenge(),
    })
}

fn health_lease(claims: Value, der: &[u8]) -> Value {
    json!({
        "claims": claims,
        "signature": {
            "algorithm": "ecdsa-p256-sha256",
            "encoding": "asn1-der",
            "value": STANDARD.encode(der),
        },
    })
}

fn protection_lease(claims: Value, r: &[u8; 32], s: &[u8; 32]) -> Value {
    json!({
        "schemaVersion": "protection-lease.v1",
        "claims": claims,
        "signature": {
            "algorithm": "ecdsa-p256-sha256",
            "keyId": KEY_ID,
            "value": STANDARD.encode([r.as_slice(), s.as_slice()].concat()),
        },
    })
}

fn outbox(lease: &Value, snapshot: &[u8]) -> Value {
    json!({
        "schemaVersion": "hol-guard-health-lease-outbox.v1",
        "lease": lease,
        "leaseDigest": sha256_hex(&canonical(lease)),
        "snapshot": STANDARD.encode(snapshot),
    })
}

fn run(request: &Value) -> Result<Value, String> {
    run_command(serde_json::to_vec(request).expect("request").as_slice())
        .map(|bytes| serde_json::from_slice(&bytes).expect("answer"))
}

fn check(op: &str, value: Value) -> Value {
    run(&json!({"schema": "health-lease-contract.v1", "op": op, "value": value})).expect("answer")
}

fn parse(op: &str, payload: &[u8]) -> Value {
    run(&json!({
        "schema": "health-lease-contract.v1",
        "op": op,
        "payload": STANDARD.encode(payload),
    }))
    .expect("answer")
}

fn refused(reason_code: &str) -> Value {
    json!({"ok": false, "reason_code": reason_code})
}

fn with(mut value: Value, pointer: &str, replacement: Value) -> Value {
    *value.pointer_mut(pointer).expect("pointer") = replacement;
    value
}

#[test]
fn health_claims_in_contract_are_accepted() {
    assert_eq!(check("health-claims", health_claims()), json!({"ok": true}));
    let chained = with(
        with(health_claims(), "/sequence", json!(2)),
        "/previousLeaseDigest",
        json!("a".repeat(64)),
    );
    let chained = with(chained, "/previousLeaseKeyId", json!(KEY_ID));
    assert_eq!(check("health-claims", chained), json!({"ok": true}));
}

#[test]
fn health_claims_outside_the_contract_are_refused() {
    let mutations = [
        ("/schemaVersion", json!("hol-guard-health-lease.v0")),
        ("/sequence", json!(0)),
        ("/sequence", json!(1.0)),
        ("/sequence", json!(true)),
        ("/previousLeaseDigest", json!("a".repeat(64))),
        ("/previousLeaseKeyId", json!(KEY_ID)),
        ("/issuedAt", json!("2026-07-18T14:00:00.000Z")),
        ("/issuedAt", json!("2026-07-18T14:00:00+00:00")),
        ("/issuedAt", json!("2026-07-18T14:30:00Z")),
        ("/leaseExpiresAt", json!("2026-07-18T15:00:01Z")),
        ("/leaseExpiresAt", json!("2026-02-30T14:10:00Z")),
        ("/issuedAt", json!("0000-07-18T14:00:00Z")),
        ("/workspaceId", json!("-workspace")),
        ("/deviceId", json!("d".repeat(129))),
        ("/machineInstallationId", json!("A".repeat(32))),
        ("/snapshotDigest", json!("a".repeat(63))),
        ("/signingKeyId", json!("k".repeat(42))),
        (
            "/snapshotSchemaVersion",
            json!("local-integrity-snapshot.v0"),
        ),
    ];
    for (pointer, value) in mutations {
        assert_eq!(
            check(
                "health-claims",
                with(health_claims(), pointer, value.clone())
            ),
            refused("health_lease_invalid"),
            "{pointer} = {value}"
        );
    }
    let unchained = with(health_claims(), "/sequence", json!(2));
    let mut extra = health_claims();
    extra["note"] = json!("x");
    let mut missing = health_claims();
    missing
        .as_object_mut()
        .expect("object")
        .remove("previousLeaseKeyId");
    for claims in [unchained, extra, missing, json!([])] {
        assert_eq!(
            check("health-claims", claims),
            refused("health_lease_invalid")
        );
    }
}

#[test]
fn protection_claims_with_or_without_a_challenge_are_accepted() {
    assert_eq!(
        check("protection-claims", protection_claims()),
        json!({"ok": true})
    );
    assert_eq!(
        check(
            "protection-claims",
            with(protection_claims(), "/challenge", Value::Null)
        ),
        json!({"ok": true})
    );
    assert_eq!(
        check("protection-challenge", challenge()),
        json!({"ok": true})
    );
}

#[test]
fn a_lease_issued_outside_its_challenge_window_names_the_challenge() {
    for issued in ["2026-07-18T13:59:50Z", "2026-07-18T14:00:51Z"] {
        assert_eq!(
            check(
                "protection-claims",
                with(protection_claims(), "/issuedAt", json!(issued))
            ),
            refused("health_lease_challenge_invalid"),
            "{issued}"
        );
    }
}

#[test]
fn a_malformed_challenge_is_refused_as_a_challenge() {
    let mutations = [
        ("/nonce", json!("n".repeat(31))),
        ("/nonce", json!(format!("{}=", "n".repeat(32)))),
        ("/validForSeconds", json!(29)),
        ("/validForSeconds", json!(301)),
        ("/issuedAt", json!("2026-07-18T13:59:50.Z")),
        ("/issuedAt", json!("2026-07-18T13:59:50")),
        ("/issuedAt", json!("2026-13-18T13:59:50Z")),
    ];
    for (pointer, value) in mutations {
        assert_eq!(
            check(
                "protection-challenge",
                with(challenge(), pointer, value.clone())
            ),
            refused("health_lease_challenge_invalid"),
            "{pointer} = {value}"
        );
    }
    let mut extra = challenge();
    extra["note"] = json!("x");
    assert_eq!(
        check(
            "protection-claims",
            with(protection_claims(), "/challenge", extra)
        ),
        refused("health_lease_challenge_invalid")
    );
    assert_eq!(
        check(
            "protection-challenge",
            with(challenge(), "/challengeId", json!(".challenge"))
        ),
        refused("health_lease_invalid")
    );
}

#[test]
fn protection_claims_outside_the_contract_are_refused() {
    let mutations = [
        ("/validForSeconds", json!(179)),
        ("/validForSeconds", json!(1801)),
        ("/sequence", json!(0)),
        ("/previousLeaseDigest", json!("a".repeat(64))),
        ("/issuedAt", json!("2026-07-18T14:00:00.5Z")),
        ("/snapshotSchemaVersion", json!("other")),
        ("/signingKeyId", json!("k+".repeat(21) + "k")),
    ];
    for (pointer, value) in mutations {
        assert_eq!(
            check(
                "protection-claims",
                with(protection_claims(), pointer, value.clone())
            ),
            refused("health_lease_invalid"),
            "{pointer} = {value}"
        );
    }
    assert_eq!(
        check(
            "protection-claims",
            with(protection_claims(), "/sequence", json!(2))
        ),
        refused("health_lease_invalid")
    );
}

#[test]
fn a_signed_health_lease_returns_its_claims_and_signature() {
    let der = der_encode(&HIGH_BIT, &LOW);
    let lease = health_lease(health_claims(), &der);

    assert_eq!(
        parse("health-lease", &canonical(&lease)),
        json!({
            "ok": true,
            "kind": "health",
            "claims": health_claims(),
            "signature": STANDARD.encode(&der),
        })
    );
}

#[test]
fn a_health_lease_signature_must_be_canonical_low_s_der() {
    let mut padded = vec![0x30, 0x45, 0x02, 0x21, 0x00];
    padded.extend_from_slice(&LOW);
    padded.extend_from_slice(&[0x02, 0x20]);
    padded.extend_from_slice(&LOW);
    let mut trailing = der_encode(&LOW, &LOW);
    trailing.push(0);
    trailing[1] += 1;
    for der in [
        der_encode(&LOW, &high_s()),
        der_encode(&P256_ORDER, &LOW),
        der_encode(&[0; 32], &LOW),
        padded,
        trailing,
        Vec::new(),
    ] {
        let lease = health_lease(health_claims(), &der);
        assert_eq!(
            parse("health-lease", &canonical(&lease)),
            refused("health_lease_invalid"),
            "{}",
            hex::encode(&der)
        );
    }
    assert_eq!(
        parse(
            "health-lease",
            &canonical(&health_lease(
                health_claims(),
                &der_encode(&LOW, &P256_HALF_ORDER)
            ))
        )["ok"],
        json!(true)
    );
}

#[test]
fn a_health_lease_outside_its_canonical_spelling_is_refused() {
    let lease = health_lease(health_claims(), &der_encode(&LOW, &LOW));
    let unpadded = with(
        lease.clone(),
        "/signature/value",
        json!(STANDARD
            .encode(der_encode(&LOW, &LOW))
            .trim_end_matches('=')),
    );
    let wrong_encoding = with(lease.clone(), "/signature/encoding", json!("raw"));
    let wrong_claims = with(lease.clone(), "/claims/sequence", json!(0));
    for refused_lease in [unpadded, wrong_encoding, wrong_claims] {
        assert_eq!(
            parse("health-lease", &canonical(&refused_lease)),
            refused("health_lease_invalid")
        );
    }
    let pretty = serde_json::to_vec_pretty(&lease).expect("pretty");
    assert_eq!(
        parse("health-lease", &pretty),
        refused("health_lease_invalid")
    );
}

#[test]
fn a_signed_protection_lease_returns_its_signature_as_der() {
    let lease = protection_lease(protection_claims(), &HIGH_BIT, &P256_HALF_ORDER);

    assert_eq!(
        parse("protection-lease", &canonical(&lease)),
        json!({
            "ok": true,
            "kind": "protection",
            "claims": protection_claims(),
            "signature": STANDARD.encode(der_encode(&HIGH_BIT, &P256_HALF_ORDER)),
        })
    );
}

#[test]
fn a_protection_lease_needs_a_low_s_signature_by_its_signing_key() {
    let refused_leases = [
        protection_lease(protection_claims(), &LOW, &high_s()),
        protection_lease(protection_claims(), &P256_ORDER, &LOW),
        protection_lease(protection_claims(), &[0; 32], &LOW),
        with(
            protection_lease(protection_claims(), &LOW, &LOW),
            "/signature/keyId",
            json!("j".repeat(43)),
        ),
        with(
            protection_lease(protection_claims(), &LOW, &LOW),
            "/signature/value",
            json!(STANDARD.encode([0x11; 63])),
        ),
        with(
            protection_lease(protection_claims(), &LOW, &LOW),
            "/schemaVersion",
            json!("protection-lease.v0"),
        ),
    ];
    for lease in refused_leases {
        assert_eq!(
            parse("protection-lease", &canonical(&lease)),
            refused("health_lease_invalid"),
            "{lease}"
        );
    }
    let late = with(
        protection_lease(protection_claims(), &LOW, &LOW),
        "/claims/issuedAt",
        json!("2026-07-18T14:05:00Z"),
    );
    assert_eq!(
        parse("protection-lease", &canonical(&late)),
        refused("health_lease_challenge_invalid")
    );
}

#[test]
fn an_outbox_returns_its_lease_and_the_snapshot_it_signs_for() {
    let snapshot = snapshot_bytes();
    let health = health_lease(health_claims(), &der_encode(&LOW, &LOW));
    let protection = protection_lease(protection_claims(), &LOW, &LOW);

    let answer = parse("outbox", &canonical(&outbox(&health, &snapshot)));
    assert_eq!(answer["ok"], json!(true));
    assert_eq!(answer["kind"], json!("health"));
    assert_eq!(answer["claims"], health_claims());
    assert_eq!(answer["snapshot"], json!(STANDARD.encode(&snapshot)));

    let answer = parse("outbox", &canonical(&outbox(&protection, &snapshot)));
    assert_eq!(answer["kind"], json!("protection"));
    assert_eq!(
        answer["signature"],
        json!(STANDARD.encode(der_encode(&LOW, &LOW)))
    );
}

#[test]
fn an_outbox_that_does_not_carry_its_own_lease_and_snapshot_is_refused() {
    let other_snapshot = canonical(&with(
        snapshot(),
        "/identifiers/workspaceId",
        json!("workspace-b"),
    ));
    let snapshot = snapshot_bytes();
    let lease = health_lease(health_claims(), &der_encode(&LOW, &LOW));
    let rebound = health_lease(
        with(
            health_claims(),
            "/snapshotDigest",
            json!(sha256_hex(&other_snapshot)),
        ),
        &der_encode(&LOW, &LOW),
    );
    let refused_outboxes = [
        with(
            outbox(&lease, &snapshot),
            "/leaseDigest",
            json!("a".repeat(64)),
        ),
        outbox(&lease, &other_snapshot),
        outbox(&rebound, &other_snapshot),
        with(outbox(&lease, &snapshot), "/schemaVersion", json!("other")),
        with(outbox(&lease, &snapshot), "/snapshot", json!("not base64")),
        with(outbox(&lease, &snapshot), "/lease", json!("lease")),
    ];
    for refused_outbox in refused_outboxes {
        assert_eq!(
            parse("outbox", &canonical(&refused_outbox)),
            refused("health_lease_outbox_invalid")
        );
    }
    let unsigned = health_lease(health_claims(), &der_encode(&LOW, &P256_ORDER));
    assert_eq!(
        parse("outbox", &canonical(&outbox(&unsigned, &snapshot))),
        refused("health_lease_invalid")
    );
    let pretty = serde_json::to_vec_pretty(&outbox(&lease, &snapshot)).expect("pretty");
    assert_eq!(
        parse("outbox", &pretty),
        refused("health_lease_outbox_invalid")
    );
}

#[test]
fn timestamps_count_microseconds_from_the_epoch() {
    assert_eq!(utc_instant("1970-01-01T00:00:00Z", false), Some(0));
    assert_eq!(
        utc_instant("1970-01-02T00:00:01.5Z", true),
        Some(86_401_500_000)
    );
    assert_eq!(
        utc_instant("2000-03-01T00:00:00.12345678Z", true),
        Some(951_868_800_123_456)
    );
    assert_eq!(
        utc_instant("2024-02-29T00:00:00Z", false),
        Some(1_709_164_800_000_000)
    );
    assert_eq!(utc_instant("2023-02-29T00:00:00Z", false), None);
    assert_eq!(utc_instant("2026-07-18T24:00:00Z", false), None);
    assert_eq!(utc_instant("2026-07-18T14:00:60Z", false), None);
    assert_eq!(utc_instant("2026-07-18T14:00:00.5Z", false), None);
    assert_eq!(utc_instant("2026-07-18 14:00:00Z", false), None);
}

#[test]
fn a_request_outside_the_operations_fails() {
    let reject = |request: Value| {
        assert_eq!(
            run(&request),
            Err("health_lease_contract_request_invalid".to_owned()),
            "{request}"
        );
    };
    reject(json!({"schema": "health-lease-contract.v0", "op": "health-claims", "value": {}}));
    reject(json!({"schema": "health-lease-contract.v1", "op": "sign", "value": {}}));
    reject(json!({"schema": "health-lease-contract.v1", "op": "health-claims"}));
    reject(json!({"schema": "health-lease-contract.v1", "op": "outbox", "value": {}}));
    reject(json!({"schema": "health-lease-contract.v1", "op": "outbox", "payload": "%%"}));
    reject(json!({
        "schema": "health-lease-contract.v1",
        "op": "health-claims",
        "value": {},
        "payload": "",
    }));
    reject(json!({
        "schema": "health-lease-contract.v1",
        "op": "health-claims",
        "value": {},
        "path": "/etc/passwd",
    }));
}
