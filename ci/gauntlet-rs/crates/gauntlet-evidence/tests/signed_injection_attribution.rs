use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_contracts::canonicalize;
use gauntlet_evidence::reduce_signed_injection_attribution;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

fn key() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap()
}

fn signed(case: &Value, key: &Ed25519KeyPair) -> Value {
    let mut control = case["record"].clone();
    let extra = control["extra_probes"].clone();
    let canonical = canonicalize(extra.to_string().as_bytes()).unwrap();
    control["extra_probes"] = json!({
        "record": extra,
        "signature": STANDARD.encode(key.sign(&canonical).as_ref()),
    });
    control["controller_public_key_hex"] = Value::String(
        key.public_key()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    );
    control
}

#[test]
fn signed_probe_preserves_twelve_python_attribution_cases_without_a_pass_verdict() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_injection_attribution_v1.json")).unwrap();
    let key = key();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let control = signed(case, &key);
        let raw = serde_json::to_vec(&control).unwrap();
        let result = reduce_signed_injection_attribution(&raw, key.public_key().as_ref());
        if case["accepted"] == true {
            assert_eq!(
                result.unwrap(),
                case["guard_intervention"],
                "{}",
                case["name"]
            );
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                case["error"],
                "{}",
                case["name"]
            );
        }
    }
}

#[test]
fn changed_probe_declared_key_or_outside_key_refuses_before_attribution() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_injection_attribution_v1.json")).unwrap();
    let key = key();
    let control = signed(&fixture["cases"][0], &key);
    let raw = serde_json::to_vec(&control).unwrap();
    let other = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
    assert_eq!(
        reduce_signed_injection_attribution(&raw, other.public_key().as_ref())
            .unwrap_err()
            .to_string(),
        "control key differs from outside pin"
    );

    let mut changed = control.clone();
    changed["extra_probes"]["record"]["injection_control"]["attack_payload"] = json!("OTHER");
    assert_eq!(
        reduce_signed_injection_attribution(
            &serde_json::to_vec(&changed).unwrap(),
            key.public_key().as_ref(),
        )
        .unwrap_err()
        .to_string(),
        "externally pinned controller signature invalid"
    );

    changed = control.clone();
    changed["controller_public_key_hex"] = json!("00".repeat(32));
    assert_eq!(
        reduce_signed_injection_attribution(
            &serde_json::to_vec(&changed).unwrap(),
            key.public_key().as_ref(),
        )
        .unwrap_err()
        .to_string(),
        "control key differs from outside pin"
    );
}

#[test]
fn ambiguous_or_unsigned_control_refuses() {
    let key = key();
    let fixture: Value =
        serde_json::from_str(include_str!("python_injection_attribution_v1.json")).unwrap();
    let mut control = signed(&fixture["cases"][0], &key);
    control["extra_probes"] = fixture["cases"][0]["record"]["extra_probes"].clone();
    let unsigned = serde_json::to_vec(&control).unwrap();
    assert_eq!(
        reduce_signed_injection_attribution(&unsigned, key.public_key().as_ref())
            .unwrap_err()
            .to_string(),
        "invalid controller envelope"
    );
    let duplicated = br#"{"controller_public_key_hex":"00","controller_public_key_hex":"00"}"#;
    assert_eq!(
        reduce_signed_injection_attribution(duplicated, key.public_key().as_ref())
            .unwrap_err()
            .to_string(),
        "invalid injection control record"
    );
}
