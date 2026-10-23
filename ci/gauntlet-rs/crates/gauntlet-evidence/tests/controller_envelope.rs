use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_contracts::canonicalize;
use gauntlet_evidence::verify_controller_envelope;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn signed() -> (Value, Vec<u8>, Vec<u8>) {
    let key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    let record = json!({"kind":"injection-control","nested":{"path":"/synthetic","value":73}});
    let canonical = canonicalize(record.to_string().as_bytes()).unwrap();
    let signature = STANDARD.encode(key.sign(&canonical).as_ref());
    let envelope = json!({"record":record,"signature":signature});
    (
        envelope.clone(),
        serde_json::to_vec(&envelope).unwrap(),
        key.public_key().as_ref().to_vec(),
    )
}

#[test]
fn vm_python_cryptography_signature_matches_rust_canonical_bytes() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_controller_envelope_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/benchmark/developer_product_custody.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(
        fixture["schema"],
        "gauntlet-python-controller-envelope-fixture.v1"
    );
    let key: Vec<u8> = fixture["public_key_hex"]
        .as_str()
        .unwrap()
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let rust_key = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
    assert_eq!(rust_key.public_key().as_ref(), key);
    let record = &fixture["envelope"]["record"];
    let canonical = canonicalize(record.to_string().as_bytes()).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&canonical)),
        fixture["canonical_record_sha256"]
    );
    let raw = serde_json::to_vec(&fixture["envelope"]).unwrap();
    assert_eq!(verify_controller_envelope(&raw, &key).unwrap(), *record);
}

#[test]
fn exact_external_key_and_canonical_record_are_required() {
    let (envelope, raw, public_key) = signed();
    assert_eq!(
        verify_controller_envelope(&raw, &public_key).unwrap(),
        envelope["record"]
    );
    let pretty = serde_json::to_vec_pretty(&envelope).unwrap();
    assert_eq!(
        verify_controller_envelope(&pretty, &public_key).unwrap(),
        envelope["record"]
    );

    let mut changed_record = envelope.clone();
    changed_record["record"]["nested"]["value"] = json!(74);
    assert!(
        verify_controller_envelope(&serde_json::to_vec(&changed_record).unwrap(), &public_key)
            .is_err()
    );
    let wrong_key = Ed25519KeyPair::from_seed_unchecked(&[8; 32]).unwrap();
    assert!(verify_controller_envelope(&raw, wrong_key.public_key().as_ref()).is_err());
    assert!(verify_controller_envelope(&raw, &public_key[..31]).is_err());
}

#[test]
fn duplicate_ambiguous_or_malformed_envelopes_refuse() {
    let (envelope, _raw, public_key) = signed();
    let mut extra = envelope.clone();
    extra["producer_passed"] = json!(true);
    assert_eq!(
        verify_controller_envelope(&serde_json::to_vec(&extra).unwrap(), &public_key)
            .unwrap_err()
            .to_string(),
        "invalid controller envelope"
    );
    let mut bad_signature = envelope.clone();
    bad_signature["signature"] = json!("not-base64");
    assert_eq!(
        verify_controller_envelope(&serde_json::to_vec(&bad_signature).unwrap(), &public_key)
            .unwrap_err()
            .to_string(),
        "externally pinned controller signature invalid"
    );
    assert_eq!(
        verify_controller_envelope(br#"{"record":{},"record":{},"signature":"x"}"#, &public_key)
            .unwrap_err()
            .to_string(),
        "invalid controller envelope"
    );
    assert!(
        verify_controller_envelope(br#"{"record":{},"signature":false}"#, &public_key).is_err()
    );
}
