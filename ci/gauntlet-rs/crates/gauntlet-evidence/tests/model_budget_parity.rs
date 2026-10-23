use gauntlet_evidence::{read_signed_model_budget, verify_signed_model_budget, DEFAULT_BASE_URL};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::symlink;

fn public_key(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/model_budget_v1.json")).unwrap()
}

#[test]
fn signed_provider_accounting_matches_pinned_python() {
    let fixture = fixture();
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    for (path, field) in [
        (
            "ci/gauntlet/benchmark/business_model_budget.py",
            "python_source_sha256",
        ),
        (
            "ci/gauntlet/benchmark/model_endpoint.py",
            "model_endpoint_source_sha256",
        ),
    ] {
        let source = baseline["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["path"] == path)
            .unwrap();
        assert_eq!(fixture[field], source["sha256"], "{path}");
    }
    assert_eq!(
        fixture["schema"],
        "hol-gauntlet-python-model-budget-fixtures.v1"
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 39);
    let key = public_key(fixture["public_key_hex"].as_str().unwrap());
    for case in cases {
        for (name, digest) in case["outside_sources"].as_object().unwrap() {
            let path = format!("ci/gauntlet/benchmark/{name}");
            let source = baseline["files"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["path"] == path)
                .unwrap();
            assert_eq!(*digest, source["sha256"], "{path}");
        }
        let raw = serde_json::to_vec(&case["envelope"]).unwrap();
        let observed = verify_signed_model_budget(
            &raw,
            &key,
            "qwen3.6",
            100,
            Some(&"a".repeat(64)),
            Some(5),
            &case["outside_sources"],
            DEFAULT_BASE_URL,
        );
        if case["expected"]["accepted"] == true {
            assert_eq!(
                observed.unwrap(),
                case["expected"]["usage"],
                "{}",
                case["name"]
            );
        } else {
            assert!(observed.is_err(), "{}", case["name"]);
        }
    }
}

#[test]
fn outside_key_source_and_byte_budget_refuse_forgeries() {
    let fixture = fixture();
    let sample = &fixture["cases"][0];
    let raw = serde_json::to_vec(&sample["envelope"]).unwrap();
    let mut wrong_key = public_key(fixture["public_key_hex"].as_str().unwrap());
    wrong_key[0] ^= 1;
    assert!(verify_signed_model_budget(
        &raw,
        &wrong_key,
        "qwen3.6",
        100,
        Some(&"a".repeat(64)),
        Some(5),
        &sample["outside_sources"],
        DEFAULT_BASE_URL,
    )
    .is_err());
    let key = public_key(fixture["public_key_hex"].as_str().unwrap());
    let mut wrong_sources = sample["outside_sources"].clone();
    wrong_sources["business_model_budget.py"] = json!("b".repeat(64));
    assert!(verify_signed_model_budget(
        &raw,
        &key,
        "qwen3.6",
        100,
        Some(&"a".repeat(64)),
        Some(5),
        &wrong_sources,
        DEFAULT_BASE_URL,
    )
    .is_err());
    assert!(verify_signed_model_budget(
        &vec![b'x'; 8 * 1024 * 1024 + 1],
        &key,
        "qwen3.6",
        100,
        None,
        None,
        &sample["outside_sources"],
        DEFAULT_BASE_URL,
    )
    .is_err());
}

#[test]
fn digest_pinned_budget_file_reader_refuses_mutable_or_ambiguous_custody() {
    let fixture = fixture();
    let sample = &fixture["cases"][0];
    let key = public_key(fixture["public_key_hex"].as_str().unwrap());
    let raw = serde_json::to_vec(&sample["envelope"]).unwrap();
    let digest = format!("{:x}", Sha256::digest(&raw));
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("model-budget.json");
    fs::write(&path, &raw).unwrap();
    let read = |path: &std::path::Path, pin: &str| {
        read_signed_model_budget(
            path,
            pin,
            &key,
            "qwen3.6",
            100,
            Some(&"a".repeat(64)),
            Some(5),
            &sample["outside_sources"],
            DEFAULT_BASE_URL,
        )
    };
    assert_eq!(read(&path, &digest).unwrap(), sample["expected"]["usage"]);
    assert!(read(&path, &"0".repeat(64)).is_err());
    let linked = root.join("linked.json");
    fs::hard_link(&path, &linked).unwrap();
    assert!(read(&path, &digest).is_err());
    fs::remove_file(&linked).unwrap();
    let alias = root.join("alias");
    symlink(&root, &alias).unwrap();
    assert!(read(&alias.join("model-budget.json"), &digest).is_err());
    let hidden = root.join("retained.json");
    fs::rename(&path, &hidden).unwrap();
    symlink(&hidden, &path).unwrap();
    assert!(read(&path, &digest).is_err());
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"changed").unwrap();
    assert!(read(&path, &digest).is_err());
    fs::write(&path, vec![b'x'; 8 * 1024 * 1024 + 1]).unwrap();
    assert!(read(&path, &digest).is_err());
}
