use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::*;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn reference() -> PathBuf {
    repo().join("tests/fixtures/provider_integrations/exampleshield/manifest.json")
}

fn run(request: Value) -> Value {
    run_command(&serde_json::to_vec(&request).unwrap())
}

fn code(answer: &Value) -> &str {
    answer["error"]["code"].as_str().unwrap_or_default()
}

#[test]
fn the_reference_provider_passes_from_its_checkout() {
    let answer = run(json!({"manifest": reference()}));
    assert_eq!(answer["ok"], true, "{answer}");
    assert_eq!(answer["passed"], true, "{answer}");
    assert_eq!(answer["provider_id"], "provider.exampleshield");
    assert_eq!(answer["checks"].as_array().unwrap().len(), 5);
    assert!(answer["corpus_rows"].as_u64().unwrap() > 0);
}

#[test]
fn a_missing_recording_fails_the_recordings_check() {
    let directory =
        std::env::temp_dir().join(format!("provider-conformance-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let source = repo().join("tests/fixtures/provider_integrations/exampleshield/recordings.json");
    let mut recordings: Value = serde_json::from_slice(&fs::read(source).unwrap()).unwrap();
    recordings["recordings"]
        .as_array_mut()
        .unwrap()
        .retain(|recording| recording["name"] != "rate-limited");
    let path = directory.join("recordings.json");
    fs::write(&path, serde_json::to_vec(&recordings).unwrap()).unwrap();
    let answer = run(json!({"manifest": reference(), "recordings": path}));
    fs::remove_dir_all(&directory).unwrap();
    assert_eq!(answer["passed"], false, "{answer}");
    let recordings_check = &answer["checks"][1];
    assert_eq!(recordings_check["id"], "recordings");
    assert_eq!(
        recordings_check["problems"],
        json!(["browser.origin-reputation: no recording fails as rate_limited"])
    );
}

#[test]
fn files_outside_a_checkout_need_explicit_paths() {
    let directory =
        std::env::temp_dir().join(format!("provider-conformance-out-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let manifest = directory.join("provider.exampleshield.json");
    fs::copy(reference(), &manifest).unwrap();
    let answer = run(json!({"manifest": manifest}));
    let named = run(json!({
        "manifest": manifest,
        "gate": repo().join(GATE),
        "recordings": repo().join("tests/fixtures/provider_integrations/exampleshield/recordings.json"),
    }));
    fs::remove_dir_all(&directory).unwrap();
    assert_eq!(code(&answer), "gate_not_found", "{answer}");
    assert_eq!(named["passed"], true, "{named}");
}

#[test]
fn bad_requests_are_refused() {
    assert_eq!(code(&run_command(b"{")), "request_invalid");
    assert_eq!(
        code(&run(json!({"manifest": "x", "extra": 1}))),
        "request_invalid"
    );
    assert_eq!(
        code(&run(
            json!({"manifest": repo().join("no-such-manifest.json")})
        )),
        "manifest_unreadable"
    );
    assert_eq!(
        code(&run(json!({"manifest": repo()}))),
        "manifest_unreadable"
    );
}

#[test]
fn the_slug_is_only_a_safe_path_segment() {
    assert_eq!(
        provider_slug(br#"{"id":"provider.example-shield2"}"#).as_deref(),
        Some("example-shield2")
    );
    for manifest in [
        br#"{"id":"provider../../etc"}"#.as_slice(),
        br#"{"id":"provider."}"#,
        br#"{"id":"other.exampleshield"}"#,
        br#"{"id":"provider.Example"}"#,
        br#"{"id":"provider.a/b"}"#,
        b"[]",
    ] {
        assert_eq!(
            provider_slug(manifest),
            None,
            "{}",
            String::from_utf8_lossy(manifest)
        );
    }
}
