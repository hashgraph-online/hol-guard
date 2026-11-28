use serde_json::{json, Value};

use super::*;
use crate::conformance::run_conformance;
use crate::noise::BaselineDecision;

fn manifest() -> Value {
    json!({
        "schemaVersion": "guard.provider-integration.v1",
        "id": "provider.exampleshield",
        "name": "ExampleShield",
        "publisher": {"name": "ExampleShield Inc.", "url": "https://exampleshield.example", "verified": false},
        "summary": "Checks the sites an agent opens against your ExampleShield account.",
        "surfaces": ["browser"],
        "auth": {
            "kind": "api-key",
            "header": "x-provider-key",
            "keyFormat": {"minLength": 24, "maxLength": 128, "charset": "base64url"},
            "obtainUrl": "https://exampleshield.example/keys"
        },
        "hosts": ["api.exampleshield.example"],
        "capabilities": [{
            "id": "browser.origin-reputation",
            "request": {
                "method": "POST",
                "path": "/v1/guard/origin",
                "body": {"origin": {"fact": "target.origin"}}
            },
            "response": {
                "verdict": {"pointer": "/result/verdict", "map": {"clean": "ok", "suspicious": "caution", "malicious": "danger", "unlisted": "danger"}},
                "reasonCodes": {"pointer": "/result/reasons", "allow": ["phishing", "new_domain"]},
                "ttlSeconds": {"pointer": "/ttl", "min": 60, "max": 86400}
            },
            "shares": ["target.origin"]
        }],
        "limits": {"timeoutMs": 1200, "maxResponseBytes": 4096, "maxRequestsPerMinute": 30},
        "privacyUrl": "https://exampleshield.example/privacy",
        "termsUrl": "https://exampleshield.example/terms"
    })
}

fn draft(manifest: &Value) -> Result<DraftedRecordings, DraftError> {
    draft_recordings(&serde_json::to_vec(manifest).unwrap())
}

fn recordings(drafted: &DraftedRecordings) -> Vec<Value> {
    let file: Value = serde_json::from_str(&drafted.text).unwrap();
    assert_eq!(file["schema"], RECORDINGS_SCHEMA);
    file["recordings"].as_array().unwrap().clone()
}

#[test]
fn the_draft_covers_every_mapped_verdict_unknown_and_each_failure() {
    let drafted = draft(&manifest()).expect("draft");
    assert_eq!(drafted.provider_id, "provider.exampleshield");
    let rows = recordings(&drafted);
    assert_eq!(drafted.count, rows.len());
    assert_eq!(
        rows.len(),
        4 + 1 + 5,
        "four table entries, unknown, five failures"
    );
    let expects: Vec<String> = rows
        .iter()
        .map(|row| {
            row["expect"]["verdict"]
                .as_str()
                .or_else(|| row["expect"]["failure"].as_str())
                .unwrap()
                .to_owned()
        })
        .collect();
    for wanted in [
        "ok",
        "caution",
        "danger",
        "unknown",
        "unauthorized",
        "rate_limited",
        "status",
        "oversize",
        "malformed",
    ] {
        assert!(
            expects.iter().any(|seen| seen == wanted),
            "{wanted} missing"
        );
    }
}

#[test]
fn bodies_follow_the_manifest_pointers_and_a_listed_unlisted_is_avoided() {
    let rows = recordings(&draft(&manifest()).unwrap());
    let danger = rows
        .iter()
        .find(|row| row["body"].as_str().unwrap().contains("malicious"))
        .unwrap();
    let body: Value = serde_json::from_str(danger["body"].as_str().unwrap()).unwrap();
    assert_eq!(
        body,
        json!({"result": {"verdict": "malicious", "reasons": ["phishing"]}, "ttl": 60})
    );
    assert_eq!(
        danger["expect"],
        json!({"verdict": "danger", "reasonCodes": ["phishing"]})
    );
    let unmapped = rows
        .iter()
        .find(|row| row["name"] == "browser-origin-reputation-unmapped")
        .unwrap();
    assert!(unmapped["body"].as_str().unwrap().contains("unlisted-1"));
    assert_eq!(unmapped["expect"]["verdict"], "unknown");
    let oversize = rows
        .iter()
        .find(|row| row["expect"]["failure"] == "oversize")
        .unwrap();
    assert_eq!(oversize["padToBytes"], 4097);
}

#[test]
fn the_draft_passes_the_kit_recordings_check() {
    let manifest = serde_json::to_vec(&manifest()).unwrap();
    let drafted = draft_recordings(&manifest).unwrap();
    let parsed = parse_recordings(drafted.text.as_bytes()).unwrap();
    let borrowed: Vec<_> = parsed.iter().map(|recording| recording.borrow()).collect();
    let report = run_conformance(&manifest, &borrowed, &[BaselineDecision::Allow]);
    assert!(report.checks[1].passed(), "{:?}", report.checks[1].problems);
}

#[test]
fn colliding_pointers_keep_the_verdict() {
    let mut manifest = manifest();
    manifest["capabilities"][0]["response"]["reasonCodes"]["pointer"] =
        json!("/result/verdict/codes");
    let rows = recordings(&draft(&manifest).unwrap());
    for row in rows
        .iter()
        .filter(|row| row["status"] == 200 && row["expect"].get("verdict").is_some())
    {
        let body: Value = serde_json::from_str(row["body"].as_str().unwrap()).unwrap();
        assert!(body["result"]["verdict"].is_string());
        assert_eq!(row["expect"]["reasonCodes"], json!([]));
    }
}

#[test]
fn a_manifest_that_does_not_compile_is_refused_with_the_compiler_code() {
    let mut broken = manifest();
    broken["hosts"] = json!([]);
    let error = draft(&broken).unwrap_err();
    assert!(
        error.code().starts_with("provider_integration_"),
        "{}",
        error.code()
    );
    assert_eq!(
        draft_recordings(b"not json").unwrap_err().code(),
        "provider_integration_json_invalid"
    );
}

#[test]
fn a_draft_too_large_for_one_file_is_refused() {
    let mut big = manifest();
    let map: serde_json::Map<String, Value> = (0..16)
        .map(|index| (format!("v{index}"), json!("caution")))
        .collect();
    big["capabilities"][0]["response"]["verdict"]["map"] = Value::Object(map);
    let first = big["capabilities"][0].clone();
    let capabilities: Vec<Value> = [
        "browser.origin-reputation",
        "browser.download-reputation",
        "browser.site-policy",
    ]
    .iter()
    .map(|id| {
        let mut capability = first.clone();
        capability["id"] = json!(id);
        capability
    })
    .collect();
    big["capabilities"] = json!(capabilities);
    assert_eq!(draft(&big).unwrap_err(), DraftError::TooMany);
}
