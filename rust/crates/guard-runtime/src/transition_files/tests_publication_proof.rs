use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use super::dispatch;
use super::inspect::sha256_hex;

const OPERATION: &str = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";

fn observation() -> Value {
    json!({
        "observed_monotonic": 10.0,
        "operation_id": OPERATION,
        "generation": "generation",
        "guard_home": "/guard",
        "runtime_identity": {"path": "/runtime", "size": 1, "mtime_ns": 2, "sha256": "ab"},
        "installed_hook_evidence": {
            "harness": "codex",
            "config_sha256": sha256_hex(b"config"),
            "manifest_sha256": sha256_hex(b""),
        },
    })
}

fn request(observation: Value) -> Value {
    json!({
        "op": "publication_inverse_proof",
        "home": "/guard",
        "observation": observation,
        "publication": 1.0,
        "started": 2.0,
        "now": 11.0,
        "operation_id": OPERATION,
        "generation": "generation",
        "guard_home": "/guard",
        "runtime_identity": {"path": "/runtime", "size": 1.0, "mtime_ns": 2, "sha256": "ab"},
        "config_after": STANDARD.encode(b"config"),
        "manifest_after": null,
    })
}

fn answer(request: &Value) -> Result<Value, String> {
    let answer = dispatch(request).map_err(|error| format!("{error:?}"))?;
    match answer.get("error") {
        Some(error) => Err(error.to_string()),
        None => Ok(answer["value"].clone()),
    }
}

#[test]
fn a_proof_for_this_publication_retires_its_inverse() {
    assert_eq!(answer(&request(observation())).unwrap(), json!(null));
}

#[test]
fn a_proof_that_names_anything_else_is_refused() {
    let mut cases = Vec::new();
    for (key, value) in [
        ("operation_id", json!("other")),
        ("generation", json!("other")),
        ("guard_home", json!("/elsewhere")),
        ("runtime_identity", json!({"path": "/other"})),
        ("installed_hook_evidence", json!(null)),
        ("observed_monotonic", json!(12.0)),
        ("observed_monotonic", json!(1.5)),
        ("observed_monotonic", json!(true)),
        ("observed_monotonic", json!("10")),
    ] {
        let mut proof = observation();
        proof[key] = value;
        cases.push(proof);
    }
    for (key, value) in [
        ("harness", json!("cursor")),
        ("config_sha256", json!("0")),
        ("manifest_sha256", json!(sha256_hex(b"manifest"))),
    ] {
        let mut proof = observation();
        proof["installed_hook_evidence"][key] = value;
        cases.push(proof);
    }
    for proof in cases {
        let error = answer(&request(proof.clone())).unwrap_err();
        assert!(
            error.contains("publication_inverse_native_verification_invalid"),
            "{proof}: {error}"
        );
    }
    let mut not_object = request(json!("proof"));
    not_object["observation"] = json!("proof");
    assert!(answer(&not_object).is_err());
}

#[test]
fn a_proof_older_than_the_publication_or_newer_than_now_is_refused() {
    for (key, value) in [
        ("publication", json!(3.0)),
        ("started", json!(0.5)),
        ("started", json!(10.5)),
        ("now", json!(9.0)),
        ("now", json!(null)),
        ("started", json!(false)),
    ] {
        let mut asked = request(observation());
        asked[key] = value;
        let error = answer(&asked).unwrap_err();
        assert!(
            error.contains("publication_inverse_native_verification_invalid"),
            "{key}: {error}"
        );
    }
}
