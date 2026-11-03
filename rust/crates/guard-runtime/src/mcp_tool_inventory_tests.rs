use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const PARITY: &str = include_str!("../testdata/mcp_tool_inventory_parity.json");

fn answer(server: &str, definitions: &str, trust_layers: &str) -> Value {
    let reply = dispatch(&json!({
        "harness": "codex",
        "server_item_id": server,
        "definitions": definitions,
        "trust_layers": trust_layers,
    }))
    .expect("answer");
    serde_json::from_str(reply["answer"].as_str().expect("answer text")).expect("answer json")
}

#[test]
fn tool_readings_match_the_python_classifiers() {
    let parity: Value = serde_json::from_str(PARITY).expect("parity");
    for case in parity["cases"].as_array().expect("cases") {
        let server = case["server"].as_str().expect("server");
        let definitions = case["definitions"].as_str().expect("definitions");
        let tools = answer(server, definitions, "null")["tools"].clone();
        let expected = case["tools"].as_array().expect("expected");
        assert_eq!(tools.as_array().expect("tools").len(), expected.len());
        for (tool, want) in tools.as_array().expect("tools").iter().zip(expected) {
            let name = want["name"].as_str().expect("name");
            assert_eq!(tool["name"], want["name"]);
            assert_eq!(tool["display_name"], want["display_name"], "{name}");
            assert_eq!(tool["capabilities"], want["capabilities"], "{name}");
            assert_eq!(tool["risk_level"], want["risk_level"], "{name}");
            assert_eq!(tool["semantic_hash"], want["semantic_hash"], "{name}");
            assert_eq!(
                tool["source_fingerprint"], want["source_fingerprint"],
                "{name}"
            );
            let fingerprints = &tool["fingerprints"];
            assert_eq!(
                fingerprints["descriptionHash"], want["descriptionHash"],
                "{name}"
            );
            assert_eq!(
                fingerprints["inputSchemaHash"], want["inputSchemaHash"],
                "{name}"
            );
            assert_eq!(tool["item_id"], json!(format!("{server}:tool:{name}")));
        }
    }
}

#[test]
fn signal_text_follows_declaration_order() {
    // `api` then `key` reads as an API key only when the server declared
    // them in that order, which a sorted parse would lose.
    let declared = r#"{"tools":[{"name":"a","inputSchema":{"x":"api","key":1}}]}"#;
    let reversed = r#"{"tools":[{"name":"a","inputSchema":{"key":1,"x":"api"}}]}"#;
    assert_eq!(
        answer("s", declared, "null")["tools"][0]["capabilities"],
        json!(["reads_secrets"])
    );
    assert_eq!(
        answer("s", reversed, "null")["tools"][0]["capabilities"],
        json!(["unknown"])
    );
}

#[test]
fn fingerprint_fields_keep_their_order_and_annotations() {
    let definitions =
        r#"{"tools":[{"name":"t","annotations":{"z":1,"a":true},"outputSchema":{"o":1}}]}"#;
    let reply = dispatch(&json!({
        "harness": "codex",
        "server_item_id": "s",
        "definitions": definitions,
        "trust_layers": "null",
    }))
    .expect("answer");
    let text = reply["answer"].as_str().expect("answer text");
    assert!(text.contains(
        r#""fingerprints":{"descriptionHash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","inputSchemaHash":null,"outputSchemaHash":"#
    ));
    assert!(text.contains(r#""annotations":{"z":1,"a":true},"schemaPresent":true}"#));
}

#[test]
fn server_cisco_layers_are_inherited_unsigned() {
    let layers = r#"[
        {"layerType":"cisco_mcp_scanner","metadata":{"inheritedFromServerItemId":"old","attestation":"x","attestationStatus":"signed","verdict":"clean"},"score":1},
        {"layerType":"other","metadata":{}},
        {"layerType":"cisco_mcp_scanner"},
        "not a layer"
    ]"#;
    let inherited = answer("srv", r#"{"tools":[]}"#, layers)["inherited_layers"].clone();
    assert_eq!(
        inherited,
        json!([
            {
                "layerType": "cisco_mcp_scanner",
                "metadata": {
                    "inheritedFromServerItemId": "srv",
                    "verdict": "clean",
                    "attestationStatus": "unsigned"
                },
                "score": 1
            },
            {
                "layerType": "cisco_mcp_scanner",
                "metadata": {"attestationStatus": "unsigned", "inheritedFromServerItemId": "srv"}
            }
        ])
    );
}

#[test]
fn malformed_requests_are_refused() {
    let base = json!({
        "harness": "codex",
        "server_item_id": "s",
        "definitions": "{}",
        "trust_layers": "null",
    });
    assert!(dispatch(&base).is_ok());
    for key in ["harness", "server_item_id", "definitions", "trust_layers"] {
        let mut missing = base.clone();
        missing.as_object_mut().expect("object").remove(key);
        assert_eq!(dispatch(&missing), Err(ERR_INVALID), "{key}");
    }
    let mut extra = base.clone();
    extra["other"] = json!(1);
    assert_eq!(dispatch(&extra), Err(ERR_INVALID));
    let mut broken = base.clone();
    broken["definitions"] = json!("{");
    assert_eq!(dispatch(&broken), Err(ERR_INVALID));
    // `str.encode` cannot hash a description holding a lone surrogate.
    let mut surrogate = base;
    surrogate["definitions"] = json!(r#"{"tools":[{"name":"t","description":"\ud800"}]}"#);
    assert_eq!(dispatch(&surrogate), Err(ERR_INVALID));
}

#[test]
fn lone_surrogates_round_trip_in_names() {
    // The answer writes the surrogate back as the escape `json.loads` reads.
    let reply = dispatch(&json!({
        "harness": "codex",
        "server_item_id": "s",
        "definitions": r#"{"tools":[{"name":"t\ud800"}]}"#,
        "trust_layers": "null",
    }))
    .expect("answer");
    let text = reply["answer"].as_str().expect("answer text");
    assert!(text.contains(r#""item_id":"s:tool:t\ud800""#));
}
