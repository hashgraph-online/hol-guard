//! Python-frozen RPC request and response decisions above the HMAC bridge.

use gauntlet_evidence::{parse_bridge_rpc_request, parse_bridge_rpc_response, BridgeRpcReply};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[test]
fn python_rpc_shapes_and_reason_classes_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/python_bridge_rpc_v1.json")).unwrap();
    assert_eq!(
        fixture["schema"],
        "hol-gauntlet-python-bridge-rpc-fixtures.v1"
    );
    assert_eq!(
        fixture["python_source_sha256"],
        format!(
            "{:x}",
            Sha256::digest(include_bytes!(
                "../../../../gauntlet/benchmark/vm_bridge_rpc.py"
            ))
        )
    );
    let request = parse_bridge_rpc_request(&json!({
        "request_id":fixture["request_id"],
        "operation":fixture["operation"],
        "payload":fixture["payload"],
    }))
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 30);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expected = &case["expected"];
        match case["mode"].as_str().unwrap() {
            "request" => match parse_bridge_rpc_request(&case["body"]) {
                Ok(actual) => {
                    assert_eq!(expected["status"], "accepted", "{name}");
                    assert_eq!(actual.request_id(), case["body"]["request_id"]);
                    assert_eq!(actual.operation(), case["body"]["operation"]);
                    assert_eq!(actual.payload(), &case["body"]["payload"]);
                }
                Err(error) => {
                    assert_eq!(expected["status"], "BridgeProtocolError", "{name}");
                    assert_eq!(error.to_string(), expected["reason"], "{name}");
                }
            },
            "response" => match parse_bridge_rpc_response(&case["body"], &request) {
                Ok(BridgeRpcReply::Success(result)) => {
                    assert_eq!(expected["status"], "accepted", "{name}");
                    assert_eq!(result, expected["result"], "{name}");
                }
                Ok(BridgeRpcReply::RemoteFailure { code, kind }) => {
                    assert_eq!(expected["status"], "BridgeRemoteError", "{name}");
                    assert_eq!(
                        expected["reason"],
                        format!("bridge operation failed: {code}"),
                        "{name}"
                    );
                    assert_eq!(expected["poisoned"], false, "{name}");
                    if code == "operation-failed" {
                        assert_eq!(kind, Some("ValueError".to_owned()), "{name}");
                    } else {
                        assert_eq!(kind, None, "{name}");
                    }
                }
                Err(error) => {
                    assert_eq!(expected["status"], "BridgeProtocolError", "{name}");
                    assert_eq!(error.to_string(), expected["reason"], "{name}");
                    assert_eq!(expected["poisoned"], true, "{name}");
                }
            },
            other => panic!("unexpected Python RPC fixture mode {other}"),
        }
    }
}
