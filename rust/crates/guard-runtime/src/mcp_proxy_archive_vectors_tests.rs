//! Parity vectors recorded from the retired Python archive binder and package
//! reason projection. The vectors are the contract; there is no Python oracle.

use guard_contracts::McpProxyQueryV1;
use serde_json::{json, Value};

use crate::mcp_proxy_decision_op::decide;

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/mcp_proxy_decision/archive_signal_vectors.json");

fn query(request: &Value) -> McpProxyQueryV1 {
    serde_json::from_value(request.clone()).expect("vector request must deserialize")
}

fn corpus() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    document["vectors"].as_array().unwrap().clone()
}

fn apply(params: &Value, edits: &[Value]) -> Value {
    let mut bound = params.clone();
    for edit in edits {
        let mut slot = &mut bound;
        for step in edit["path"].as_array().unwrap() {
            slot = match step {
                Value::String(key) => slot.get_mut(key).unwrap(),
                other => slot.get_mut(other.as_u64().unwrap() as usize).unwrap(),
            };
        }
        *slot = edit["value"].clone();
    }
    bound
}

fn platform_key() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else {
        "unix"
    }
}

#[test]
fn archive_binding_matches_every_recorded_vector() {
    let mut checked = 0;
    for vector in corpus() {
        let request = &vector["request"];
        if request["check"] != "external_archive_bind" {
            continue;
        }
        let expected = &vector["expected"][platform_key()];
        let actual = decide(&query(request));
        assert_eq!(actual["kind"], expected["kind"], "vector {}", vector["id"]);
        if expected["kind"] == "bound" {
            let edits = actual["edits"].as_array().unwrap();
            assert_eq!(
                apply(&request["params"], edits),
                expected["bound_params"],
                "vector {}",
                vector["id"]
            );
        }
        checked += 1;
    }
    assert!(checked > 1500, "corpus unexpectedly small: {checked}");
}

#[test]
fn reason_signals_match_every_recorded_vector() {
    let mut checked = 0;
    for vector in corpus() {
        if vector["request"]["check"] != "package_reason_signals" {
            continue;
        }
        let actual = decide(&query(&vector["request"]));
        assert_eq!(actual, vector["expected"], "vector {}", vector["id"]);
        checked += 1;
    }
    assert!(checked >= 15);
}

#[test]
fn unmatched_archive_fails_closed() {
    let request = json!({
        "check": "external_archive_bind",
        "params": {"url": "https://example.com/a.tgz"},
        "replacements": [["https://example.com/a.tgz", "/a"], ["https://example.com/b.tgz", "/b"]],
        "requires_binding": false,
    });
    assert_eq!(decide(&query(&request))["kind"], "unbound");
}
