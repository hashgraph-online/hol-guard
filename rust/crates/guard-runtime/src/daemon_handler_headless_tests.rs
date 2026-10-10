//! Vectors recorded from the retired Python headless response builders.

use guard_contracts::DAEMON_HANDLER_REQUEST_SCHEMA;
use serde_json::{json, Value};

const VECTORS: &str = include_str!("../tests/fixtures/daemon_headless_vectors.json");

fn answer(query: &Value) -> Value {
    let request = json!({
        "operation": "daemon_handler",
        "request": {
            "schema": DAEMON_HANDLER_REQUEST_SCHEMA,
            "request_id": "req-headless",
            "query": query,
        }
    });
    let out =
        crate::resident_protocol::evaluate_resident_bytes(request.to_string().as_bytes(), None)
            .expect("daemon handler op should answer");
    let reply: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(reply["status"], "ok", "{query}");
    reply["payload"].clone()
}

#[test]
fn matches_vectors_recorded_from_python() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() > 1500, "{} vectors", vectors.len());
    for vector in vectors {
        let name = vector["name"].as_str().unwrap();
        let expected = &vector["expected"];
        let reply = answer(&vector["query"]);
        assert_eq!(reply["kind"], vector["query"]["kind"], "vector {name}");
        assert_eq!(reply["outcome"], expected["outcome"], "vector {name}");
        assert_eq!(reply["status"], expected["status"], "vector {name}");
        assert_eq!(reply["body"], expected["body"], "vector {name}");
        assert_eq!(reply["fields"], expected["fields"], "vector {name}");
    }
}

#[test]
fn vectors_cover_every_kind_and_status() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    for (kind, outcome) in [
        ("headless_error", "reject"),
        ("headless_cursor_surface", "reject"),
        ("headless_state", "proceed"),
        ("detection_statuses", "proceed"),
        ("supply_chain_sync_error", "reject"),
    ] {
        assert!(
            vectors.iter().any(|vector| vector["query"]["kind"] == kind
                && vector["expected"]["outcome"] == outcome),
            "no {outcome} vectors for {kind}"
        );
    }
    let statuses: std::collections::BTreeSet<i64> = vectors
        .iter()
        .filter(|vector| vector["expected"]["outcome"] == "reject")
        .filter_map(|vector| vector["expected"]["status"].as_i64())
        .collect();
    assert_eq!(
        statuses,
        [400, 403, 404, 409, 502, 503].into_iter().collect()
    );
    let app_statuses: std::collections::BTreeSet<&str> = vectors
        .iter()
        .filter_map(|vector| vector["expected"]["fields"]["app_status"].as_str())
        .collect();
    assert_eq!(
        app_statuses,
        ["inactive", "observed", "protected", "unknown"]
            .into_iter()
            .collect()
    );
}
