use serde_json::{json, Value};

use super::*;

/// Requests with the answers the Python claim builders gave for the same item.
const VECTORS: &str = include_str!("../testdata/aibom_trust_claims/vectors.json");

fn vectors() -> Vec<Value> {
    serde_json::from_str::<Value>(VECTORS)
        .expect("vectors parse")
        .as_array()
        .expect("vector list")
        .clone()
}

fn vector(name: &str) -> Value {
    vectors()
        .into_iter()
        .find(|vector| vector["name"] == name)
        .expect("named vector")
}

#[test]
fn every_vector_answers_what_the_python_builders_built() {
    for vector in vectors() {
        let answer = dispatch(&vector["request"]).expect("claims answer");
        assert_eq!(answer, vector["expected"], "{}", vector["name"]);
    }
}

#[test]
fn a_later_run_of_the_same_scanner_replaces_the_earlier_layer() {
    let answer = dispatch(&vector("skill")["request"]).expect("claims answer");
    let layers = answer["layers"].as_array().expect("layers");
    assert_eq!(layers.len(), 2);
    assert_eq!(layers[0]["layerType"], "local_baseline");
    assert_eq!(layers[1]["status"], "error");
    assert!(layers[1]["trustScore"].is_null());
}

#[test]
fn reported_severity_counts_win_over_the_findings() {
    let answer = dispatch(&vector("mcp")["request"]).expect("claims answer");
    let layer = &answer["layers"][0];
    assert_eq!(
        layer["metadata"]["findingsBySeverity"],
        json!({"critical": 0, "high": 1, "medium": 0, "low": 0})
    );
    assert_eq!(layer["trustScore"], 88);
    assert_eq!(answer["local_security"]["safety"]["targetsScanned"], 0);
}

#[test]
fn a_changed_finding_changes_the_security_evidence_hash() {
    let mut request = vector("skill")["request"].clone();
    let before = dispatch(&request).expect("claims answer");
    request["security"]["findings"][0]["description"] = json!("Runs wget");
    let after = dispatch(&request).expect("claims answer");
    assert_ne!(
        before["local_security"]["metadata"]["evidenceHash"],
        after["local_security"]["metadata"]["evidenceHash"]
    );
    assert_eq!(before["resolution"], after["resolution"]);
}

#[test]
fn the_domain_keeps_at_most_32_components() {
    let mut request = vector("skill")["request"].clone();
    let component = json!({"key": "k", "score": 50, "rationale": "r", "evidence": []});
    let first = vec![component.clone(); 30];
    let second = vec![component; 5];
    request["domain"]["adapters"] = json!([
        {"adapter_id": "a", "label": "A", "weight": 0.5, "emitted": true, "components": first},
        {"adapter_id": "b", "label": "B", "weight": 0.5, "emitted": true, "components": second},
    ]);
    let answer = dispatch(&request).expect("claims answer");
    let components = answer["resolution"]["trustComponents"]
        .as_array()
        .expect("components");
    assert_eq!(components.len(), MAX_DOMAIN_COMPONENTS);
    assert_eq!(components[31]["componentId"], "b:k");
    assert!(components[0].get("evidence").is_none());
    assert_eq!(
        answer["resolution"]["metadata"]["evidence"]["componentCount"],
        32
    );
}

#[test]
fn malformed_requests_are_invalid() {
    let good = vector("skill")["request"].clone();
    let mut cases = vec![json!([]), json!({"domain": null, "cisco_layers": []})];
    for (pointer, value) in [
        ("/cisco_layers", json!({})),
        ("/cisco_layers/0/scanner", json!("other")),
        ("/cisco_layers/0/run/metadata", json!([])),
        ("/cisco_layers/0/run/finding_severities", json!(null)),
        ("/domain", json!("skill")),
        ("/domain/score", json!("high")),
        ("/domain/adapters/0/emitted", json!(1)),
        ("/security", json!([])),
        ("/security/findings/0", json!("finding")),
        ("/security/entity_type", json!(null)),
    ] {
        let mut request = good.clone();
        *request.pointer_mut(pointer).expect("pointer") = value;
        cases.push(request);
    }
    for args in cases {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
