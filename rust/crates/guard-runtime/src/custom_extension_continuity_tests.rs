//! Replays continuity vectors recorded from the reference Python
//! (`scripts/record_custom_extension_continuity_vectors.py`).

use serde_json::{json, Map, Value};

use super::*;

const VECTORS: &str = include_str!("../tests/fixtures/custom_extension_continuity_vectors.json");

#[test]
fn continuity_matches_python_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("vectors");
    assert!(vectors.len() >= 300);
    for vector in &vectors {
        let got = evaluate(&vector["request"]).expect("answer");
        assert_eq!(got, vector["expected"], "vector {}", vector["name"]);
    }
}

/// The client sends no details first and adds the ones each answer names;
/// the final answer must match the vector recorded with every detail sent.
#[test]
fn plan_loads_only_the_details_it_reads() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("vectors");
    let mut fewer = 0;
    for vector in &vectors {
        let request = &vector["request"];
        if request["operation"] != "plan" {
            continue;
        }
        let all = request["details"].as_object().expect("details");
        let mut lazy = request.clone();
        lazy["details"] = json!({});
        let got = loop {
            let answer = evaluate(&lazy).expect("answer");
            let Some(wanted) = answer.get("need_details").and_then(Value::as_array) else {
                break answer;
            };
            assert!(!wanted.is_empty(), "vector {}", vector["name"]);
            for cli_id in wanted {
                let cli_id = cli_id.as_str().expect("cli id");
                assert!(
                    lazy["details"].get(cli_id).is_none(),
                    "vector {}",
                    vector["name"]
                );
                lazy["details"][cli_id] = all.get(cli_id).cloned().expect("known local");
            }
        };
        assert_eq!(got, vector["expected"], "vector {}", vector["name"]);
        if lazy["details"].as_object().map(Map::len) < Some(all.len()) {
            fewer += 1;
        }
    }
    assert!(fewer > 0);
}

#[test]
fn malformed_requests_are_errors_not_refusals() {
    for request in [
        json!({}),
        json!({"operation": "other"}),
        json!({"operation": "plan", "continuity": {}, "now": "x"}),
        json!({"operation": "local_mutation", "cli_id": "local-cli.a"}),
        json!({"operation": "public_state"}),
    ] {
        assert_eq!(evaluate(&request), Err(ERR_REQUEST), "{request}");
    }
}
