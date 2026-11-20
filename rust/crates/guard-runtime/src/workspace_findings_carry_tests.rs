use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn finding(id: &str, detector: &str) -> Value {
    json!({"finding_id": id, "detector": detector, "severity": "high"})
}

fn request(detectors: Value, findings: Value, earlier: Value) -> Value {
    json!({
        "coverage": {"reasons": ["ci_incomplete"], "detectors": detectors},
        "findings": findings,
        "earlier": earlier,
        "run_id": "r1",
        "settled": [],
        "max_findings": 500,
        "byte_budget": 261_120,
    })
}

fn carried_ids(answer: &Value) -> Vec<String> {
    answer["carried"]
        .as_array()
        .expect("carried")
        .iter()
        .map(|item| item["finding_id"].as_str().expect("id").to_owned())
        .collect()
}

#[test]
fn an_unfinished_detector_carries_its_earlier_findings() {
    let answer = dispatch(&request(
        json!({"ci": "incomplete"}),
        json!([]),
        json!([finding("a", "ci")]),
    ))
    .expect("answer");
    assert_eq!(
        answer["carried"],
        json!([{"finding_id": "a", "detector": "ci", "severity": "high", "carried_from_run_id": "r1"}])
    );
    assert_eq!(answer["reasons"], json!(["ci_incomplete"]));
}

#[test]
fn a_carried_finding_keeps_the_run_that_last_observed_it() {
    let mut earlier = finding("a", "ci");
    earlier["carried_from_run_id"] = json!("r0");
    let mut empty_origin = finding("b", "ci");
    empty_origin["carried_from_run_id"] = json!("");
    let answer = dispatch(&request(
        json!({"ci": "not_run"}),
        json!([]),
        json!([earlier, empty_origin]),
    ))
    .expect("answer");
    assert_eq!(answer["carried"][0]["carried_from_run_id"], "r0");
    assert_eq!(answer["carried"][1]["carried_from_run_id"], "r1");
}

#[test]
fn rechecked_retired_settled_and_repeated_findings_are_not_carried() {
    let mut args = request(
        json!({"ci": "complete", "secrets": "no_inputs", "supply_chain": "incomplete", "lint": "incomplete"}),
        json!([finding("seen", "lint")]),
        json!([
            finding("ci", "ci"),
            finding("secrets", "secrets"),
            finding("retired", "retired_v0"),
            finding("settled", "supply_chain_local_v1"),
            finding("seen", "lint"),
            finding("package", "supply_chain_local_v1"),
            {"finding_id": "nameless"},
            "text",
        ]),
    );
    args["settled"] = json!([false, false, false, true]);
    let answer = dispatch(&args).expect("answer");
    assert_eq!(carried_ids(&answer), vec!["package"]);
}

#[test]
fn nothing_to_carry_changes_nothing() {
    for args in [
        request(
            json!({"ci": "complete"}),
            json!([]),
            json!([finding("a", "ci")]),
        ),
        request(json!({"ci": "incomplete"}), json!([]), json!([])),
        request(json!({"ci": "incomplete"}), json!([]), Value::Null),
        request(Value::Null, json!([]), json!([finding("a", "ci")])),
    ] {
        assert_eq!(dispatch(&args), Ok(json!({"carried": null})), "{args}");
    }
}

#[test]
fn carried_findings_stop_at_the_count_and_byte_bounds() {
    let earlier: Vec<Value> = (0..4)
        .map(|index| finding(&format!("e{index}"), "ci"))
        .collect();
    let mut args = request(
        json!({"ci": "incomplete"}),
        json!([finding("own", "lint")]),
        json!(earlier),
    );
    args["coverage"]["reasons"] = json!(["ci_incomplete", 7]);
    args["max_findings"] = json!(3);
    let answer = dispatch(&args).expect("answer");
    assert_eq!(carried_ids(&answer), vec!["e0", "e1"]);
    assert_eq!(
        answer["reasons"],
        json!(["ci_incomplete", "7", "carried_finding_cap"])
    );

    // The run's own finding is 56 bytes and each carried entry 80; one
    // byte each separates them.
    args["max_findings"] = json!(500);
    args["byte_budget"] = json!(57 + 81);
    args["coverage"]["reasons"] = json!(["carried_finding_cap"]);
    let answer = dispatch(&args).expect("answer");
    assert_eq!(carried_ids(&answer), vec!["e0"]);
    assert_eq!(answer["reasons"], json!(["carried_finding_cap"]));
}

#[test]
fn sizes_count_python_ascii_escapes() {
    // "é" is stored as `é`: six bytes, not two. A budget sized for
    // the UTF-8 text would admit the finding Python refuses.
    let mut earlier = finding("a", "ci");
    earlier["severity"] = json!("é");
    let mut args = request(json!({"ci": "incomplete"}), json!([]), json!([earlier]));
    args["byte_budget"] = json!(81);
    let answer = dispatch(&args).expect("answer");
    assert_eq!(answer["carried"], json!([]));
    assert_eq!(
        answer["reasons"],
        json!(["ci_incomplete", "carried_finding_cap"])
    );
    args["byte_budget"] = json!(82);
    assert_eq!(carried_ids(&dispatch(&args).expect("answer")), vec!["a"]);
}

#[test]
fn malformed_requests_are_refused() {
    let valid = request(json!({"ci": "incomplete"}), json!([]), json!([]));
    let mut cases = Vec::new();
    for (key, value) in [
        ("coverage", json!([])),
        ("findings", json!(["text"])),
        ("settled", json!([1])),
        ("max_findings", json!(-1)),
        ("byte_budget", json!("1")),
        ("extra", json!(1)),
    ] {
        let mut args = valid.clone();
        args[key] = value;
        cases.push(args);
    }
    let mut missing = valid.clone();
    missing.as_object_mut().expect("object").remove("run_id");
    cases.push(missing);
    cases.push(json!([]));
    for args in cases {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
