//! Replays `description_vectors.json`, recorded from the original Python
//! `resolve_inventory_item_description`, through the native operation.

use serde_json::{json, Value};

use crate::inventory_export_redaction::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str =
    include_str!("../testdata/inventory_item_description/description_vectors.json");

fn described(request: &Value) -> String {
    let answer = dispatch(request).expect("answer");
    answer["description"]
        .as_str()
        .expect("description")
        .to_owned()
}

fn request(description: &str, home_dir: Value, workspace_dir: Value) -> Value {
    json!({
        "op": "item_description",
        "harness": "codex",
        "item_kind": "skill",
        "display_name": "s",
        "publisher": null,
        "explicit_description": null,
        "metadata_descriptions": [description, null, null, null],
        "home_dir": home_dir,
        "workspace_dir": workspace_dir,
        "cwd": "/",
    })
}

#[test]
fn descriptions_match_the_python_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    for case in vectors.as_array().expect("cases") {
        assert_eq!(
            described(&case["request"]),
            case["expected"].as_str().expect("expected"),
            "{}",
            case["label"]
        );
    }
}

#[test]
fn a_known_home_redacts_paths_the_way_finding_text_does() {
    // The vectors were recorded without a home: that half of the Python went
    // through the resident, so these pin it from the redaction rules instead.
    if cfg!(windows) {
        return;
    }
    let home = json!("/opt/agent");
    let workspace = json!("/srv/proj");
    assert_eq!(
        described(&request(
            "Plain  words\tonly.",
            home.clone(),
            workspace.clone()
        )),
        "Plain words only."
    );
    assert_eq!(
        described(&request(
            "Runs /srv/proj/tool.sh and /opt/agent/notes.txt",
            home.clone(),
            workspace.clone()
        )),
        "Runs {workspace}/tool.sh and {home}/notes.txt"
    );
    assert_eq!(
        described(&request("Uses /srv/proj/x.bin", home.clone(), Value::Null)),
        "Uses x.bin"
    );
    // Without a home the workspace is never consulted.
    assert_eq!(
        described(&request("Uses /srv/proj/x.bin", Value::Null, workspace)),
        "Uses /srv/proj/x.bin"
    );
}

#[test]
fn a_known_home_cuts_the_text_before_it_is_cleaned() {
    // `_safe_finding_text` keeps 500 characters, so the cleaned text fits and
    // carries no ellipsis.
    let long = "w ".repeat(400);
    let expected = "w ".repeat(250);
    let answer = described(&request(&long, json!("/opt/agent"), Value::Null));
    assert_eq!(answer, expected.trim_end());
    assert_eq!(answer.chars().count(), 499);
}

#[test]
fn malformed_requests_are_refused() {
    let valid = request("d", Value::Null, Value::Null);
    assert!(dispatch(&valid).is_ok());
    for key in [
        "harness",
        "item_kind",
        "display_name",
        "publisher",
        "explicit_description",
        "metadata_descriptions",
        "home_dir",
        "workspace_dir",
        "cwd",
    ] {
        let mut missing = valid.clone();
        missing.as_object_mut().expect("object").remove(key);
        assert_eq!(dispatch(&missing), Err(ERR_INVALID), "{key}");
        let mut wrong = valid.clone();
        wrong[key] = json!(1);
        assert_eq!(dispatch(&wrong), Err(ERR_INVALID), "{key}");
    }
    for key in ["harness", "item_kind", "display_name", "cwd"] {
        let mut wrong = valid.clone();
        wrong[key] = Value::Null;
        assert_eq!(dispatch(&wrong), Err(ERR_INVALID), "{key}");
    }
    for descriptions in [
        json!([]),
        json!(["a", null, null]),
        json!(["a", null, null, null, null]),
        json!([1, null, null, null]),
        json!({"description": "a"}),
    ] {
        let mut wrong = valid.clone();
        wrong["metadata_descriptions"] = descriptions;
        assert_eq!(dispatch(&wrong), Err(ERR_INVALID));
    }
    let mut extra = valid.clone();
    extra["other"] = json!("");
    assert_eq!(dispatch(&extra), Err(ERR_INVALID));
}
