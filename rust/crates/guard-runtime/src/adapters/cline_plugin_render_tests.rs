//! Replays the Cline plugin sources the original Python builder wrote, and
//! pins the argument refusals.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::cline_plugin_render::render;
use super::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/cline/cline_plugin_render_vectors.json");

fn cases() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(document["schema"], "guard-cline-plugin-render-vectors.v1");
    document["cases"].as_array().expect("cases").clone()
}

fn source(args: &Value) -> String {
    render(args).expect("renders")["source"]
        .as_str()
        .expect("source")
        .to_owned()
}

#[test]
fn every_recorded_source_replays() {
    let cases = cases();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let rendered = source(&case["args"]);
        assert_eq!(
            rendered.chars().count() as u64,
            case["chars"].as_u64().expect("chars"),
            "{}",
            case["name"]
        );
        assert_eq!(
            hex::encode(Sha256::digest(rendered.as_bytes())),
            case["sha256"].as_str().expect("sha256"),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn the_source_carries_the_managed_marker_and_no_placeholder() {
    for case in cases() {
        let rendered = source(&case["args"]);
        assert!(rendered.starts_with("// HOL_GUARD_MANAGED_CLINE_PLUGIN_V1\n"));
        assert!(rendered.ends_with("export default plugin;\n"));
    }
    let mut args = cases()[0]["args"].clone();
    args["adapter_state"] = json!("/state/@@guard_cli@@");
    assert!(source(&args).contains("const ADAPTER_STATE = \"/state/@@guard_cli@@\";"));
}

#[test]
fn malformed_arguments_are_refused() {
    let base = cases()[0]["args"].clone();
    let mut refused = Vec::new();
    for (key, value) in [
        ("guard_cli", json!("python")),
        ("guard_cli", json!(["python", 7])),
        ("hook_argv", Value::Null),
        ("adapter_state", json!(["/state"])),
        ("proof_loaded", Value::Null),
        ("proof_pretool", json!(7)),
        ("proof_posttool", json!(false)),
    ] {
        let mut args = base.clone();
        args[key] = value;
        refused.push(args);
    }
    let mut extra = base.clone();
    extra["unexpected"] = json!("x");
    refused.push(extra);
    let mut missing = base.clone();
    missing
        .as_object_mut()
        .expect("object")
        .remove("proof_posttool");
    refused.push(missing);
    refused.push(json!([]));
    for args in refused {
        assert_eq!(render(&args), Err(ERR_INVALID), "{args}");
    }
}
