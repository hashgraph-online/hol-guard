//! Replays the Pi extension sources the original Python builders wrote, and
//! pins the argument refusals.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::pi_extension_render::render;
use super::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/pi/pi_extension_render_vectors.json");

fn cases() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(document["schema"], "guard-pi-extension-render-vectors.v1");
    document["cases"].as_array().expect("cases").clone()
}

fn source(args: &Value) -> String {
    render(args).expect("renders")["source"]
        .as_str()
        .expect("source")
        .to_owned()
}

fn case_args(name: &str) -> Value {
    cases()
        .into_iter()
        .find(|case| case["name"] == name)
        .expect("case")["args"]
        .clone()
}

#[test]
fn every_recorded_source_replays() {
    let cases = cases();
    assert_eq!(cases.len(), 11);
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
fn harness_blocks_and_markers_never_reach_the_source() {
    for case in cases() {
        // A value may spell a marker on purpose; values are never rescanned.
        if case["args"].to_string().contains("@@") {
            continue;
        }
        let rendered = source(&case["args"]);
        for marker in ["@@if ", "@@fi@@", "@@begin ", "@@end "] {
            assert!(!rendered.contains(marker), "{} {marker}", case["name"]);
        }
    }
}

#[test]
fn a_placeholder_spelled_in_a_value_is_not_rescanned() {
    let mut args = case_args("active_omp_posix");
    args["guard_home"] = json!("/home/@@cli_command@@");
    assert!(source(&args).contains("\"/home/@@cli_command@@\""));
}

#[test]
fn values_are_spelled_as_python_json() {
    let mut args = case_args("active_pi_posix");
    args["guard_home"] = json!("/h\u{e9}/\u{1f600}\u{7f}");
    args["taskkill_path"] = Value::Null;
    let rendered = source(&args);
    assert!(rendered.contains("\"/h\\u00e9/\\ud83d\\ude00\\u007f\""));
}

#[test]
fn malformed_arguments_are_refused() {
    let active = case_args("active_omp_posix");
    let previous = case_args("previous_pi_posix");
    let mut refused = Vec::new();
    for (key, value) in [
        ("variant", json!("next")),
        ("harness", json!("codex")),
        ("display_name", json!(7)),
        ("guard_args", json!(["--guard-home", 7])),
        ("guard_home", Value::Null),
        ("home_dir_is_default", json!("false")),
        ("compatibility_version", json!(7.0)),
        ("compatibility_version", json!(true)),
        ("compatibility_version", json!("7")),
        ("cli_args", json!("hook")),
        ("taskkill_path", json!(7)),
        ("native_hook_runtime", json!(["runtime"])),
        ("contained_sink_command", json!("sink")),
        ("contained_request_root", Value::Null),
    ] {
        let mut args = active.clone();
        args[key] = value;
        refused.push(args);
    }
    let mut extra = active.clone();
    extra["unexpected"] = json!(true);
    refused.push(extra);
    let mut missing = active.clone();
    missing
        .as_object_mut()
        .expect("object")
        .remove("taskkill_path");
    refused.push(missing);
    let mut previous_with_active_field = previous.clone();
    previous_with_active_field["contained_request_root"] = json!("/root");
    refused.push(previous_with_active_field);
    let mut active_without_its_fields = active.clone();
    for key in [
        "native_hook_runtime",
        "contained_sink_command",
        "contained_request_root",
    ] {
        active_without_its_fields
            .as_object_mut()
            .expect("object")
            .remove(key);
    }
    refused.push(active_without_its_fields);
    refused.push(json!([]));
    for args in refused {
        assert_eq!(render(&args), Err(ERR_INVALID), "{args}");
    }
}

#[test]
fn a_null_native_hook_runtime_renders() {
    let mut args = case_args("active_omp_posix");
    args["native_hook_runtime"] = Value::Null;
    assert!(source(&args).contains("const GUARD_NATIVE_HOOK_RUNTIME: string | null = null;"));
}

#[test]
fn display_name_cannot_break_generated_javascript() {
    let mut args = case_args("active_pi_posix");
    args["display_name"] = json!("Pi'; throw new Error(\"injected\"); \" ` ${process.env.PWN}");
    let rendered = source(&args);
    assert!(!rendered.contains("Pi'; throw new Error"));
    assert!(rendered.contains("Pi\\'"));
    assert!(rendered.contains("\\\""));
    assert!(rendered.contains("\\`"));
    assert!(rendered.contains("\\${process.env.PWN}"));
}
