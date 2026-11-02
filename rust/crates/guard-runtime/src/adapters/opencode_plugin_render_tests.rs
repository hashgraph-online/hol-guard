//! Replays OpenCode pretool plugin vectors recorded from the original Python
//! renderer (see `testdata/opencode/record_plugin_render_vectors.py`). Every
//! expected source comes from Python, never from Rust output.

use serde_json::{json, Value};

use crate::opencode_plugin_render::render;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/opencode/plugin_render_vectors.json");

fn cases() -> Vec<Value> {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-opencode-plugin-render-vectors.v1");
    vectors["cases"].as_array().unwrap().clone()
}

#[test]
fn replays_every_recorded_plugin_source() {
    let mut failures = Vec::new();
    let cases = cases();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let answer = render(&case["args"]);
        let expected = case["source"].as_str().unwrap();
        match answer {
            Ok(answer) if answer == json!({ "source": expected }) => {}
            Ok(answer) => {
                let source = answer["source"].as_str().unwrap_or_default();
                let at = source
                    .chars()
                    .zip(expected.chars())
                    .position(|(left, right)| left != right)
                    .unwrap_or(source.len().min(expected.len()));
                let window = |text: &str| text.chars().skip(at).take(120).collect::<String>();
                failures.push(format!(
                    "{name}: first difference at char {at}\n  resident: {:?}\n  python:   {:?}",
                    window(source),
                    window(expected),
                ));
            }
            Err(error) => failures.push(format!("{name}: refused with {error}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(cases.len() >= 9, "only {} cases recorded", cases.len());
}

#[test]
fn a_request_with_a_missing_extra_or_mistyped_field_is_refused() {
    let base = cases()[0]["args"].clone();
    let mut extra = base.clone();
    extra["unexpected"] = json!(true);
    let mut missing = base.clone();
    missing.as_object_mut().unwrap().remove("taskkill_path");
    let mut frozen = base.clone();
    frozen["frozen"] = json!("false");
    let mut stat = base.clone();
    stat["python"]["target_stat"]["mtime_ns"] = json!("1");
    let mut float_stat = base.clone();
    float_stat["python"]["invocation_stat"]["size"] = json!(1.5);
    let mut root = base.clone();
    root["import_roots"] = json!(["/ok", 7]);
    let mut argv = base.clone();
    argv["native_bridge_argv"] = json!("bounded-hook-bridge");
    for (label, request) in [
        ("extra", extra),
        ("missing", missing),
        ("frozen", frozen),
        ("stat", stat),
        ("float stat", float_stat),
        ("import root", root),
        ("argv", argv),
    ] {
        assert_eq!(render(&request).unwrap_err(), ERR_INVALID, "{label}");
    }
}

#[test]
fn a_bridge_config_with_a_lone_surrogate_or_bad_json_is_refused() {
    let mut request = cases()[0]["args"].clone();
    let argv = request["native_bridge_argv"].as_array_mut().unwrap();
    argv[6] = json!(r#"{"guard_home":"\ud800"}"#);
    assert_eq!(render(&request).unwrap_err(), ERR_INVALID);
    let argv = request["native_bridge_argv"].as_array_mut().unwrap();
    argv[6] = json!("{not json");
    assert_eq!(render(&request).unwrap_err(), ERR_INVALID);
}
