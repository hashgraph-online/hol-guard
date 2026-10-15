//! Parity with the Python Codex hook bridge, recorded before the port.

use serde_json::Value;

use super::*;
use crate::hook_env_stamp::dumps;
use crate::pyjson::parse_mapping_lone_surrogates;

const VECTORS: &str = include_str!("../testdata/codex_hook_bridge/vectors.json");

fn vectors(section: &str) -> Vec<Value> {
    let all: Value = serde_json::from_str(VECTORS).unwrap();
    all[section].as_array().unwrap().clone()
}

fn entries(text: &str) -> Vec<(String, PyVal)> {
    match parse_mapping_lone_surrogates(text).ok().unwrap().value {
        PyVal::Dict(entries) => entries,
        other => panic!("not an object: {other:?}"),
    }
}

#[test]
fn responses_are_shaped_as_python_shapes_them() {
    let cases = vectors("shape");
    assert!(cases.len() > 100);
    for case in cases {
        let response = case["response"].as_str().unwrap();
        let event = case["event"].as_str().unwrap();
        let mut rendered = String::new();
        dumps(
            &codex_hook_response(&entries(response), event),
            true,
            false,
            &mut rendered,
        );
        assert_eq!(
            rendered,
            case["expected"].as_str().unwrap(),
            "{event} {response}"
        );
    }
}

#[test]
fn fail_closed_matches_python() {
    for case in vectors("fail_closed") {
        let event = case["event"].as_str().unwrap();
        assert_eq!(
            fail_closed(event),
            case["expected"].as_str().unwrap(),
            "{event:?}"
        );
    }
}

#[test]
fn event_names_match_python() {
    for case in vectors("event_names") {
        let payload = case["payload"].as_str().unwrap();
        assert_eq!(
            runtime_hook_event_name(&entries(payload)),
            case["expected"].as_str().unwrap(),
            "{payload}"
        );
    }
}
