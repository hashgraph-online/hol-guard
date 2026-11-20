//! Replays `config_normalize_vectors.json`, recorded from the original Python
//! `_normalized_config_payload`, through the native kind.

use serde_json::{json, Value};

use crate::opencode_config_normalize::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../testdata/opencode/config_normalize_vectors.json");
const GUARD_HOME: &str = "/opt/hg-test/home";
const CONFIG_PATH: &str = "/opt/hg-test/work/opencode.json";

fn request(config: &str, scope: &str) -> Value {
    json!({
        "config": config,
        "scope": scope,
        "config_path": CONFIG_PATH,
        "guard_home": GUARD_HOME,
        "cwd": "/",
    })
}

fn normalized(config: &str, scope: &str) -> String {
    let answer = dispatch(&request(config, scope)).expect("answer");
    answer["config"].as_str().expect("config text").to_owned()
}

fn refreshable(config: &str, scope: &str) -> String {
    let mut asked = request(config, scope);
    asked["op"] = json!("refreshable");
    let answer = dispatch(&asked).expect("answer");
    answer["names"].as_str().expect("names text").to_owned()
}

#[test]
fn normalized_configs_match_the_python_vectors() {
    // The vectors were recorded on a POSIX host, where these paths are
    // absolute and a command's name follows its last forward slash.
    if cfg!(windows) {
        return;
    }
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    for case in vectors.as_array().expect("cases") {
        let config = case["config"].as_str().expect("config");
        let scope = case["scope"].as_str().expect("scope");
        assert_eq!(
            normalized(config, scope),
            case["expected"].as_str().expect("expected"),
            "{}",
            case["label"]
        );
        assert_eq!(
            refreshable(config, scope),
            case["refreshable"].as_str().expect("refreshable"),
            "{}",
            case["label"]
        );
    }
}

#[test]
fn a_relative_path_without_a_working_directory_never_matches() {
    if cfg!(windows) {
        return;
    }
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let dotted = vectors
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["label"] == "dotted config path resolves equal")
        .expect("dotted case");
    let config = dotted["config"].as_str().expect("config");
    let mut relative = request(config, "global");
    relative["guard_home"] = json!("opt/hg-test/home");
    relative["cwd"] = json!("");
    let answer = dispatch(&relative).expect("answer");
    let text = answer["config"].as_str().expect("config text");
    assert!(text.contains("hol-guard::srv"), "{text}");
    relative["cwd"] = json!("/");
    let answer = dispatch(&relative).expect("answer");
    let text = answer["config"].as_str().expect("config text");
    assert!(!text.contains("hol-guard::srv"), "{text}");
}

#[test]
fn private_use_characters_without_a_lone_surrogate_are_kept() {
    assert_eq!(
        normalized(r#"{"mcp": {"󰀀": {"command": ["x"]}}}"#, "global"),
        "{\"mcp\":{\"\u{f0000}\":{\"command\":[\"x\"]}}}"
    );
}

#[test]
fn malformed_requests_are_refused() {
    let valid = request("{}", "global");
    assert!(dispatch(&valid).is_ok());
    for key in ["config", "scope", "config_path", "guard_home", "cwd"] {
        let mut missing = valid.clone();
        missing.as_object_mut().expect("object").remove(key);
        assert_eq!(dispatch(&missing), Err(ERR_INVALID), "{key}");
        let mut wrong = valid.clone();
        wrong[key] = json!(1);
        assert_eq!(dispatch(&wrong), Err(ERR_INVALID), "{key}");
    }
    let mut extra = valid.clone();
    extra["other"] = json!("");
    assert_eq!(dispatch(&extra), Err(ERR_INVALID));
    let mut asked = valid.clone();
    asked["op"] = json!("refreshable");
    assert!(dispatch(&asked).is_ok());
    for op in [json!("other"), json!(1), Value::Null] {
        let mut wrong = valid.clone();
        wrong["op"] = op;
        assert_eq!(dispatch(&wrong), Err(ERR_INVALID));
    }
    asked["other"] = json!("");
    assert_eq!(dispatch(&asked), Err(ERR_INVALID));
    for config in ["[]", "{", "1", r#"{"a\ud800": "󰀀"}"#] {
        assert_eq!(
            dispatch(&request(config, "global")),
            Err(ERR_INVALID),
            "{config}"
        );
    }
}
