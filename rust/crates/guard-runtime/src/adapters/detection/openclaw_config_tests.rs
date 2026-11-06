//! Replays OpenClaw configuration-loading vectors recorded from the original
//! Python loader (see `testdata/openclaw/record_openclaw_config_vectors.py`).
//! Fixture trees and expected payloads come from Python, never from Rust
//! output. `<ROOT>` is the fixture root.

use std::fs;

use serde_json::{json, Value};

use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::openclaw_config::{load, ERR_CONFIG_TOO_LARGE};
use crate::pi_vectors_tests::{materialize, release, substitute};
use crate::pyjson::parse_marking_lone_surrogates;

const VECTORS: &str = include_str!("../../../testdata/openclaw/config_vectors.json");
const CONFIG: &str = "home/.openclaw/openclaw.json";

#[test]
fn replays_every_recorded_openclaw_config_case() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-openclaw-config-vectors.v1");
    let mut replayed = 0;
    let mut failures = Vec::new();
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let root = temp_home(&format!("occ-{name}").chars().take(60).collect::<String>());
        materialize(&root, case);
        let root_text = root.to_string_lossy().into_owned();
        // `{:?}` compares NaN with NaN, which `PartialEq` never does.
        let answer = load(&root.join(CONFIG), None).map(|value| format!("{value:?}"));
        let expected = if case["refused"] == true {
            None
        } else {
            let payload = substitute(&case["payload"], &root_text);
            let payload = parse_marking_lone_surrogates(payload.as_str().unwrap()).unwrap();
            Some(format!("{payload:?}"))
        };
        match (&answer, &expected) {
            (Err(_), None) => {}
            (Ok(answer), Some(expected)) if answer == expected => {}
            _ => failures.push(format!(
                "{name}\n  resident: {answer:?}\n  python:   {expected:?}"
            )),
        }
        release(&root);
        replayed += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(replayed >= 35, "only {replayed} cases recorded");
}

#[test]
fn an_include_spelled_with_a_tilde_reads_the_callers_home() {
    let root = temp_home("occ-tilde");
    let config = root.join("cfg/openclaw.json");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::create_dir_all(root.join("home/sub")).unwrap();
    fs::write(
        &config,
        r#"{"$include": ["~/sub/a.json", " ~ ", "~"], "z": 0}"#,
    )
    .unwrap();
    fs::write(root.join("home/sub/a.json"), r#"{"a": 1}"#).unwrap();
    let home = root.join("home");
    let loaded = load(&config, home.to_str()).unwrap().to_json().unwrap();
    assert_eq!(loaded, json!({"a": 1, "z": 0}));
    let unexpanded = load(&config, None).unwrap().to_json().unwrap();
    assert_eq!(unexpanded, json!({"z": 0}));
    release(&root);
}

#[test]
fn input_python_cannot_parse_is_refused() {
    let root = temp_home("occ-refused");
    let config = root.join("openclaw.json");
    for text in [
        format!("{{\"a\": {}}}", "9".repeat(5000)),
        format!("{}{}", "[".repeat(2000), "]".repeat(2000)),
    ] {
        fs::write(&config, text).unwrap();
        assert!(load(&config, None).is_err());
    }
    release(&root);
}

#[test]
fn a_configuration_past_the_read_limit_is_refused_not_dropped() {
    let root = temp_home("occ-oversized");
    let config = root.join("openclaw.json");
    let padding = " ".repeat(8 * 1024 * 1024);
    fs::write(&config, format!("{{\"a\": 1}}{padding}")).unwrap();
    assert_eq!(load(&config, None).unwrap_err(), ERR_CONFIG_TOO_LARGE);
    fs::write(&config, r#"{"$include": "big.json", "a": 1}"#).unwrap();
    fs::write(root.join("big.json"), format!("{{\"b\": 1}}{padding}")).unwrap();
    assert_eq!(load(&config, None).unwrap_err(), ERR_CONFIG_TOO_LARGE);
    fs::write(root.join("big.json"), r#"{"b": 1}"#).unwrap();
    let loaded = load(&config, None).unwrap().to_json().unwrap();
    assert_eq!(loaded, json!({"b": 1, "a": 1}));
    release(&root);
}
