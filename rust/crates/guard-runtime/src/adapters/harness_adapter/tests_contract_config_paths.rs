//! `existing_contract_config_paths`: the contract paths that exist.

use std::fs;

use serde_json::{json, Value};

use super::super::contract_config_paths::{matches, wild};
use super::super::dispatch;
use super::Home;

fn existing(home: &Home, harness: &str) -> Value {
    let request = json!({
        "op": "existing_contract_config_paths",
        "context": home.context(json!({})),
        "harness": harness,
    });
    dispatch(&request).unwrap()["config_paths"].clone()
}

#[test]
fn only_the_paths_that_exist_are_named() {
    let home = Home::new();
    assert_eq!(existing(&home, "claude-code"), json!([]));
    let settings = home.home().join(".claude/settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "{}").unwrap();
    assert_eq!(
        existing(&home, "claude-code"),
        json!([settings.to_string_lossy()])
    );
}

#[test]
fn a_directory_path_loses_its_trailing_slash() {
    let home = Home::new();
    let hooks = home.home().join(".cline/hooks");
    fs::create_dir_all(&hooks).unwrap();
    assert_eq!(existing(&home, "cline"), json!([hooks.to_string_lossy()]));
}

#[test]
fn a_harness_without_a_contract_has_no_paths() {
    let home = Home::new();
    assert_eq!(existing(&home, "no-such-harness"), json!([]));
}

#[test]
fn a_wildcard_segment_matches_the_entries_of_its_directory() {
    let home = Home::new();
    let extensions = home.home().join(".pi/agent/extensions");
    fs::create_dir_all(&extensions).unwrap();
    fs::write(extensions.join("b.ts"), "").unwrap();
    fs::write(extensions.join("a.ts"), "").unwrap();
    fs::write(extensions.join(".hidden.ts"), "").unwrap();
    fs::write(extensions.join("c.js"), "").unwrap();
    let paths = existing(&home, "pi");
    assert_eq!(
        paths,
        json!([
            extensions.join("a.ts").to_string_lossy(),
            extensions.join("b.ts").to_string_lossy()
        ])
    );
}

#[test]
fn wildcards_follow_fnmatch() {
    assert!(matches("*.ts", "a.ts"));
    assert!(!matches("*.ts", "a.js"));
    assert!(!matches("*.ts", ".a.ts"));
    assert!(matches(".*.ts", ".a.ts"));
    assert!(matches("a?c", "abc"));
    assert!(!matches("a?c", "ac"));
    assert!(matches("[ab]x", "bx"));
    assert!(!matches("[!ab]x", "bx"));
    assert!(matches("[a-c]x", "cx"));
    assert!(wild(&['*'], &[]));
}

#[test]
fn the_bundled_contracts_stay_inside_what_the_matcher_covers() {
    let document: Value =
        serde_json::from_str(crate::harness_protection_contract::CONTRACT).unwrap();
    for row in document["contracts"].as_array().unwrap() {
        for path in row["config_paths"].as_array().unwrap() {
            let path = path.as_str().unwrap();
            assert!(!path.contains("**"), "{path}");
        }
    }
}
