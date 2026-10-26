//! Replays Copilot detection vectors recorded from the original Python
//! implementation (see `testdata/copilot/record_copilot_vectors.py`). Fixture
//! trees and expected artifacts come from Python, never from Rust output.
//! `<ROOT>` is the fixture root.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::copilot_detect::detect;
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/copilot/vectors.json");

fn substitute(value: &Value, root: &str) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace("<ROOT>", root)),
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| substitute(item, root)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.replace("<ROOT>", root), substitute(item, root)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn materialize(root: &Path, case: &Value) {
    for name in ["work", "home"] {
        fs::create_dir_all(root.join(name)).unwrap();
    }
    let root_text = root.to_string_lossy();
    let mut locked: Vec<(PathBuf, u32)> = Vec::new();
    for entry in case["files"].as_array().unwrap() {
        let path = root.join(entry["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        match entry["hex"].as_str() {
            Some(text) => fs::write(&path, hex::decode(text).unwrap()).unwrap(),
            None => fs::write(&path, entry["text"].as_str().unwrap()).unwrap(),
        }
        locked.push((path, entry["mode"].as_u64().unwrap() as u32));
    }
    for relative in case["dirs"].as_array().unwrap() {
        fs::create_dir_all(root.join(relative.as_str().unwrap())).unwrap();
    }
    for entry in case["symlinks"].as_array().unwrap() {
        let path = root.join(entry["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let target = entry["target"]
            .as_str()
            .unwrap()
            .replace("<ROOT>", &root_text);
        symlink(target, path).unwrap();
    }
    for (path, mode) in locked {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// Restores access so the fixture tree can be removed.
fn release(root: &Path) {
    fn walk(path: &Path) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if metadata.file_type().is_symlink() {
            return;
        }
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o755));
        if metadata.is_dir() {
            for child in fs::read_dir(path).into_iter().flatten().flatten() {
                walk(&child.path());
            }
        }
    }
    walk(root);
    let _ = fs::remove_dir_all(root);
}

fn replay(case: &Value) {
    let name = case["name"].as_str().unwrap();
    let root = temp_home(
        &format!("copilot-{name}")
            .chars()
            .take(60)
            .collect::<String>(),
    );
    materialize(&root, case);
    let root_text = root.to_string_lossy().into_owned();
    let result = detect(&substitute(&case["args"], &root_text));
    if case["refused"] == true {
        assert!(
            result.is_err(),
            "{name}: Python refused, the resident answered {result:?}"
        );
        release(&root);
        return;
    }
    let answer = result.unwrap_or_else(|code| panic!("{name}: resident refused with {code}"));
    assert_eq!(
        answer["artifacts"],
        substitute(&case["artifacts"], &root_text),
        "{name}: artifacts"
    );
    assert_eq!(
        answer["found_paths"],
        substitute(&case["found_paths"], &root_text),
        "{name}: found paths"
    );
    assert_eq!(answer["warnings"], json!([]), "{name}: warnings");
    release(&root);
}

#[test]
fn replays_every_recorded_copilot_detection_case() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-copilot-vectors.v1");
    let mut replayed = 0;
    for case in vectors["cases"].as_array().unwrap() {
        replay(case);
        replayed += 1;
    }
    assert!(replayed >= 50, "only {replayed} cases recorded");
}

fn single_config(tag: &str, text: &str) -> (PathBuf, Value) {
    let root = temp_home(tag);
    let config = root.join("mcp-config.json");
    fs::write(&config, text).unwrap();
    let args = json!({
        "harness": "copilot",
        "sources": [{"path": config.to_string_lossy(), "scope": "global", "kind": "mcp"}],
    });
    (root, args)
}

/// CPython keeps an unpaired surrogate in a command it cannot later encode
/// into the inventory; the resident refuses the config instead. The oracle
/// answered this input, so it cannot sit in the recorded vectors.
#[test]
fn emitted_lone_surrogates_are_refused() {
    for text in [
        "{\"mcpServers\": {\"a\": {\"command\": \"\\ud800\"}}}",
        "{\"mcpServers\": {\"a\": {\"command\": \"x\", \"args\": [\"\\udc00\"]}}}",
        "{\"mcpServers\": {\"a\": {\"command\": \"x\", \"env\": {\"K\": \"\\ud800\"}}}}",
        "{\"preToolUse\": [{\"bash\": \"\\ud800\"}]}",
    ] {
        let (root, args) = single_config("copilot-surrogate", text);
        assert!(detect(&args).is_err(), "{text}");
        release(&root);
    }
}

/// Nesting past the parser's depth limit is refused rather than read as an
/// empty config. How deep CPython reads depends on its version, so this is
/// not a recorded vector.
#[test]
fn nesting_past_the_depth_limit_is_refused() {
    let text = format!("{{\"a\": {}{}}}", "[".repeat(5000), "]".repeat(5000));
    let (root, args) = single_config("copilot-deep", &text);
    assert!(detect(&args).is_err());
    release(&root);
}

#[test]
fn malformed_requests_are_refused() {
    for args in [
        json!({}),
        json!({"harness": "copilot"}),
        json!({"harness": "codex", "sources": []}),
        json!({"harness": "copilot", "sources": [{"path": "/tmp/x", "scope": "global"}]}),
        json!({"harness": "copilot", "sources": [{"path": "/tmp/x", "scope": "global", "kind": "other"}]}),
        json!({"harness": "copilot", "sources": [{"path": "/tmp/x", "scope": 1, "kind": "mcp"}]}),
        json!({"harness": "copilot", "sources": [], "contents": []}),
        json!({"harness": "copilot", "sources": [{"path": "/tmp/x", "scope": "global", "kind": "mcp"}],
            "contents": {}}),
        json!({"harness": "copilot", "sources": [{"path": "/tmp/x", "scope": "global", "kind": "mcp"}],
            "contents": {"/tmp/x": "zz"}}),
    ] {
        assert!(detect(&args).is_err(), "{args}");
    }
}
