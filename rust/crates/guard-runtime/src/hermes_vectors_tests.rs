//! Replays Hermes detection vectors recorded from the original Python
//! implementation (see `testdata/zcode/record_hermes_vectors.py`). Fixture
//! trees and expected artifacts come from Python, never from Rust output.
//! `<ROOT>` is the fixture root.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::hermes_detect::detect;

const VECTORS: &str = include_str!("../testdata/hermes/vectors.json");

fn substitute(value: &Value, root: &str) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace("<ROOT>", root)),
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| substitute(item, root)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), substitute(item, root)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
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
            Some(hex) => fs::write(&path, decode_hex(hex)).unwrap(),
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
    for (relative, mode) in case["dir_modes"].as_object().unwrap() {
        fs::set_permissions(
            root.join(relative),
            fs::Permissions::from_mode(mode.as_u64().unwrap() as u32),
        )
        .unwrap();
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

/// Replays one case; `Err` lists every field that differs from Python.
fn replay(case: &Value) -> Result<(), String> {
    let name = case["name"].as_str().unwrap();
    let root = temp_home(
        &format!("hermes-{name}")
            .chars()
            .take(60)
            .collect::<String>(),
    );
    if case["requires_case_insensitive_fs"] == true && !folds_case(&root) {
        release(&root);
        return Ok(());
    }
    materialize(&root, case);
    let root_text = root.to_string_lossy().into_owned();
    let args = substitute(&case["args"], &root_text);
    let result = detect(&args);
    let outcome = check(case, name, &root_text, result);
    release(&root);
    outcome
}

/// Whether the fixture volume treats names that differ only in case as one.
fn folds_case(directory: &Path) -> bool {
    let probe = directory.join("CaseProbe");
    fs::write(&probe, b"").unwrap();
    let folded = directory.join("caseprobe").exists();
    fs::remove_file(&probe).unwrap();
    folded
}

fn check(
    case: &Value,
    name: &str,
    root_text: &str,
    result: Result<Value, &'static str>,
) -> Result<(), String> {
    if case["refused"] == true {
        return match result {
            Err(_) => Ok(()),
            Ok(_) => Err(format!("{name}: expected a refusal, the resident answered")),
        };
    }
    let answer = result.map_err(|code| format!("{name}: resident refused with {code}"))?;
    let mut mismatches = Vec::new();
    for field in ["artifacts", "found_paths", "warnings"] {
        if answer[field] != substitute(&case[field], root_text) {
            mismatches.push(format!(
                "{name}: {field}\n  resident: {}\n  python:   {}",
                answer[field],
                substitute(&case[field], root_text)
            ));
        }
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(mismatches.join("\n"))
    }
}

#[test]
fn replays_every_recorded_hermes_detection_case() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-hermes-vectors.v1");
    let mut replayed = 0;
    let mut failures = Vec::new();
    for case in vectors["cases"].as_array().unwrap() {
        if let Err(message) = replay(case) {
            failures.push(message);
        }
        replayed += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(replayed >= 95, "only {replayed} cases recorded");
}

#[test]
fn malformed_requests_are_refused() {
    let valid = serde_json::json!({
        "harness": "hermes", "hermes_home": "/tmp/x", "host_home": null,
        "managed_names": [], "manifest_path": "/tmp/m.json"
    });
    assert!(detect(&valid).is_ok());
    for (key, value) in [
        ("harness", serde_json::json!("zcode")),
        ("hermes_home", serde_json::json!("relative")),
        ("hermes_home", serde_json::json!(1)),
        ("host_home", serde_json::json!("relative")),
        ("manifest_path", serde_json::json!("relative")),
        ("managed_names", serde_json::json!([1])),
        ("managed_names", serde_json::json!("x")),
        ("skill_identities", serde_json::json!([])),
    ] {
        let mut args = valid.clone();
        args[key] = value.clone();
        assert!(detect(&args).is_err(), "{key}={value}");
    }
    assert!(detect(&serde_json::json!({})).is_err());
    assert!(detect(&serde_json::json!([])).is_err());
}

/// PyYAML's long timestamp form accepts a one-digit month or day when a time
/// follows. That value is not a string the config may apply.
#[test]
fn one_digit_timestamp_with_a_time_rejects_the_config() {
    let root = temp_home("hermes-stamp");
    let home = root.join("home/.hermes");
    fs::create_dir_all(&home).unwrap();
    fs::write(
        home.join("config.yaml"),
        "mcp_servers:\n  hidden:\n    command: evil\n    at: 2024-1-5 10:00:00\n",
    )
    .unwrap();
    let manifest = root.join("guard-home/hermes/manifest.json");
    fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    fs::write(&manifest, "{}\n").unwrap();
    let args = serde_json::json!({
        "harness": "hermes",
        "hermes_home": home.to_string_lossy(),
        "host_home": null,
        "managed_names": [],
        "manifest_path": manifest.to_string_lossy(),
    });
    let answer = detect(&args).expect("timestamp config");
    let artifacts = answer["artifacts"].as_array().expect("artifacts");
    assert!(
        artifacts
            .iter()
            .any(|artifact| { artifact["metadata"]["config_reason"] == "config_value_invalid" }),
        "{answer}"
    );
    assert!(
        artifacts
            .iter()
            .all(|artifact| artifact["command"] != "evil"),
        "{answer}"
    );
    let tagged =
        crate::hermes_yaml::load("mcp_servers:\n  one:\n    command: !!str tool\n").expect("yaml");
    let tagged = tagged.expect("!!str is a core tag");
    let command = tagged
        .get("mcp_servers")
        .and_then(|servers| servers.get("one"))
        .and_then(|server| server.get("command"))
        .and_then(|command| command.as_str());
    assert_eq!(command, Some("tool"));
}
