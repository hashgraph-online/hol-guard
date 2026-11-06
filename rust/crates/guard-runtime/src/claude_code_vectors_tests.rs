//! Replays Claude Code detection vectors recorded from the original Python
//! implementation (see `testdata/claude_code/record_claude_code_vectors.py`). Fixture
//! trees and expected artifacts come from Python, never from Rust output.
//! `<ROOT>` is the fixture root.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::claude_code_detect::detect;
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/claude_code/vectors.json");

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
    let work_is_link = case["symlinks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["path"] == "work");
    if !work_is_link {
        fs::create_dir_all(root.join("work")).unwrap();
    }
    fs::create_dir_all(root.join(case["home"].as_str().unwrap())).unwrap();
    let root_text = root.to_string_lossy();
    let mut locked: Vec<(PathBuf, u32)> = Vec::new();
    for entry in case["files"].as_array().unwrap() {
        let path = root.join(entry["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        match entry["hex"].as_str() {
            Some(hex) => fs::write(&path, decode_hex(hex)).unwrap(),
            None => fs::write(
                &path,
                entry["text"]
                    .as_str()
                    .unwrap()
                    .replace("<ROOT>", &root_text),
            )
            .unwrap(),
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
        &format!("claude-{name}")
            .chars()
            .take(60)
            .collect::<String>(),
    );
    materialize(&root, case);
    let root_text = root.to_string_lossy().into_owned();
    let result = detect(&substitute(&case["args"], &root_text));
    let outcome = check(case, name, &root_text, result);
    release(&root);
    outcome
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
            Ok(answer) => Err(format!(
                "{name}: expected a refusal, the resident answered {answer}"
            )),
        };
    }
    let answer = result.map_err(|code| format!("{name}: resident refused with {code}"))?;
    let mut mismatches = Vec::new();
    for field in ["artifacts", "found_paths"] {
        let expected = substitute(&case[field], root_text);
        if answer[field] != expected {
            mismatches.push(format!(
                "{name}: {field}\n  resident: {}\n  python:   {expected}",
                answer[field]
            ));
        }
    }
    if answer["warnings"] != json!([]) {
        mismatches.push(format!("{name}: warnings {}", answer["warnings"]));
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(mismatches.join("\n"))
    }
}

#[test]
fn replays_every_recorded_claude_code_detection_case() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-claude-code-vectors.v1");
    let mut replayed = 0;
    let mut failures = Vec::new();
    for case in vectors["cases"].as_array().unwrap() {
        if let Err(message) = replay(case) {
            failures.push(message);
        }
        replayed += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(replayed >= 50, "only {replayed} cases recorded");
}

#[test]
fn malformed_requests_are_refused() {
    let valid = json!({"harness": "claude-code", "home": "/nonexistent/h", "workspace": null});
    assert!(detect(&valid).is_ok());
    for (key, value) in [
        ("harness", json!("claude")),
        ("harness", json!(1)),
        ("home", json!(null)),
        ("home", json!(1)),
        ("workspace", json!(1)),
        ("workspace", json!("work")),
        ("cwd", json!("relative")),
        ("cwd", json!(1)),
    ] {
        let mut args = valid.clone();
        args[key] = value.clone();
        assert!(detect(&args).is_err(), "{key}={value}");
    }
    assert!(detect(&json!({"harness": "claude-code"})).is_err());
    assert!(detect(&json!({})).is_err());
    assert!(detect(&json!([])).is_err());
}

/// Python hands a header value carrying a lone surrogate to the digest op,
/// which cannot decode it, and keeps the server with unbound digests; the
/// resident refuses the inventory instead of inventing a binding.
#[test]
fn header_value_lone_surrogate_is_refused() {
    let root = temp_home("claude-header-surrogate");
    let settings = root.join("home/.claude/settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{"mcpServers": {"a": {"url": "https://a", "headers": {"K": "\udc00"}}}}"#,
    )
    .unwrap();
    let home = root.join("home").to_string_lossy().into_owned();
    let result = detect(&json!({"harness": "claude-code", "home": home}));
    release(&root);
    assert!(result.is_err(), "{result:?}");
}
