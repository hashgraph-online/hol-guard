//! Replays Codex detection vectors recorded from the original Python
//! implementation (see `testdata/codex/record_codex_vectors.py`). Fixture
//! trees and expected artifacts come from Python, never from Rust output.
//! `<ROOT>` is the fixture root; `<CMD>` stays literal in files and requests.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::codex_detect::detect;
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/codex/vectors.json");

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

/// `contents` carries file bytes as hex; `<ROOT>` inside them is expanded
/// before re-encoding, while `<CMD>` stays literal like it does in files.
fn expand_contents(args: &mut Value, root: &str) {
    let Some(contents) = args.get_mut("contents").and_then(Value::as_object_mut) else {
        return;
    };
    for value in contents.values_mut() {
        let Some(hex) = value.as_str() else { continue };
        let bytes = decode_hex(hex);
        let text = String::from_utf8_lossy(&bytes).replace("<ROOT>", root);
        *value = Value::String(
            text.bytes()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
    }
}

/// Replays one case; `Err` lists every field that differs from Python.
fn replay(case: &Value) -> Result<(), String> {
    let name = case["name"].as_str().unwrap();
    let root = temp_home(&format!("codex-{name}").chars().take(60).collect::<String>());
    materialize(&root, case);
    let root_text = root.to_string_lossy().into_owned();
    let mut args = substitute(&case["args"], &root_text);
    expand_contents(&mut args, &root_text);
    let result = detect(&args);
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
fn replays_every_recorded_codex_detection_case() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-codex-vectors.v1");
    let mut replayed = 0;
    let mut failures = Vec::new();
    for case in vectors["cases"].as_array().unwrap() {
        if let Err(message) = replay(case) {
            failures.push(message);
        }
        replayed += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(replayed >= 140, "only {replayed} cases recorded");
}

fn valid_request() -> Value {
    serde_json::json!({
        "harness": "codex",
        "authenticated_bindings": [],
        "sources": [{
            "config_path": "/tmp/h/.codex/config.toml",
            "hooks_path": "/tmp/h/.codex/hooks.json",
            "config_scope": "global",
            "hooks_scope": "global",
            "authenticated": true,
            "config_legacy": [],
            "hooks_legacy": []
        }],
        "contents": null
    })
}

#[test]
fn malformed_requests_are_refused() {
    assert!(detect(&valid_request()).is_ok());
    for (key, value) in [
        ("harness", serde_json::json!("hermes")),
        ("authenticated_bindings", serde_json::json!("x")),
        ("authenticated_bindings", serde_json::json!([1])),
        ("sources", serde_json::json!({})),
        ("sources", serde_json::json!([1])),
        ("contents", serde_json::json!([])),
        ("contents", serde_json::json!("x")),
    ] {
        let mut args = valid_request();
        args[key] = value.clone();
        assert!(detect(&args).is_err(), "{key}={value}");
    }
    for (key, value) in [
        ("config_path", serde_json::json!("relative.toml")),
        ("hooks_path", serde_json::json!(3)),
        ("config_scope", serde_json::json!(null)),
        ("hooks_scope", serde_json::json!(1)),
        ("authenticated", serde_json::json!("yes")),
        ("config_legacy", serde_json::json!({})),
        ("hooks_legacy", serde_json::json!([1])),
    ] {
        let mut args = valid_request();
        args["sources"][0][key] = value.clone();
        assert!(detect(&args).is_err(), "sources[0].{key}={value}");
    }
    assert!(detect(&serde_json::json!({})).is_err());
    assert!(detect(&serde_json::json!([])).is_err());
}

#[test]
fn undecodable_sources_are_refused() {
    let root = temp_home("codex-undecodable");
    for (name, bytes) in [
        ("config.toml", b"\xff".as_slice()),
        ("hooks.json", b"\xff".as_slice()),
    ] {
        fs::create_dir_all(root.join(".codex")).unwrap();
        fs::write(root.join(".codex").join(name), bytes).unwrap();
    }
    let mut args = valid_request();
    args["sources"][0]["config_path"] = serde_json::json!(root.join(".codex/config.toml"));
    args["sources"][0]["hooks_path"] = serde_json::json!(root.join(".codex/hooks.json"));
    assert!(detect(&args).is_err());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn only_a_number_the_parser_cannot_hold_refuses_a_toml_source() {
    use crate::codex_sources::{toml_payload, ERR_VALUE};

    for text in [
        "x = 99999999999999999999\n",
        "list = [1, 99999999999999999999]\n",
        "a = 99999999999999999999\nb = 18446744073709551616\n",
    ] {
        assert_eq!(
            toml_payload(Some(text.as_bytes())).err(),
            Some(ERR_VALUE),
            "{text}"
        );
    }
    for text in [
        "file123 = = 1\n",
        "n = 1000000000000000000 =\n",
        "sha = \"sha256:0123456789abcdef0123456789abcdef\" trailing\n",
        "big = 99999999999999999999 junk\n",
        "note = \"99999999999999999999\" =\n",
        "# 99999999999999999999\n= 1\n",
    ] {
        let payload = toml_payload(Some(text.as_bytes())).unwrap();
        assert!(payload.as_dict().is_some_and(<[_]>::is_empty), "{text}");
    }
    assert!(toml_payload(Some(b"n = 9223372036854775807\n")).is_ok());
}
