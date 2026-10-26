//! Replays ZCode detection vectors recorded from the original Python
//! implementation (see `testdata/zcode/record_zcode_vectors.py`). Fixture
//! trees and expected artifacts come from Python, never from Rust output.
//! `<ROOT>` is the fixture root.

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::zcode_detect::detect;

const VECTORS: &str = include_str!("../testdata/zcode/vectors.json");

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

/// The recorded lists come from a case-folding volume, where `Alpha` and
/// `alpha` are one directory. A case-sensitive volume keeps both, and
/// `sorted(path.iterdir())` then visits `Alpha` before `Zed`.
fn volume_keeps_distinct_case(root: &Path, case: &Value) -> bool {
    let paths: Vec<&str> = case["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["path"].as_str())
        .collect();
    for (index, left) in paths.iter().enumerate() {
        for right in paths.iter().skip(index + 1) {
            let mut prefix = PathBuf::new();
            for (left_part, right_part) in left.split('/').zip(right.split('/')) {
                if left_part.to_lowercase() == right_part.to_lowercase() && left_part != right_part
                {
                    let left_path = root.join(&prefix).join(left_part);
                    let right_path = root.join(&prefix).join(right_part);
                    let (Ok(left_meta), Ok(right_meta)) =
                        (fs::metadata(&left_path), fs::metadata(&right_path))
                    else {
                        return false;
                    };
                    return left_meta.ino() != right_meta.ino()
                        || left_meta.dev() != right_meta.dev();
                }
                if left_part != right_part {
                    break;
                }
                prefix.push(left_part);
            }
        }
    }
    true
}

fn recorded<'a>(case: &'a Value, root: &Path, field: &str) -> &'a Value {
    let distinct = format!("{field}_case_sensitive");
    if volume_keeps_distinct_case(root, case) {
        if let Some(value) = case.get(&distinct) {
            return value;
        }
    }
    &case[field]
}

fn replay(case: &Value) {
    let name = case["name"].as_str().unwrap();
    let root = temp_home(&format!("zcode-{name}").chars().take(60).collect::<String>());
    materialize(&root, case);
    let root_text = root.to_string_lossy().into_owned();
    let args = substitute(&case["args"], &root_text);
    let result = detect(&args);
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
        substitute(recorded(case, &root, "artifacts"), &root_text),
        "{name}: artifacts"
    );
    assert_eq!(
        answer["found_paths"],
        substitute(recorded(case, &root, "found_paths"), &root_text),
        "{name}: found paths"
    );
    release(&root);
}

#[test]
fn replays_every_recorded_zcode_detection_case() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-zcode-vectors.v1");
    let mut replayed = 0;
    for case in vectors["cases"].as_array().unwrap() {
        replay(case);
        replayed += 1;
    }
    assert!(replayed >= 60, "only {replayed} cases recorded");
}

#[test]
fn case_sensitive_recording_is_selected_when_spellings_stay_distinct() {
    let root = temp_home("zcode-case-select");
    fs::create_dir_all(root.join("Alpha")).unwrap();
    fs::write(root.join("Alpha/a"), b"a").unwrap();
    fs::create_dir_all(root.join("alpha")).unwrap();
    fs::write(root.join("alpha/b"), b"b").unwrap();
    let distinct = fs::metadata(root.join("Alpha")).unwrap().ino()
        != fs::metadata(root.join("alpha")).unwrap().ino();
    let case = serde_json::json!({
        "files": [{"path": "Alpha/a"}, {"path": "alpha/b"}],
        "artifacts": ["folded"],
        "artifacts_case_sensitive": ["distinct"],
    });
    let expected = if distinct { "distinct" } else { "folded" };
    assert_eq!(
        recorded(&case, &root, "artifacts"),
        &serde_json::json!([expected])
    );
    release(&root);
}

/// CPython keeps `{"\ud800": a, "\ud801": b}` as two members; decoding both
/// keys to U+FFFD would drop the first, so the resident refuses the config
/// instead. The oracle answered this input, so it cannot sit in the recorded
/// vectors (those only mark cases Python itself refused).
#[test]
fn object_keys_with_lone_surrogates_are_refused() {
    let root = temp_home("zcode-surrogate-keys");
    let config = root.join("home/.zcode/cli/config.json");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &config,
        "{\"mcpServers\": {\"\\ud800\": {\"command\": \"a\"}, \
         \"\\ud801\": {\"command\": \"b\"}}}",
    )
    .unwrap();
    let v2_config = root.join("home/.zcode/v2/config.json");
    let args = serde_json::json!({
        "harness": "zcode",
        "configs": [{"path": config.to_string_lossy(), "scope": "global"}],
        "v2_config": v2_config.to_string_lossy(),
        "plugin_roots": [],
        "marketplace_roots": [],
    });
    assert_eq!(
        detect(&args).expect_err("surrogate keys must not collapse into one server"),
        crate::zcode_artifacts::ERR_UNREPRESENTABLE
    );
    release(&root);
}

/// A lone surrogate in a value still decodes, and the server beside it is
/// reported. Refusal is only for keys, which would otherwise merge.
#[test]
fn object_values_with_lone_surrogates_stay_readable() {
    let root = temp_home("zcode-surrogate-value");
    let config = root.join("home/.zcode/cli/config.json");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(
        &config,
        "{\"mcp\": {\"servers\": {\"ok\": {\"command\": \"tool\", \
         \"note\": \"\\ud800\"}}}}",
    )
    .unwrap();
    let v2_config = root.join("home/.zcode/v2/config.json");
    let args = serde_json::json!({
        "harness": "zcode",
        "configs": [{"path": config.to_string_lossy(), "scope": "global"}],
        "v2_config": v2_config.to_string_lossy(),
        "plugin_roots": [],
        "marketplace_roots": [],
    });
    let answer = detect(&args).expect("a surrogate value must stay readable");
    let artifacts = answer["artifacts"].as_array().expect("artifacts");
    assert!(
        artifacts
            .iter()
            .any(|artifact| artifact["command"] == "tool"),
        "server command missing from {answer}"
    );
    release(&root);
}

#[test]
fn malformed_requests_are_refused() {
    for args in [
        serde_json::json!({}),
        serde_json::json!({"harness": "zcode"}),
        serde_json::json!({"harness": "zcode", "configs": [{"path": "relative", "scope": "global"}],
            "v2_config": "/tmp/x", "plugin_roots": [], "marketplace_roots": []}),
        serde_json::json!({"harness": "zcode", "configs": [], "v2_config": "relative",
            "plugin_roots": [], "marketplace_roots": []}),
        serde_json::json!({"harness": "zcode", "configs": [{"path": "/tmp/x", "scope": 1}],
            "v2_config": "/tmp/x", "plugin_roots": [], "marketplace_roots": []}),
    ] {
        assert!(detect(&args).is_err(), "{args}");
    }
}
