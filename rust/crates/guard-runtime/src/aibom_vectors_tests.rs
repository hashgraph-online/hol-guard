//! Replays AIBOM discovery vectors recorded from the original Python
//! implementation (see `testdata/aibom/record_aibom_vectors.py`). Fixture
//! trees, expected artifacts and expected digests all come from Python,
//! never from Rust output. `<ROOT>` is the fixture root and `<MID>` the
//! marketplace id derived from the marketplace file's resolved path.

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::aibom_artifact::sha256_hex;
use crate::aibom_op::{codex_skills, mcp_metadata, workspace_artifacts, workspace_merge_plan};
use crate::guard_store_cmd_vectors_tests::temp_home;

const VECTORS: &str = include_str!("../testdata/aibom/aibom_vectors.json");

fn substitute(value: &Value, root: &str, marketplace_id: &str) -> Value {
    match value {
        Value::String(text) => Value::String(
            text.replace("<ROOT>", root)
                .replace("<MID>", marketplace_id),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| substitute(item, root, marketplace_id))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), substitute(item, root, marketplace_id)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// These vectors were recorded where directory lookup is case-insensitive, so
/// `docs/Design` is the directory already created as `docs/design`. Reuse that
/// directory. The final component of a file or link keeps its recorded spelling,
/// which is how `B.md` stays distinct from `b.md`.
fn path_reusing_directory_case(path: &Path, reuse_final: bool) -> PathBuf {
    let mut resolved = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        if final_component && !reuse_final {
            resolved.push(component);
            break;
        }
        if let std::path::Component::Normal(name) = component {
            let exact = resolved.join(name);
            if exact.is_dir() {
                resolved = exact;
                continue;
            }
            if let Some(existing) = directory_with_same_case(&resolved, name) {
                resolved.push(existing);
                continue;
            }
        }
        resolved.push(component);
    }
    resolved
}

fn directory_with_same_case(parent: &Path, name: &std::ffi::OsStr) -> Option<std::ffi::OsString> {
    let folded = name.to_string_lossy().to_lowercase();
    fs::read_dir(parent)
        .ok()?
        .filter_map(Result::ok)
        .find_map(|entry| {
            let is_dir = entry.file_type().ok()?.is_dir();
            if !is_dir {
                return None;
            }
            let found = entry.file_name();
            (found.to_string_lossy().to_lowercase() == folded).then_some(found)
        })
}

fn materialize(root: &Path, case: &Value) {
    for name in ["work", "home", "uhome"] {
        fs::create_dir_all(root.join(name)).unwrap();
    }
    let root_text = root.to_string_lossy();
    let mut locked: Vec<(PathBuf, u32)> = Vec::new();
    for entry in case["files"].as_array().unwrap() {
        let path = path_reusing_directory_case(&root.join(entry["path"].as_str().unwrap()), false);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, entry["text"].as_str().unwrap()).unwrap();
        locked.push((path, entry["mode"].as_u64().unwrap() as u32));
    }
    for relative in case["dirs"].as_array().unwrap() {
        let path = path_reusing_directory_case(&root.join(relative.as_str().unwrap()), true);
        fs::create_dir_all(path).unwrap();
    }
    for entry in case["symlinks"].as_array().unwrap() {
        let path = path_reusing_directory_case(&root.join(entry["path"].as_str().unwrap()), false);
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

/// Restores read access so the fixture tree can be removed.
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

fn marketplace_id(root: &Path, case: &Value) -> String {
    case["marketplace_files"]
        .as_array()
        .and_then(|files| files.first())
        .and_then(Value::as_str)
        .and_then(|relative| fs::canonicalize(root.join(relative)).ok())
        .map(|resolved| sha256_hex(&resolved.to_string_lossy())[..12].to_owned())
        .unwrap_or_default()
}

/// What the Python facade does with a merge plan.
fn apply_plan(
    plan: &Value,
    existing: &[Value],
    config_paths: &[Value],
) -> (Vec<Value>, Vec<Value>) {
    if plan["extra_count"] == 0 {
        return (existing.to_vec(), config_paths.to_vec());
    }
    let mut artifacts = existing.to_vec();
    for replacement in plan["replacements"].as_array().unwrap() {
        let index = replacement["index"].as_u64().unwrap() as usize;
        artifacts[index] = replacement["artifact"].clone();
    }
    artifacts.extend(plan["appended"].as_array().unwrap().iter().cloned());
    let mut paths: Vec<Value> = Vec::new();
    for path in config_paths
        .iter()
        .chain(plan["found_paths"].as_array().unwrap())
    {
        if !paths.contains(path) {
            paths.push(path.clone());
        }
    }
    (artifacts, paths)
}

fn replay_filesystem_case(case: &Value) {
    let name = case["name"].as_str().unwrap();
    let root = temp_home(&format!("aibom-{name}").chars().take(60).collect::<String>());
    materialize(&root, case);
    let root_text = root.to_string_lossy().into_owned();
    let mid = marketplace_id(&root, case);
    let args = substitute(&case["args"], &root_text, &mid);
    let kind = case["kind"].as_str().unwrap();
    let result = match kind {
        "workspace_artifacts" => workspace_artifacts(&args),
        "merge_plan" => workspace_merge_plan(&args),
        "codex_skills" => codex_skills(&args),
        other => panic!("{name}: unknown kind {other}"),
    };
    if case["refused"] == true {
        assert!(
            result.is_err(),
            "{name}: Python refused, the resident answered {result:?}"
        );
        release(&root);
        return;
    }
    let answer = result.unwrap_or_else(|code| panic!("{name}: resident refused with {code}"));
    let expected = substitute(&case["artifacts"], &root_text, &mid);
    if kind == "merge_plan" {
        let existing = substitute(&case["existing_artifacts"], &root_text, &mid);
        let existing_paths = substitute(&case["existing_config_paths"], &root_text, &mid);
        let (artifacts, paths) = apply_plan(
            &answer,
            existing.as_array().unwrap(),
            existing_paths.as_array().unwrap(),
        );
        assert_eq!(
            Value::Array(artifacts),
            expected,
            "{name}: merged artifacts"
        );
        let expected_paths = substitute(&case["config_paths"], &root_text, &mid);
        assert_eq!(Value::Array(paths), expected_paths, "{name}: config paths");
    } else {
        assert_eq!(answer["artifacts"], expected, "{name}: artifacts");
    }
    release(&root);
}

#[test]
fn replays_every_recorded_aibom_discovery_case() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-aibom-vectors.v1");
    let mut replayed = 0;
    for case in vectors["cases"].as_array().unwrap() {
        if case["kind"] == "mcp_metadata" {
            continue;
        }
        replay_filesystem_case(case);
        replayed += 1;
    }
    assert!(replayed >= 40, "only {replayed} filesystem cases recorded");
}

#[test]
fn replays_every_recorded_mcp_metadata_case() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let mut replayed = 0;
    for case in vectors["cases"].as_array().unwrap() {
        if case["kind"] != "mcp_metadata" {
            continue;
        }
        let name = case["name"].as_str().unwrap();
        let answer = mcp_metadata(&case["args"]).unwrap_or_else(|code| panic!("{name}: {code}"));
        assert_eq!(answer, case["expected"], "{name}");
        replayed += 1;
    }
    assert!(replayed >= 10, "only {replayed} metadata cases recorded");
}

#[test]
fn relative_or_missing_roots_are_refused() {
    for args in [
        serde_json::json!({"harness": "codex", "workspace_dir": "relative/path"}),
        serde_json::json!({"harness": "codex", "workspace_dir": ""}),
        serde_json::json!({"harness": "codex"}),
        serde_json::json!({"workspace_dir": "/tmp"}),
    ] {
        assert!(workspace_artifacts(&args).is_err(), "{args}");
    }
}
