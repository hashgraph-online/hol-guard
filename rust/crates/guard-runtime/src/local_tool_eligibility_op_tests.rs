//! `LocalToolEligibility` replayed against the vectors the retired Python
//! decision recorded (`testdata/local_tool_eligibility/record_vectors.py`).
//! The fixture tree is rebuilt in a temporary directory, so every path and
//! stat value is normalized before the recorded identity material compares.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use guard_contracts::{LocalToolEligibilityRequestV1, LOCAL_TOOL_ELIGIBILITY_REQUEST_SCHEMA};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::*;

const VECTORS: &str = include_str!("../testdata/local_tool_eligibility/vectors.json");
const ROOT: &str = "<root>";
const STAT_KEYS: [&str; 4] = ["device", "inode", "change_time_ns", "modified_time_ns"];

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}

fn build_fixture(root: &Path, fixture: &Value) {
    for entry in fixture.as_array().unwrap() {
        let path = root.join(text(entry, "path"));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        if text(entry, "type") == "symlink" {
            std::os::unix::fs::symlink(text(entry, "target"), &path).unwrap();
            continue;
        }
        fs::write(&path, text(entry, "content").as_bytes()).unwrap();
        let mode = u32::try_from(entry["mode"].as_u64().unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }
    for directory in ["home/active", "home"] {
        fs::create_dir_all(root.join(directory)).unwrap();
    }
}

fn substitute(value: &str, root: &str) -> String {
    value.replace(ROOT, root)
}

fn normalize(value: &Value, root: &str) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| {
                    let normalized = if STAT_KEYS.contains(&key.as_str()) {
                        Value::String("<stat>".to_owned())
                    } else {
                        normalize(item, root)
                    };
                    (key.clone(), normalized)
                })
                .collect::<Map<String, Value>>(),
        ),
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| normalize(item, root)).collect())
        }
        Value::String(item) => Value::String(item.replace(root, ROOT)),
        other => other.clone(),
    }
}

fn canonical_sha256(value: &Value) -> String {
    let mut bytes = Vec::new();
    guard_contracts::write_canonical_json(value, &mut bytes).unwrap();
    hex::encode(Sha256::digest(&bytes))
}

fn request(
    command: &str,
    cwd: &str,
    home_dir: Option<String>,
    document: &Value,
    root: &str,
) -> LocalToolEligibilityRequestV1 {
    let launch_env = document["launch_env"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(name, value)| (name.clone(), substitute(value.as_str().unwrap(), root)))
        .collect::<BTreeMap<String, String>>();
    LocalToolEligibilityRequestV1 {
        schema: LOCAL_TOOL_ELIGIBILITY_REQUEST_SCHEMA.to_owned(),
        request_id: "local-tool-eligibility-test".to_owned(),
        command: substitute(command, root),
        cwd: substitute(cwd, root),
        home_dir,
        user_home: Some(substitute(text(document, "user_home"), root)),
        launch_env,
    }
}

#[test]
fn recorded_vectors_replay_exactly() {
    let document = vectors();
    assert_eq!(
        text(&document, "schema"),
        "guard-local-tool-eligibility-vectors.v1"
    );
    let directory = tempfile::tempdir().unwrap();
    let root_path = fs::canonicalize(directory.path()).unwrap();
    build_fixture(&root_path, &document["fixture"]);
    let root = root_path.to_str().unwrap().to_owned();
    let tree_rows: Vec<Vec<String>> = document["trusted_trees"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            row.as_array()
                .unwrap()
                .iter()
                .map(|cell| cell.as_str().unwrap().to_owned())
                .collect()
        })
        .collect();
    let trees: Vec<TrustedTree<'_>> = tree_rows
        .iter()
        .map(|row| {
            (
                row[0].as_str(),
                row[1].as_str(),
                row[2].as_str(),
                row[3].as_str(),
            )
        })
        .collect();
    let cases = document["vectors"].as_array().unwrap();
    assert!(!cases.is_empty());
    let mut eligible = 0;
    for case in cases {
        let name = text(case, "name");
        let home_dir = case["home_dir"]
            .as_str()
            .map(|value| substitute(value, &root));
        let found = eligibility(
            &request(
                text(case, "command"),
                text(case, "cwd"),
                home_dir,
                &document,
                &root,
            ),
            &trees,
        );
        let expected = &case["expected"];
        let Some(found) = found else {
            assert!(expected.is_null(), "{name}: expected eligible, got none");
            continue;
        };
        assert!(
            !expected.is_null(),
            "{name}: expected ineligible, got {found:?}"
        );
        eligible += 1;
        assert_eq!(found.tool_name, text(expected, "tool_name"), "{name}");
        assert_eq!(found.capability, text(expected, "capability"), "{name}");
        assert_eq!(
            found.read_only_reason,
            text(expected, "read_only_reason"),
            "{name}"
        );
        assert_eq!(found.trust_basis, text(expected, "trust_basis"), "{name}");
        assert_eq!(
            Value::Bool(found.indefinite_allowed),
            expected["indefinite_allowed"],
            "{name}"
        );
        assert_eq!(
            found.tool_identity_hash,
            canonical_sha256(&found.identity_material),
            "{name}"
        );
        let normalized = normalize(&found.identity_material, &root);
        assert_eq!(normalized, expected["material"], "{name}");
        assert_eq!(
            canonical_sha256(&normalized),
            text(expected, "material_sha256"),
            "{name}"
        );
    }
    assert!(eligible > 0);
}

fn envelope(request: &LocalToolEligibilityRequestV1) -> Value {
    serde_json::from_slice(&evaluate_local_tool_eligibility_request(request).unwrap()).unwrap()
}

#[test]
fn ineligible_command_answers_null_payload() {
    let document = vectors();
    let mut ineligible = request("rm -rf /", "/", None, &document, "/nonexistent-root");
    ineligible.request_id = "request-ineligible".to_owned();
    let reply = envelope(&ineligible);
    assert_eq!(reply["schema"], LOCAL_TOOL_ELIGIBILITY_RESULT_SCHEMA);
    assert_eq!(reply["request_id"], "request-ineligible");
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["code"], "ok");
    assert!(reply["payload"].is_null());
    let digest = reply["request_sha256"].as_str().unwrap();
    let hex_digest = digest.strip_prefix("sha256:").unwrap();
    assert_eq!(hex_digest.len(), 64);
    assert!(hex_digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn request_digest_binds_the_command() {
    let document = vectors();
    let first = request("ls", "/", None, &document, "/nonexistent-root");
    let mut second = first.clone();
    second.command = "ls -a".to_owned();
    assert_ne!(
        envelope(&first)["request_sha256"],
        envelope(&second)["request_sha256"]
    );
}

#[test]
fn schema_mismatch_is_refused() {
    let document = vectors();
    let mut wrong = request("ls", "/", None, &document, "/nonexistent-root");
    wrong.schema = "guard-local-tool-eligibility-request.v0".to_owned();
    assert_eq!(
        evaluate_local_tool_eligibility_request(&wrong).unwrap_err(),
        "native_local_tool_eligibility_schema_mismatch"
    );
}
