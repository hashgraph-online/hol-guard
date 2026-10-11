//! Parity vectors recorded from the legacy Python `local_supply_chain`
//! approval-hash path before it was deleted.

use super::*;
use guard_contracts::PackageApprovalHashRequestV1;
use serde_json::{json, Value};
use std::path::PathBuf;

const VECTORS: &str = include_str!("../testdata/package_approval_hash_vectors.json");

struct Workspace(PathBuf);

impl Workspace {
    fn new(name: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "hol-guard-approval-hash-{name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(vector: &Value, workspace: &Workspace, kind: &str) -> PackageApprovalHashRequestV1 {
    let root = &workspace.0;
    for (relative, text) in vector["workspace_files"].as_object().unwrap() {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text.as_str().unwrap()).unwrap();
    }
    let db = root.join("guard.db");
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE publisher_cache (publisher_key TEXT PRIMARY KEY, payload_json TEXT NOT NULL, updated_at TEXT NOT NULL)",
        )
        .unwrap();
    for (index, row) in vector["advisory_rows"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        connection
            .execute(
                "INSERT INTO publisher_cache VALUES (?1, ?2, ?3)",
                rusqlite::params![index.to_string(), row.to_string(), format!("{index:03}")],
            )
            .unwrap();
    }
    drop(connection);
    let mut value = vector["request"].clone();
    let map = value.as_object_mut().unwrap();
    map.insert("schema".into(), json!(PACKAGE_AUTHORITY_REQUEST_SCHEMA));
    map.insert("request_id".into(), json!("vector"));
    map.insert("guard_home".into(), json!(root.to_string_lossy()));
    map.insert("kind".into(), json!(kind));
    if kind == "artifact_hash" {
        map.insert("store_path".into(), json!(db.to_string_lossy()));
        map.insert("workspace_dir".into(), json!(root.to_string_lossy()));
    } else {
        for key in [
            "execution_context",
            "extension_control_digest",
            "feed_snapshot_hash",
            "launch_identity",
            "additional_policy_context",
            "sandbox_analysis",
        ] {
            map.remove(key);
        }
    }
    serde_json::from_value(value).unwrap()
}

fn run(request: &PackageApprovalHashRequestV1) -> Result<Value, String> {
    evaluate_package_approval_hash(request)
        .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap()["payload"].clone())
}

#[test]
fn recorded_python_vectors_match() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 10);
    for vector in &vectors {
        let name = vector["name"].as_str().unwrap();
        let workspace = Workspace::new(name);
        let hashed = run(&request(vector, &workspace, "artifact_hash")).unwrap();
        assert_eq!(
            hashed["artifact_hash"], vector["expected"]["artifact_hash"],
            "{name}"
        );
        assert_eq!(
            hashed["current_action"], vector["expected"]["current_action"],
            "{name}"
        );
        let workspace = Workspace::new(name);
        let action = run(&request(vector, &workspace, "current_action")).unwrap();
        assert_eq!(
            action,
            json!({"current_action": vector["expected"]["current_action"]}),
            "{name}"
        );
    }
}

#[test]
fn rejects_malformed_requests() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let workspace = Workspace::new("reject");
    let good = request(&vectors[0], &workspace, "artifact_hash");

    let mut unknown_kind = good.clone();
    unknown_kind.kind = "other".into();
    assert_eq!(
        run(&unknown_kind).unwrap_err(),
        "native_package_approval_hash_invalid"
    );

    let mut schema = good.clone();
    schema.schema = "wrong".into();
    assert_eq!(
        run(&schema).unwrap_err(),
        "native_package_approval_hash_schema_mismatch"
    );

    let mut context = good.clone();
    context.execution_context = Some(json!({"digest": "d", "version": 1, "components": []}));
    assert_eq!(
        run(&context).unwrap_err(),
        "native_package_approval_hash_invalid"
    );

    let mut missing_digest = good.clone();
    missing_digest.extension_control_digest = None;
    assert_eq!(
        run(&missing_digest).unwrap_err(),
        "native_package_approval_hash_invalid"
    );

    let mut missing_store = good;
    missing_store.store_path = Some(workspace.0.join("absent.db").to_string_lossy().into_owned());
    assert_eq!(
        run(&missing_store).unwrap_err(),
        "native_package_advisory_store_unavailable"
    );
}
