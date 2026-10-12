//! Parity vectors recorded from the legacy Python `local_supply_chain` audit
//! helpers (`audit_receipt_metadata`, advisory-alias enrichment, `_ci_gate_result`
//! and `_resolve_empty_audit_outcome`) before they were deleted.

use super::*;
use guard_contracts::PackageAuditProjectionRequestV1;
use std::path::PathBuf;

const VECTORS: &str = include_str!("../testdata/package_audit_projection_vectors.json");

struct Fixture {
    home: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let home = std::env::temp_dir().join(format!(
            "hol-guard-audit-projection-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(home.join("workspace")).unwrap();
        Self { home }
    }

    fn workspace(&self) -> PathBuf {
        self.home.join("workspace")
    }

    fn store(&self, workspace_id: Option<&str>, bundle: &Value) -> String {
        let path = self.home.join("guard.db");
        let _ = std::fs::remove_file(&path);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE sync_state (state_key TEXT PRIMARY KEY, payload_json TEXT NOT NULL);
                 CREATE TABLE guard_supply_chain_bundle_cache (
                     workspace_id TEXT PRIMARY KEY, response_json TEXT NOT NULL, cached_at TEXT NOT NULL);",
            )
            .unwrap();
        if let Some(workspace_id) = workspace_id {
            connection
                .execute(
                    "INSERT INTO sync_state VALUES ('oauth_local_credentials', ?1)",
                    [json!({"workspace_id": workspace_id}).to_string()],
                )
                .unwrap();
            if !bundle.is_null() {
                connection
                    .execute(
                        "INSERT INTO guard_supply_chain_bundle_cache VALUES (?1, ?2, 'now')",
                        [
                            workspace_id.to_owned(),
                            json!({"bundle": bundle}).to_string(),
                        ],
                    )
                    .unwrap();
            }
        }
        path.to_string_lossy().into_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn request(query: Value) -> PackageAuditProjectionRequestV1 {
    serde_json::from_value(json!({
        "schema": PACKAGE_AUTHORITY_REQUEST_SCHEMA,
        "request_id": "vector",
        "guard_home": "/tmp/guard-home",
        "query": query,
    }))
    .unwrap()
}

fn run(request: &PackageAuditProjectionRequestV1) -> Result<Value, String> {
    evaluate_package_audit_projection(request)
        .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap()["payload"].clone())
}

fn query_for(vector: &Value, fixture: &Fixture) -> Value {
    let kind = vector["query"].as_str().unwrap();
    match kind {
        "receipt" => {
            for (relative, text) in vector["files"].as_object().unwrap() {
                let path = fixture.workspace().join(relative);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, text.as_str().unwrap()).unwrap();
            }
            std::fs::create_dir_all(fixture.workspace().join("dir")).unwrap();
            std::fs::create_dir_all(fixture.workspace().join("sub")).unwrap();
            let mut query = json!({"query": "receipt", "result": vector["result"]});
            if vector["use_workspace"].as_bool().unwrap() {
                query["workspace_dir"] = json!(fixture.workspace().to_string_lossy());
            }
            if vector["has_store"].as_bool().unwrap() {
                query["store_path"] =
                    json!(fixture.store(vector["workspace_id"].as_str(), &vector["bundle"]));
            }
            query
        }
        "aliases" => json!({
            "query": "aliases",
            "packages": vector["packages"],
            "store_path": fixture.store(vector["workspace_id"].as_str(), &vector["bundle"]),
        }),
        "ci_gate" => {
            json!({"query": "ci_gate", "evaluation": vector["evaluation"], "threshold": vector["threshold"]})
        }
        _ => json!({
            "query": "empty_outcome",
            "manifest_paths": vector["manifest_paths"],
            "lockfile_paths": vector["lockfile_paths"],
            "posture": vector["posture"],
        }),
    }
}

#[test]
fn recorded_python_vectors_match() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 900);
    for (index, vector) in vectors.iter().enumerate() {
        let fixture = Fixture::new();
        let query = query_for(vector, &fixture);
        let actual = run(&request(query)).unwrap();
        assert_eq!(actual, vector["expected"], "vector {index}: {vector}");
    }
}

#[test]
fn rejects_malformed_requests() {
    let valid = request(json!({
        "query": "empty_outcome", "manifest_paths": [], "lockfile_paths": [], "posture": {},
    }));
    assert!(run(&valid).is_ok());
    let mut bad_schema = valid.clone();
    bad_schema.schema = "other".into();
    assert_eq!(
        run(&bad_schema).unwrap_err(),
        "native_package_audit_projection_schema_mismatch"
    );
    let mut empty_id = valid.clone();
    empty_id.request_id = String::new();
    assert!(run(&empty_id).is_err());
    let bad_posture = request(json!({
        "query": "empty_outcome", "manifest_paths": [], "lockfile_paths": [], "posture": [],
    }));
    assert_eq!(
        run(&bad_posture).unwrap_err(),
        "native_package_audit_projection_invalid"
    );
    let missing_store = request(json!({
        "query": "aliases", "packages": [], "store_path": "/nonexistent/guard.db",
    }));
    assert_eq!(
        run(&missing_store).unwrap_err(),
        "native_package_audit_projection_store_unavailable"
    );
}

const CLOUD_VECTORS: &[u8] = include_bytes!("../testdata/cloud_audit_vectors.json.gz");
const VECTOR_MACHINE: &str = "vector-host";

fn cloud_vectors() -> Vec<Value> {
    use std::io::Read;
    let mut text = String::new();
    flate2::read::GzDecoder::new(CLOUD_VECTORS)
        .read_to_string(&mut text)
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Lay a recorded workspace out under `<home>/vector-parent/vector-ws` (or use the
/// recorded absolute path, which the vector keeps non-existent) and write the
/// recorded bundle summary into the store.
fn cloud_query_for(vector: &Value, fixture: &Fixture) -> Value {
    let workspace = match vector["workspace"].as_str().unwrap() {
        "REL" => {
            let root = fixture.home.join("vector-parent").join("vector-ws");
            std::fs::create_dir_all(&root).unwrap();
            for (relative, text) in vector["files"].as_object().unwrap() {
                let path = root.join(relative);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, text.as_str().unwrap()).unwrap();
            }
            root.to_string_lossy().into_owned()
        }
        absolute => absolute.strip_prefix("ABS:").unwrap().to_owned(),
    };
    let store = fixture.store(None, &Value::Null);
    if !vector["summary"].is_null() {
        rusqlite::Connection::open(&store)
            .unwrap()
            .execute(
                "INSERT INTO sync_state VALUES ('supply_chain_bundle_summary', ?1)",
                [vector["summary"].to_string()],
            )
            .unwrap();
    }
    json!({
        "query": "cloud_payload",
        "workspace_dir": workspace,
        "workspace_id": vector["workspace_id"],
        "store_path": store,
        "inventory_workspace_dir": workspace,
        "inventory_digest": "",
        "mode": vector["mode"],
        "page_size": vector["page_size"],
        "machine": VECTOR_MACHINE,
    })
}

#[test]
fn recorded_python_cloud_audit_vectors_match() {
    let vectors = cloud_vectors();
    assert!(vectors.len() >= 1400);
    for (index, vector) in vectors.iter().enumerate() {
        let fixture = Fixture::new();
        let kind = vector["query"].as_str().unwrap();
        let query = match kind {
            "cloud_payload" => {
                // The recorded inventories are not derived from the recorded
                // files, so the payload builder is replayed on them directly.
                let mut query = cloud_query_for(vector, &fixture);
                query.as_object_mut().unwrap().remove("query");
                let query: PackageAuditCloudPayloadQueryV1 = serde_json::from_value(query).unwrap();
                let strings = |value: &Value| -> Vec<String> {
                    value
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|item| item.as_str().unwrap().to_owned())
                        .collect()
                };
                let result = cloud_payload_from_inventory(
                    &query,
                    "/tmp/guard-home",
                    &strings(&vector["manifest_paths"]),
                    &strings(&vector["lockfile_paths"]),
                    vector["inventory"].as_array().unwrap(),
                );
                check_cloud_vector(index, vector, kind, result);
                continue;
            }
            "batch_url" => {
                let mut query = json!({
                    "query": "batch_url",
                    "sync_url": vector["sync_url"],
                    "workspace_id": vector["workspace_id"],
                });
                if let Some(job_id) = vector.get("job_id") {
                    query["job_id"] = job_id.clone();
                    query["page_size"] = vector["page_size"].clone();
                }
                query
            }
            "cloud_normalize" => {
                json!({"query": "cloud_normalize", "response": vector["response"]})
            }
            _ => json!({
                "query": "workspace_candidates",
                "installs": vector["installs"],
                "candidates": false,
            }),
        };
        check_cloud_vector(index, vector, kind, run(&request(query)));
    }
}

fn check_cloud_vector(index: usize, vector: &Value, kind: &str, result: Result<Value, String>) {
    let expected = &vector["expected"];
    if expected.get("error").is_some() {
        assert_eq!(
            result.unwrap_err(),
            "native_package_audit_projection_invalid",
            "vector {index}: {vector}"
        );
        return;
    }
    let mut actual = result.unwrap_or_else(|error| panic!("vector {index}: {error}"));
    let expected = expected["ok"].clone();
    let expected = match kind {
        "batch_url" => json!({"url": expected}),
        "install_dirs" => json!({"workspaces": expected}),
        _ => expected,
    };
    if kind == "cloud_payload" {
        let machine = actual["workspaceContext"]
            .as_object_mut()
            .unwrap()
            .remove("machine");
        assert_eq!(machine, Some(json!(VECTOR_MACHINE)), "vector {index}");
    }
    assert_eq!(actual, expected, "vector {index}: {vector}");
}

#[test]
fn workspace_candidates_keep_existing_project_directories_in_order() {
    let fixture = Fixture::new();
    let explicit = fixture.home.join("explicit");
    let managed = fixture.home.join("managed");
    for dir in [&explicit, &managed, &fixture.home.join("bare")] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(explicit.join("package.json"), "{}").unwrap();
    std::fs::write(managed.join("Cargo.toml"), "").unwrap();
    let installs = json!([
        {"workspace": managed.to_string_lossy(), "active": true, "updated_at": "2"},
        {"workspace": fixture.home.join("bare").to_string_lossy(), "updated_at": "9"},
        {"workspace": fixture.home.join("missing").to_string_lossy(), "updated_at": "1"},
    ]);
    let result = run(&request(json!({
        "query": "workspace_candidates",
        "installs": installs,
        "workspace_dir": explicit.to_string_lossy(),
        "candidates": true,
    })))
    .unwrap();
    let names: Vec<String> = result["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| {
            std::path::Path::new(path.as_str().unwrap())
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, ["explicit", "managed"]);
}

#[test]
fn cloud_payload_for_a_large_workspace_fits_one_resident_reply() {
    let fixture = Fixture::new();
    let workspace = fixture.workspace();
    let dependencies: Map<String, Value> = (0..10_050)
        .map(|index| (format!("pkg-{index}"), json!("^1.0.0")))
        .collect();
    std::fs::write(
        workspace.join("package.json"),
        json!({"name": "large", "dependencies": dependencies}).to_string(),
    )
    .unwrap();
    let workspace_dir = workspace.to_string_lossy().into_owned();
    let snapshot =
        crate::workspace_inventory_op::inventory_snapshot(&workspace_dir, None, &[], true).unwrap();
    assert_eq!(snapshot.items.len(), 10_050);
    let query = json!({
        "query": "cloud_payload",
        "workspace_dir": workspace_dir,
        "workspace_id": "ws-large",
        "store_path": fixture.store(None, &Value::Null),
        "inventory_workspace_dir": workspace_dir,
        "include_lockfile_warnings": true,
        "inventory_digest": snapshot.digest,
        "mode": "paged",
        "machine": VECTOR_MACHINE,
    });
    // The request itself stays inside the resident's strict JSON limits.
    assert!(crate::strict_json_value(&serde_json::to_vec(&query).unwrap()).is_ok());
    let request = request(query);
    let started = std::time::Instant::now();
    let bytes = evaluate_package_audit_projection(&request).expect("cloud payload");
    eprintln!(
        "cloud payload reply {} bytes in {:?}",
        bytes.len(),
        started.elapsed()
    );
    assert!(bytes.len() <= guard_contracts::MAX_NATIVE_RESPONSE_BYTES);
    let payload = &serde_json::from_slice::<Value>(&bytes).unwrap()["payload"];
    assert_eq!(payload["packages"].as_array().map(Vec::len), Some(10_050));
}

#[test]
fn cloud_payload_rejects_a_workspace_that_changed_since_its_inventory() {
    let fixture = Fixture::new();
    let workspace = fixture.workspace();
    std::fs::write(
        workspace.join("package.json"),
        r#"{"dependencies":{"a":"1"}}"#,
    )
    .unwrap();
    let workspace_dir = workspace.to_string_lossy().into_owned();
    let snapshot =
        crate::workspace_inventory_op::inventory_snapshot(&workspace_dir, None, &[], false)
            .unwrap();
    std::fs::write(
        workspace.join("package.json"),
        r#"{"dependencies":{"b":"1"}}"#,
    )
    .unwrap();
    let result = run(&request(json!({
        "query": "cloud_payload",
        "workspace_dir": workspace_dir,
        "workspace_id": "ws",
        "store_path": fixture.store(None, &Value::Null),
        "inventory_workspace_dir": workspace_dir,
        "inventory_digest": snapshot.digest,
        "mode": "paged",
    })));
    assert_eq!(
        result.unwrap_err(),
        "native_package_audit_projection_inventory_changed"
    );
}
