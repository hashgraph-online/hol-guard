use serde_json::{json, Value};

#[test]
fn native_preparation_wire_uses_bounded_base64_and_unknown_operations_fail() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let home = tempfile::tempdir().unwrap();
    let envelope = json!({"operation":"catalog_prepare_v1","request":{
        "guard_home":home.path().canonicalize().unwrap(),"action":{"kind":"advance",
        "session":"unregistered","data":STANDARD.encode(vec![0u8;65536])}}});
    let bytes = evaluate_resident_bytes(&serde_json::to_vec(&envelope).unwrap(), None).unwrap();
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["schema"], "guard.catalog-prepare-result.v1");
    assert_eq!(result["error_code"], "catalog_prepare_session_invalid");
    let mut oversized = envelope.clone();
    oversized["request"]["action"]["data"] = json!(STANDARD.encode(vec![0u8; 65537]));
    assert!(evaluate_resident_bytes(&serde_json::to_vec(&oversized).unwrap(), None).is_err());
    let mut unknown = envelope;
    unknown["operation"] = json!("catalog_prepare_v999");
    assert!(evaluate_resident_bytes(&serde_json::to_vec(&unknown).unwrap(), None).is_err());
}

use crate::resident_ops::evaluate_resident_bytes;

fn catalog_read(route: &str, query: &str, if_none_match: Option<&str>) -> Value {
    let (_, catalog_digest, _) = guard_command::native_command_program::packaged_program_digests();
    let envelope = json!({
        "operation": "catalog_read",
        "request": {
            "schema": "guard-catalog-read-request.v1",
            "route": route,
            "query": query,
            "if_none_match": if_none_match,
            "expected_catalog_digest": catalog_digest,
        },
        "deadline_budget_ms": 1000,
    });
    let bytes = evaluate_resident_bytes(&serde_json::to_vec(&envelope).unwrap(), None).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn resident_serves_catalog_pages_and_revalidation() {
    assert!(crate::resident_protocol::capabilities()
        .features
        .iter()
        .any(|feature| feature == "catalog-read-model-v1"));
    let page = catalog_read("index", "limit=5", None);
    assert_eq!(page["schema"], "guard-catalog-read-result.v1");
    assert_eq!(
        (page["outcome"].as_str(), page["http_status"].as_u64()),
        (Some("ok"), Some(200))
    );
    let body: Value = serde_json::from_str(page["body"].as_str().unwrap()).unwrap();
    assert_eq!(body["items"].as_array().unwrap().len(), 5);
    let etag = page["etag"].as_str().unwrap();
    let revalidated = catalog_read("index", "limit=5", Some(etag));
    assert_eq!(revalidated["outcome"], "not_modified");
    assert_eq!(revalidated["http_status"], 304);
    assert!(revalidated["body"].is_null());
    let missing = catalog_read("extensions/command.absent", "", None);
    assert_eq!(missing["error_code"], "catalog_extension_not_found");
    assert_eq!(missing["http_status"], 404);
}

#[test]
fn resident_rejects_unknown_catalog_request_fields() {
    let envelope = json!({
        "operation": "catalog_read",
        "request": {"schema": "guard-catalog-read-request.v1", "route": "index", "query": "",
                    "if_none_match": null, "expected_catalog_digest": "0".repeat(64), "path": "/etc"},
    });
    assert!(evaluate_resident_bytes(&serde_json::to_vec(&envelope).unwrap(), None).is_err());
}

#[test]
fn resident_discovery_protocol_is_separate_and_missing_metadata_fails_closed() {
    assert!(crate::resident_protocol::capabilities()
        .features
        .iter()
        .any(|feature| feature == "catalog-read-discovery-v2"));
    let home = tempfile::tempdir().unwrap();
    let mut envelope = json!({
        "operation": "catalog_read_v2",
        "request": {
            "guard_home": home.path().canonicalize().unwrap(),
            "discovery_root": "a".repeat(64),
            "read": {"schema": "guard-catalog-read-request.v1", "route": "index", "query": "",
                     "if_none_match": null, "expected_catalog_digest": "b".repeat(64)},
        },
    });
    let bytes = evaluate_resident_bytes(&serde_json::to_vec(&envelope).unwrap(), None).unwrap();
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["http_status"], 503);
    assert!(result["body"].is_null());
    envelope["request"]["path"] = json!("/arbitrary");
    assert!(evaluate_resident_bytes(&serde_json::to_vec(&envelope).unwrap(), None).is_err());
}

#[test]
fn resident_discovery_reads_proved_metadata_and_keeps_active_digest() {
    use sha2::{Digest, Sha256};
    let home = tempfile::tempdir().unwrap();
    let home_path = home.path().canonicalize().unwrap();
    let objects = home_path.join("native-runtime/catalog-discovery/objects");
    std::fs::create_dir_all(&objects).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in objects.ancestors().take(3) {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let put = |value: &Value| {
        let bytes = serde_json::to_vec(value).unwrap();
        assert!(bytes.len() <= 65536);
        let digest = hex::encode(Sha256::digest(&bytes));
        std::fs::write(objects.join(format!("{digest}.json")), &bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                objects.join(format!("{digest}.json")),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        json!({"sha256":digest,"length":bytes.len(),"expanded_length":bytes.len(),"kind":"data"})
    };
    let metadata = json!({
        "extension_id":"command.synthetic", "name":"Synthetic", "description":"metadata only",
        "enabled":false,"activation":"opt-in","source":"synthetic","trust_class":"external",
        "schema_version":"1","version":"1.0","required":false,"publisher":null,"icon":null,
        "permission_count":0,"rule_count":0,"rules":[],"permissions":[],
        "action_classes":[],"aliases":[],"conflicts":[],"delegated_protection":null,
        "dependencies":[],"ecosystem_ids":[],"executables":[],"project_markers":[],
        "reference_urls":[],"risk_classes":[],"safer_alternatives":[]
    });
    let entry = put(&metadata);
    let page = put(&json!({"schema":"guard.catalog-discovery-page.v1",
        "entries":[[metadata["extension_id"],entry]],"next":null}));
    let root = put(
        &json!({"schema":"guard.catalog-discovery.v1", "authority":"a".repeat(64),
        "count":1,"first":page}),
    );
    let envelope = json!({"operation":"catalog_read_v2","request":{
        "guard_home":home_path,"discovery_root":root["sha256"],"read":{
            "schema":"guard-catalog-read-request.v1","route":"index","query":"limit=1",
            "if_none_match":null,"expected_catalog_digest":"b".repeat(64)}}});
    let bytes = evaluate_resident_bytes(&serde_json::to_vec(&envelope).unwrap(), None).unwrap();
    let result: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["http_status"], 200);
    let body: Value = serde_json::from_str(result["body"].as_str().unwrap()).unwrap();
    assert_eq!(body["native_catalog_digest"], "b".repeat(64));
    assert_eq!(body["total_count"], 1);
    assert_eq!(body["items"][0]["extension_id"], metadata["extension_id"]);
    let operation: crate::resident_protocol::ResidentOperationV1 =
        serde_json::from_value(envelope).unwrap();
    assert_eq!(super::operation_guard_home(&operation), home_path.to_str());
}

#[test]
fn resident_cloud_catalog_registration_and_incomplete_failure() {
    assert!(crate::resident_protocol::capabilities()
        .features
        .iter()
        .any(|feature| feature == guard_command::cloud_catalog::CAPABILITY));
    let home = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let send = |request| {
        let envelope =
            json!({"operation":"cloud_catalog","request":request,"deadline_budget_ms":1000});
        let bytes = evaluate_resident_bytes(&serde_json::to_vec(&envelope).unwrap(), None).unwrap();
        serde_json::from_slice::<Value>(&bytes).unwrap()
    };
    let begin = send(
        json!({"action":"begin","observation":{"guard_home":home.path(),
        "discovery_root":"b".repeat(64),"discovery_authority":"c".repeat(64),
        "enforcement_catalog_digest":"a".repeat(64),"guard_version":"3.49.0",
        "generated_at":"2026-10-18T00:00:00Z"}}),
    );
    assert_eq!(begin["schema"], "guard-cloud-catalog-result.v2");
    let result = send(json!({"action":"finish","draft":begin["payload"]["draft"]}));
    assert_eq!(result["error"], "catalog_unavailable");
    assert!(result.get("payload").is_none());
}
