use serde_json::{json, Value};

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
