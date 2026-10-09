use std::collections::BTreeSet;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::catalog_read_model::{
    packaged_catalog_read_snapshot, CatalogReadRequestV1, CatalogReadResultV1, CatalogReadSnapshot,
    CATALOG_READ_REQUEST_SCHEMA, MAX_CATALOG_PAGE_BYTES, MAX_CATALOG_SNAPSHOT_ENCODED_BYTES,
};
use crate::catalog_read_projection::{
    EXTENSION_FIELDS_NOT_IN_DETAIL, MCP_TOOL_FIELDS, PERMISSION_FIELDS, RULE_FIELDS,
};
use crate::catalog_read_query::hex_prefix;
use crate::native_command_catalog::{embedded_catalog_bytes, packaged_command_catalog};

fn snapshot() -> &'static CatalogReadSnapshot {
    packaged_catalog_read_snapshot().expect("packaged catalog read snapshot")
}

fn request(snapshot: &CatalogReadSnapshot, route: &str, query: &str) -> CatalogReadRequestV1 {
    CatalogReadRequestV1 {
        schema: CATALOG_READ_REQUEST_SCHEMA.to_owned(),
        route: route.to_owned(),
        query: query.to_owned(),
        if_none_match: None,
        expected_catalog_digest: snapshot.catalog_digest().to_owned(),
    }
}

fn read(snapshot: &CatalogReadSnapshot, route: &str, query: &str) -> CatalogReadResultV1 {
    snapshot.read(&request(snapshot, route, query))
}

fn ok_body(result: &CatalogReadResultV1) -> Value {
    assert_eq!(result.outcome, "ok", "{result:?}");
    let body = result.body.as_deref().expect("body");
    assert!(body.len() <= MAX_CATALOG_PAGE_BYTES);
    serde_json::from_str(body).expect("page json")
}

fn error_code(result: &CatalogReadResultV1) -> &'static str {
    assert_eq!(result.outcome, "error", "{result:?}");
    result.error_code.expect("error code")
}

fn source_catalog() -> Vec<Value> {
    let envelope: Value = serde_json::from_slice(embedded_catalog_bytes()).expect("catalog");
    envelope["catalog"].as_array().expect("array").clone()
}

/// A provenance-consistent catalog envelope (digest recomputed) for tests.
fn synthetic(edit: impl FnOnce(&mut Vec<Value>)) -> CatalogReadSnapshot {
    let mut catalog = source_catalog();
    edit(&mut catalog);
    let digest = hex_prefix(&Sha256::digest(serde_json::to_vec(&catalog).unwrap()), 64);
    let bytes = serde_json::to_vec(&json!({"catalog_digest": digest, "catalog": catalog})).unwrap();
    CatalogReadSnapshot::from_catalog_bytes(&bytes).expect("synthetic snapshot")
}

/// Follow `next_cursor` to the end, checking page invariants.
fn traverse(snapshot: &CatalogReadSnapshot, route: &str, query: &str) -> Vec<Value> {
    let mut items = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10_000 {
        let page_query = match &cursor {
            Some(cursor) if query.is_empty() => format!("cursor={cursor}"),
            Some(cursor) => format!("{query}&cursor={cursor}"),
            None => query.to_owned(),
        };
        let page = ok_body(&read(snapshot, route, &page_query));
        assert_eq!(page["snapshot_id"], snapshot.snapshot_id());
        assert_eq!(page["native_catalog_digest"], snapshot.catalog_digest());
        let page_items = page["items"].as_array().unwrap();
        assert!(!page_items.is_empty() || page["total_count"] == 0);
        items.extend(page_items.iter().cloned());
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => {
                assert_eq!(page["total_count"].as_u64().unwrap() as usize, items.len());
                return items;
            }
        }
    }
    panic!("traversal did not terminate");
}

fn ids(items: &[Value], key: &str) -> Vec<String> {
    items
        .iter()
        .map(|item| item[key].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn packaged_snapshot_is_bound_to_native_program_and_budgeted() {
    let snapshot = snapshot();
    let bound = packaged_command_catalog().unwrap();
    assert_eq!(snapshot.catalog_digest(), bound.catalog_digest);
    assert!(snapshot.snapshot_id().starts_with("cs1-") && snapshot.snapshot_id().len() == 36);
    assert!(snapshot.encoded_bytes() > 0);
    assert!(snapshot.encoded_bytes() <= MAX_CATALOG_SNAPSHOT_ENCODED_BYTES);
    let concurrent: Vec<usize> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| packaged_catalog_read_snapshot().unwrap() as *const _ as usize))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    });
    assert!(concurrent.iter().all(|address| *address == concurrent[0]));
}

#[test]
fn projection_allowlists_cover_every_source_field() {
    let catalog = source_catalog();
    let extension_keys: BTreeSet<&str> = catalog
        .iter()
        .flat_map(|ext| ext.as_object().unwrap().keys().map(String::as_str))
        .collect();
    let details: Vec<Value> = catalog
        .iter()
        .map(|ext| {
            let route = format!("extensions/{}", ext["extension_id"].as_str().unwrap());
            ok_body(&read(snapshot(), &route, ""))
        })
        .collect();
    let mut projected: BTreeSet<&str> = details
        .iter()
        .flat_map(|detail| {
            detail["extension"]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
        })
        .filter(|key| !matches!(*key, "catalog_defaults" | "content_revision"))
        .collect();
    projected.extend(EXTENSION_FIELDS_NOT_IN_DETAIL);
    assert_eq!(projected, extension_keys);
    let tool_keys: BTreeSet<&str> = catalog
        .iter()
        .filter_map(|ext| ext["mcp_tools"].as_array())
        .flatten()
        .flat_map(|item| item.as_object().unwrap().keys().map(String::as_str))
        .collect();
    assert_eq!(tool_keys, MCP_TOOL_FIELDS.iter().copied().collect());
    let permission_keys: BTreeSet<&str> = catalog
        .iter()
        .flat_map(|ext| ext["permissions"].as_array().unwrap())
        .flat_map(|item| item.as_object().unwrap().keys().map(String::as_str))
        .collect();
    assert_eq!(permission_keys, PERMISSION_FIELDS.iter().copied().collect());
    let rule_keys: BTreeSet<&str> = catalog
        .iter()
        .flat_map(|ext| ext["rules"].as_array().unwrap())
        .flat_map(|item| item.as_object().unwrap().keys().map(String::as_str))
        .collect();
    assert_eq!(rule_keys, RULE_FIELDS.iter().copied().collect());
}

#[test]
fn index_traversal_returns_every_extension_once_in_stable_order() {
    let snapshot = snapshot();
    let mut expected = ids(&source_catalog(), "extension_id");
    expected.sort();
    for query in ["", "limit=1", "limit=7", "limit=100"] {
        let items = traverse(snapshot, "index", query);
        assert_eq!(ids(&items, "extension_id"), expected, "query {query}");
    }
    let first = ok_body(&read(snapshot, "index", ""));
    assert_eq!(first["limit"], 50);
    let item = first["items"][0].as_object().unwrap();
    for absent in [
        "permissions",
        "rules",
        "mcp_tools",
        "delegated_protection",
        "enabled",
        "activation",
    ] {
        assert!(!item.contains_key(absent), "index leaks {absent}");
    }
    assert!(item["catalog_defaults"]["enabled"].is_boolean());
    assert!(item["content_revision"]
        .as_str()
        .unwrap()
        .starts_with("er1-"));
}

#[test]
fn index_and_detail_values_match_source_catalog() {
    let snapshot = snapshot();
    let items = traverse(snapshot, "index", "limit=100");
    for source in source_catalog() {
        let id = source["extension_id"].as_str().unwrap();
        let item = items
            .iter()
            .find(|item| item["extension_id"] == id)
            .unwrap();
        for key in [
            "name",
            "version",
            "source",
            "trust_class",
            "required",
            "permission_count",
            "action_classes",
            "aliases",
            "description",
            "ecosystem_ids",
            "executables",
        ] {
            assert_eq!(item[key], source[key], "{id} {key}");
        }
        assert_eq!(item["catalog_defaults"]["enabled"], source["enabled"]);
        assert_eq!(item["catalog_defaults"]["activation"], source["activation"]);
        let detail = ok_body(&read(snapshot, &format!("extensions/{id}"), ""));
        for (key, value) in detail["extension"].as_object().unwrap() {
            if !matches!(key.as_str(), "catalog_defaults" | "content_revision") {
                assert_eq!(*value, source[key], "{id} {key}");
            }
        }
        let permissions = source["permissions"].as_array().unwrap();
        let rules = source["rules"].as_array().unwrap();
        assert_eq!(
            detail["collections"]["permissions"]["total_count"],
            permissions.len()
        );
        assert_eq!(detail["collections"]["rules"]["total_count"], rules.len());
        let expected_permissions = permissions.clone();
        let route = format!("extensions/{id}/permissions");
        assert_eq!(traverse(snapshot, &route, "limit=3"), expected_permissions);
        let expected_rules = rules.clone();
        assert_eq!(
            traverse(snapshot, &format!("extensions/{id}/rules"), ""),
            expected_rules
        );
        let expected_tools = source["mcp_tools"].as_array().cloned().unwrap_or_default();
        assert_eq!(
            detail["collections"]
                .get("mcp_tools")
                .map(|collection| collection["total_count"].clone()),
            source
                .get("mcp_tools")
                .map(|_| serde_json::json!(expected_tools.len()))
        );
        let tools_route = format!("extensions/{id}/mcp-tools");
        assert_eq!(traverse(snapshot, &tools_route, "limit=10"), expected_tools);
        assert_eq!(item.get("surface"), source.get("surface"));
    }
}

#[test]
fn filters_are_bounded_and_exact() {
    let snapshot = snapshot();
    let all = traverse(snapshot, "index", "limit=100");
    let built_in = traverse(snapshot, "index", "source=built-in&limit=100");
    assert_eq!(
        built_in.len(),
        all.iter()
            .filter(|item| item["source"] == "built-in")
            .count()
    );
    let git = traverse(snapshot, "index", "q=GIT");
    assert!(ids(&git, "extension_id").contains(&"command.git".to_owned()));
    assert!(git.len() < all.len());
    let encoded = traverse(snapshot, "index", "q=%20git+");
    assert_eq!(encoded, git);
    let risk = all[0]["risk_classes"][0].as_str().unwrap().to_owned();
    let risky = traverse(snapshot, "index", &format!("risk_class={risk}&limit=100"));
    assert!(!risky.is_empty());
    assert!(risky.iter().all(|item| item["risk_classes"]
        .as_array()
        .unwrap()
        .contains(&Value::String(risk.clone()))));
    assert_eq!(
        traverse(snapshot, "index", "trust_class=nonexistent"),
        Vec::<Value>::new()
    );
    let mcp = traverse(snapshot, "index", "surface=mcp&limit=100");
    assert_eq!(
        mcp.len(),
        all.iter().filter(|item| item["surface"] == "mcp").count()
    );
    assert!(!mcp.is_empty());
    assert_eq!(
        ok_body(&read(snapshot, "index", &format!("q={}", "a".repeat(256))))["total_count"],
        0
    );
    for query in [
        "limit=0",
        "limit=101",
        "limit=01",
        "limit=abc",
        "limit=10&limit=10",
        "unknown=1",
        "q",
        "source=../x",
        "q=%FF",
        "q=%0A",
        &format!("q={}", "a".repeat(257)),
        &format!("q={}", "a".repeat(2049)),
    ] {
        assert_eq!(
            error_code(&read(snapshot, "index", query)),
            "catalog_query_invalid",
            "{query}"
        );
    }
    assert_eq!(
        error_code(&read(snapshot, "extensions/command.git", "limit=1")),
        "catalog_query_invalid"
    );
    assert_eq!(
        error_code(&read(snapshot, "extensions/command.git/rules", "q=x")),
        "catalog_query_invalid"
    );
}

#[path = "catalog_read_request_tests.rs"]
mod request_tests;

#[path = "catalog_read_search_tests.rs"]
mod search_tests;
