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
        "description",
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
        let mut expected_permissions = permissions.clone();
        expected_permissions.sort_by_key(|item| item["permission_id"].as_str().unwrap().to_owned());
        let route = format!("extensions/{id}/permissions");
        assert_eq!(traverse(snapshot, &route, "limit=3"), expected_permissions);
        let mut expected_rules = rules.clone();
        expected_rules.sort_by_key(|item| item["rule_id"].as_str().unwrap().to_owned());
        assert_eq!(
            traverse(snapshot, &format!("extensions/{id}/rules"), ""),
            expected_rules
        );
        let mut expected_tools = source["mcp_tools"].as_array().cloned().unwrap_or_default();
        expected_tools.sort_by_key(|item| item["name"].as_str().unwrap().to_owned());
        assert_eq!(
            detail["collections"]["mcp_tools"]["total_count"],
            expected_tools.len()
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

#[test]
fn cursors_bind_snapshot_resource_filter_and_offset() {
    let snapshot = snapshot();
    let first = ok_body(&read(snapshot, "index", "limit=2"));
    let cursor = first["next_cursor"].as_str().unwrap().to_owned();
    let again = read(snapshot, "index", &format!("limit=2&cursor={cursor}"));
    assert_eq!(
        again,
        read(snapshot, "index", &format!("limit=2&cursor={cursor}"))
    );
    // The limit is not part of the binding; a client may change page size.
    assert_eq!(
        ok_body(&read(
            snapshot,
            "index",
            &format!("limit=5&cursor={cursor}")
        ))["items"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    let parts: Vec<&str> = cursor.split('.').collect();
    let altered_offset = format!("{}.{}.{}.{}", parts[0], parts[1], 3, parts[3]);
    let flipped = parts[3].replace(
        &parts[3][..1],
        if &parts[3][..1] == "0" { "1" } else { "0" },
    );
    let altered_check = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], flipped);
    for bad in [
        altered_offset.as_str(),
        altered_check.as_str(),
        "v1.0000000000000000.2.00000000000000000000000000000000",
        "v2.x",
        "../../etc/passwd",
        "v1.ABCDEF0000000000.2.00000000000000000000000000000000",
        "v1.0000000000000000.02.00000000000000000000000000000000",
    ] {
        let code = error_code(&read(snapshot, "index", &format!("limit=2&cursor={bad}")));
        assert!(
            matches!(code, "catalog_cursor_invalid" | "catalog_snapshot_expired"),
            "{bad}"
        );
    }
    assert_eq!(
        error_code(&read(
            snapshot,
            "index",
            &format!("limit=2&cursor={altered_check}")
        )),
        "catalog_cursor_invalid"
    );
    // Wrong filter or wrong resource with this snapshot's cursor.
    assert_eq!(
        error_code(&read(
            snapshot,
            "index",
            &format!("source=built-in&cursor={cursor}")
        )),
        "catalog_cursor_invalid"
    );
    assert_eq!(
        error_code(&read(
            snapshot,
            "extensions/command.git/rules",
            &format!("cursor={cursor}")
        )),
        "catalog_cursor_invalid"
    );
    assert_eq!(
        error_code(&read(
            snapshot,
            "index",
            &format!("cursor={}", "x".repeat(70))
        )),
        "catalog_cursor_invalid"
    );
    let other = synthetic(|catalog| {
        catalog[0]["description"] = Value::String("changed snapshot".into());
    });
    assert_ne!(other.snapshot_id(), snapshot.snapshot_id());
    assert_eq!(
        error_code(&read(&other, "index", &format!("limit=2&cursor={cursor}"))),
        "catalog_snapshot_expired"
    );
}

#[test]
fn routes_resolve_ids_safely() {
    let snapshot = snapshot();
    for route in [
        "extensions/../index",
        "extensions/Command.Git",
        "extensions/a/b",
        "",
        "index/",
        "extensions/.x",
    ] {
        assert_eq!(
            error_code(&read(snapshot, route, "")),
            "catalog_route_not_found",
            "{route}"
        );
    }
    assert_eq!(
        error_code(&read(
            snapshot,
            &format!("extensions/{}", "a".repeat(600)),
            ""
        )),
        "catalog_route_not_found"
    );
    assert_eq!(
        error_code(&read(snapshot, "extensions/command.absent", "")),
        "catalog_extension_not_found"
    );
    assert_eq!(
        error_code(&read(snapshot, "extensions/command.absent/permissions", "")),
        "catalog_extension_not_found"
    );
}

#[test]
fn conditional_reads_follow_weak_comparison() {
    let snapshot = snapshot();
    let full = read(snapshot, "index", "limit=10");
    let etag = full.etag.clone().unwrap();
    assert!(etag.starts_with("\"cr1-") && etag.ends_with('"'));
    let conditional = |header: &str| {
        let mut req = request(snapshot, "index", "limit=10");
        req.if_none_match = Some(header.to_owned());
        snapshot.read(&req)
    };
    for header in [
        etag.clone(),
        format!("W/{etag}"),
        format!("\"other\", {etag}"),
        "*".into(),
    ] {
        let result = conditional(&header);
        assert_eq!(
            (result.outcome, result.http_status),
            ("not_modified", 304),
            "{header}"
        );
        assert_eq!(result.body, None);
        assert_eq!(result.etag.as_deref(), Some(etag.as_str()));
    }
    for header in [
        "\"other\"",
        "garbage",
        &format!("{etag}, bad"),
        &"\"a\",".repeat(40),
    ] {
        assert_eq!(conditional(header).outcome, "ok", "{header}");
    }
    assert_ne!(read(snapshot, "index", "limit=11").etag.unwrap(), etag);
    assert_ne!(
        read(snapshot, "index", "").etag,
        read(snapshot, "extensions/command.git", "").etag
    );
}

#[test]
fn request_binding_fails_closed() {
    let snapshot = snapshot();
    let mut mismatch = request(snapshot, "index", "");
    mismatch.expected_catalog_digest = "0".repeat(64);
    assert_eq!(
        error_code(&snapshot.read(&mismatch)),
        "catalog_snapshot_mismatch"
    );
    assert_eq!(snapshot.read(&mismatch).http_status, 503);
    let mut bad_schema = request(snapshot, "index", "");
    bad_schema.schema = "guard-catalog-read-request.v0".into();
    assert_eq!(
        error_code(&snapshot.read(&bad_schema)),
        "catalog_request_invalid"
    );
    let mut bad_digest = request(snapshot, "index", "");
    bad_digest.expected_catalog_digest = "XYZ".into();
    assert_eq!(
        error_code(&snapshot.read(&bad_digest)),
        "catalog_request_invalid"
    );
    let unknown: Result<CatalogReadRequestV1, _> = serde_json::from_value(json!({
        "schema": CATALOG_READ_REQUEST_SCHEMA, "route": "index", "query": "",
        "if_none_match": null, "expected_catalog_digest": "0".repeat(64), "extra": 1
    }));
    assert!(unknown.is_err());
}

#[test]
fn snapshot_rejects_tampered_or_unbounded_catalogs() {
    let mut envelope: Value = serde_json::from_slice(embedded_catalog_bytes()).unwrap();
    envelope["catalog"][0]["name"] = Value::String("tampered".into());
    let tampered = serde_json::to_vec(&envelope).unwrap();
    assert_eq!(
        CatalogReadSnapshot::from_catalog_bytes(&tampered).unwrap_err(),
        "catalog_read_model_digest_mismatch"
    );
    let rebuild = |catalog: Vec<Value>| {
        let digest = hex_prefix(&Sha256::digest(serde_json::to_vec(&catalog).unwrap()), 64);
        let bytes =
            serde_json::to_vec(&json!({"catalog_digest": digest, "catalog": catalog})).unwrap();
        CatalogReadSnapshot::from_catalog_bytes(&bytes).map(|_| ())
    };
    let mut long = source_catalog();
    long[0]["description"] = Value::String("x".repeat(8193));
    assert_eq!(rebuild(long), Err("catalog_read_model_string_limit"));
    let mut missing = source_catalog();
    missing[0].as_object_mut().unwrap().remove("publisher");
    assert_eq!(
        rebuild(missing),
        Err("catalog_read_model_projection_field_missing")
    );
    let mut duplicate = source_catalog();
    let first = duplicate[0].clone();
    duplicate.push(first);
    assert_eq!(
        rebuild(duplicate),
        Err("catalog_read_model_duplicate_extension")
    );
}

#[test]
fn pages_respect_byte_budget_and_reject_unrepresentable_items() {
    let large = synthetic(|catalog| {
        let template = catalog[0]["permissions"][0].clone();
        let permissions: Vec<Value> = (0..200)
            .map(|index| {
                let mut permission = template.clone();
                permission["permission_id"] =
                    Value::String(format!("command.big.permission.p{index:03}"));
                permission["description"] = Value::String("<&>".repeat(2730));
                permission
            })
            .collect();
        catalog[0]["permissions"] = Value::Array(permissions);
    });
    let id = {
        let mut ids = ids(&source_catalog(), "extension_id");
        ids.truncate(1);
        ids.remove(0)
    };
    let route = format!("extensions/{id}/permissions");
    let page = ok_body(&read(&large, &route, "limit=100"));
    let count = page["items"].as_array().unwrap().len();
    assert!(
        count > 0 && count < 100,
        "byte budget should cut the page: {count}"
    );
    let body = read(&large, &route, "limit=100").body.unwrap();
    assert!(!body.contains('<') && !body.contains('>') && !body.contains('&'));
    assert!(body.contains("\\u003c\\u0026\\u003e"));
    assert_eq!(traverse(&large, &route, "limit=100").len(), 200);

    let oversized = synthetic(|catalog| {
        let huge: Vec<Value> = (0..40)
            .map(|index| Value::String(format!("{index}{}", "y".repeat(8000))))
            .collect();
        let mut permission = catalog[0]["permissions"][0].clone();
        permission["rule_ids"] = Value::Array(huge);
        catalog[0]["permissions"] = json!([permission]);
    });
    assert_eq!(
        error_code(&read(&oversized, &route, "")),
        "catalog_item_exceeds_page_budget"
    );
}
