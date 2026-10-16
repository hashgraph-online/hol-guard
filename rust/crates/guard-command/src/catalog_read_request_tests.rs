//! Request handling: cursors, route resolution, conditional reads, request
//! binding, snapshot validation and page byte budgets.

use super::*;

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
