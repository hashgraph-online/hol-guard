use super::*;
use serde_json::json;
use std::fs;

fn put(directory: &Path, value: &Value) -> PackObjectRef {
    let bytes = serde_json::to_vec(value).unwrap();
    assert!(bytes.len() <= OBJECT_BYTES);
    let sha256 = hex_prefix(&Sha256::digest(&bytes), 64);
    fs::write(directory.join(format!("{sha256}.json")), &bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            directory.join(format!("{sha256}.json")),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    PackObjectRef {
        sha256,
        length: bytes.len(),
        expanded_length: bytes.len(),
        kind: "data".into(),
    }
}

fn catalog(count: usize) -> (tempfile::TempDir, CatalogReadRequestV2) {
    let home = tempfile::tempdir().unwrap();
    let directory = home.path().join("native-runtime/catalog-discovery/objects");
    fs::create_dir_all(&directory).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in directory.ancestors().take(3) {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
    let embedded: Value = serde_json::from_slice(embedded_catalog_bytes()).unwrap();
    let mut template = embedded["catalog"][0].clone();
    template["rules"] = json!([]);
    template["permissions"] = json!([]);
    template["mcp_tools"] = json!([]);
    template["rule_count"] = json!(0);
    template["permission_count"] = json!(0);
    let mut rows = Vec::new();
    for index in 0..count {
        let id = format!("synthetic-{index:06}");
        template["extension_id"] = json!(id);
        template["name"] = json!(format!("Extension {index:06}"));
        if index + 1 == count {
            template["description"] = json!("unloadedneedle");
            let permission = embedded["catalog"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|entry| entry["permissions"].as_array().unwrap())
                .next()
                .unwrap()
                .clone();
            template["permissions"] = json!([permission]);
            template["permissions"][0]["extension_id"] = json!(id);
            template["permissions"][0]["permission_id"] = json!("synthetic-needle");
            template["permissions"][0]["description"] = json!("permissionneedle");
            template["permission_count"] = json!(1);
        }
        rows.push((id, put(&directory, &template)));
    }
    let mut next = None;
    for chunk in rows.chunks(64).rev() {
        next = Some(put(
            &directory,
            &json!({"schema":"guard.catalog-discovery-page.v1", "entries":chunk,"next":next}),
        ));
    }
    let root = put(
        &directory,
        &json!({"schema":"guard.catalog-discovery.v1", "authority":"a".repeat(64),"count":count,"first":next}),
    );
    let request = CatalogReadRequestV2 {
        guard_home: home.path().canonicalize().unwrap(),
        discovery_root: root.sha256,
        read: CatalogReadRequestV1 {
            schema: CATALOG_READ_REQUEST_SCHEMA.into(),
            route: "index".into(),
            query: "limit=100".into(),
            if_none_match: None,
            expected_catalog_digest: "b".repeat(64),
        },
    };
    (home, request)
}

fn body(request: &CatalogReadRequestV2) -> Value {
    let result = evaluate(request);
    assert_eq!(result.http_status, 200, "{result:?}");
    let bytes = result.body.unwrap();
    assert!(bytes.len() <= MAX_CATALOG_PAGE_BYTES);
    serde_json::from_str(&bytes).unwrap()
}

#[test]
fn complete_pages_beyond_legacy_cap_and_unloaded_detail_search() {
    let (_home, mut request) = catalog(600);
    let mut ids = Vec::new();
    loop {
        let page = body(&request);
        assert_eq!(page["total_count"], 600);
        ids.extend(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["extension_id"].as_str().unwrap().to_owned()),
        );
        if let Some(cursor) = page["next_cursor"].as_str() {
            request.read.query = format!("limit=100&cursor={cursor}");
        } else {
            break;
        }
    }
    assert_eq!(ids.len(), 600);
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
    request.read.query = "q=unloadedneedle&limit=1".into();
    assert_eq!(
        body(&request)["items"][0]["extension_id"],
        "synthetic-000599"
    );
    request.read.route = "permissions".into();
    request.read.query = "q=permissionneedle&limit=1".into();
    assert_eq!(
        body(&request)["items"][0]["permission_id"],
        "synthetic-needle"
    );
    request.read.route = "extensions/synthetic-000599/permissions".into();
    request.read.query = "limit=1".into();
    assert_eq!(body(&request)["total_count"], 1);
    request.read.route = "extensions/synthetic-000599".into();
    request.read.query.clear();
    assert_eq!(
        body(&request)["extension"]["extension_id"],
        "synthetic-000599"
    );
}

#[test]
fn sixteen_thousand_six_hundred_search_and_page_remain_bounded() {
    let (_home, mut request) = catalog(16_600);
    request.read.query = "limit=1".into();
    let first = body(&request);
    assert_eq!(first["total_count"], 16_600);
    assert_eq!(first["items"].as_array().unwrap().len(), 1);
    request.read.query = "q=unloadedneedle&limit=1".into();
    assert_eq!(
        body(&request)["items"][0]["extension_id"],
        "synthetic-016599"
    );
}

#[test]
fn root_and_active_identity_bind_cursors_etags_and_corruption_fails_closed() {
    let (_home, mut request) = catalog(65);
    request.read.query = "limit=1".into();
    let result = evaluate(&request);
    let first: Value = serde_json::from_str(result.body.as_ref().unwrap()).unwrap();
    request.read.if_none_match = result.etag;
    assert_eq!(evaluate(&request).http_status, 304);
    request.read.if_none_match = None;
    request.read.query = format!("limit=1&cursor={}", first["next_cursor"].as_str().unwrap());
    request.read.expected_catalog_digest = "c".repeat(64);
    assert_eq!(
        evaluate(&request).error_code,
        Some("catalog_snapshot_expired")
    );
    request.read.expected_catalog_digest = "b".repeat(64);
    let directory = request
        .guard_home
        .join("native-runtime/catalog-discovery/objects");
    let bytes = object(&directory, &request.discovery_root).unwrap();
    let mut root: Value = serde_json::from_slice(&bytes).unwrap();
    root["authority"] = json!("d".repeat(64));
    request.discovery_root = put(&directory, &root).sha256;
    assert_eq!(
        evaluate(&request).error_code,
        Some("catalog_snapshot_expired")
    );
    request.read.query = "limit=1".into();
    let first_page: PackObjectRef = serde_json::from_value(root["first"].clone()).unwrap();
    let page: Value = decode(&blob(&directory, &first_page).unwrap()).unwrap();
    let last: PackObjectRef = serde_json::from_value(page["next"].clone()).unwrap();
    fs::remove_file(directory.join(format!("{}.json", last.sha256))).unwrap();
    let failed = evaluate(&request);
    assert_eq!(failed.http_status, 503);
    assert!(failed.body.is_none()); // no successful first-page partial view
    fs::write(
        directory.join(format!("{}.json", request.discovery_root)),
        b"{}",
    )
    .unwrap();
    assert_eq!(evaluate(&request).http_status, 503);
}

#[test]
fn strict_decode_and_retained_page_budget() {
    assert!(decode::<Value>(br#"{"x":1,"x":1}"#).is_err());
    let mut selection = Selection::new(0, 100);
    let item = vec![b'x'; 8_000];
    for _ in 0..100_000 {
        selection.push(&item).unwrap();
    }
    assert_eq!(selection.total, 100_000);
    assert!(selection.bytes < MAX_CATALOG_PAGE_BYTES);
    assert!(selection.items.len() < 100);
}

#[test]
fn concatenated_metadata_details_and_incomplete_or_duplicate_indexes() {
    let (_home, mut request) = catalog(1);
    let directory = request
        .guard_home
        .join("native-runtime/catalog-discovery/objects");
    let mut root: Value = decode(&object(&directory, &request.discovery_root).unwrap()).unwrap();
    let page_ref: PackObjectRef = serde_json::from_value(root["first"].clone()).unwrap();
    let mut page: Value = decode(&blob(&directory, &page_ref).unwrap()).unwrap();
    let metadata: PackObjectRef = serde_json::from_value(page["entries"][0][1].clone()).unwrap();
    let mut value: Value = decode(&blob(&directory, &metadata).unwrap()).unwrap();
    let template = value["permissions"][0].clone();
    let permissions: Vec<Value> = (0..40)
        .map(|index| {
            let mut permission = template.clone();
            permission["permission_id"] = json!(format!("permission-{index:03}"));
            permission["description"] = json!("large metadata detail ".repeat(100));
            permission
        })
        .collect();
    value["permissions"] = json!(permissions);
    value["permission_count"] = json!(40);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(bytes.len() > OBJECT_BYTES);
    let parts: Vec<PackObjectRef> = bytes
        .chunks(OBJECT_BYTES)
        .map(|chunk| {
            let sha256 = hex_prefix(&Sha256::digest(chunk), 64);
            fs::write(directory.join(format!("{sha256}.json")), chunk).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(
                    directory.join(format!("{sha256}.json")),
                    fs::Permissions::from_mode(0o600),
                )
                .unwrap();
            }
            PackObjectRef {
                sha256,
                length: chunk.len(),
                expanded_length: chunk.len(),
                kind: "data".into(),
            }
        })
        .collect();
    let mut metadata = put(
        &directory,
        &json!({"schema":"guard.pack-concat.v1","parts":parts}),
    );
    metadata.kind = "concat".into();
    metadata.expanded_length = bytes.len();
    page["entries"][0][1] = serde_json::to_value(metadata).unwrap();
    root["first"] = serde_json::to_value(put(&directory, &page)).unwrap();
    request.discovery_root = put(&directory, &root).sha256;
    request.read.route = "extensions/synthetic-000000/permissions".into();
    request.read.query = "limit=1".into();
    assert_eq!(body(&request)["total_count"], 40);
    request.read.route = "index".into();
    assert_eq!(body(&request)["total_count"], 1);
    root["count"] = json!(2);
    request.discovery_root = put(&directory, &root).sha256;
    assert_eq!(evaluate(&request).http_status, 503);
    let duplicate = page["entries"][0].clone();
    page["entries"].as_array_mut().unwrap().push(duplicate);
    root["first"] = serde_json::to_value(put(&directory, &page)).unwrap();
    request.discovery_root = put(&directory, &root).sha256;
    assert_eq!(evaluate(&request).http_status, 503);
}
