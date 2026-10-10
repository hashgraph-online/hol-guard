//! Catalog-wide permission search (`permissions?q=`) and the catalog-unique
//! permission ID rule.

use super::*;

/// Reference permission search: every term occurs in the permission's own
/// text fields or its extension's name, ID or executables.
fn expected_permission_search(query: &str) -> Vec<String> {
    let terms: Vec<String> = query.split_whitespace().map(str::to_lowercase).collect();
    let mut catalog = source_catalog();
    catalog.sort_by(|left, right| {
        left["extension_id"]
            .as_str()
            .cmp(&right["extension_id"].as_str())
    });
    let mut matched = Vec::new();
    for extension in &catalog {
        let mut extension_text = vec![
            extension["name"].as_str().unwrap().to_owned(),
            extension["extension_id"].as_str().unwrap().to_owned(),
        ];
        extension_text.extend(
            extension["executables"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned()),
        );
        for permission in extension["permissions"].as_array().unwrap() {
            let mut fields: Vec<String> = [
                "label",
                "example_command",
                "permission_id",
                "description",
                "family",
            ]
            .iter()
            .filter_map(|key| permission[*key].as_str().map(str::to_owned))
            .collect();
            fields.extend(extension_text.iter().cloned());
            let text = fields.join(" ").to_lowercase();
            if terms.iter().all(|term| text.contains(term.as_str())) {
                matched.push(permission["permission_id"].as_str().unwrap().to_owned());
            }
        }
    }
    matched
}

#[test]
fn permission_search_traverses_every_permission_in_index_order() {
    let snapshot = snapshot();
    let expected = expected_permission_search("");
    assert!(
        expected.len() > 100,
        "multi-page traversal needs >100 permissions"
    );
    for limit in [1, 7, 100] {
        let items = traverse(snapshot, "permissions", &format!("limit={limit}"));
        assert_eq!(ids(&items, "permission_id"), expected, "limit {limit}");
    }
    let detail = traverse(snapshot, "extensions/command.git/permissions", "limit=100");
    let searched = traverse(snapshot, "permissions", "limit=100");
    let git: Vec<&Value> = searched
        .iter()
        .filter(|item| item["extension_id"] == "command.git")
        .collect();
    assert_eq!(git.len(), detail.len());
    assert!(git.iter().zip(&detail).all(|(left, right)| *left == right));
    let page = ok_body(&read(snapshot, "permissions", "limit=5"));
    assert_eq!(
        page["schema_version"],
        "guard.daemon.catalog-permission-search.v2"
    );
}

#[test]
fn permission_search_terms_match_source_fields() {
    let snapshot = snapshot();
    for query in [
        "git",
        "push",
        "git push",
        "PUSH  Force",
        "rm",
        "kubectl delete",
        "zz-no-match",
    ] {
        let encoded = query.replace(' ', "+");
        let items = traverse(snapshot, "permissions", &format!("limit=100&q={encoded}"));
        assert_eq!(
            ids(&items, "permission_id"),
            expected_permission_search(query),
            "q={query}"
        );
    }
    assert!(!expected_permission_search("git push").is_empty());
    assert!(expected_permission_search("zz-no-match").is_empty());
    let empty = ok_body(&read(snapshot, "permissions", "q=zz-no-match"));
    assert_eq!(empty["total_count"], 0);
    assert_eq!(empty["next_cursor"], Value::Null);
}

#[test]
fn permission_search_cursors_and_keys_are_bound() {
    let snapshot = snapshot();
    let first = ok_body(&read(snapshot, "permissions", "limit=1&q=git"));
    let cursor = first["next_cursor"]
        .as_str()
        .expect("second page")
        .to_owned();
    assert_eq!(
        error_code(&read(
            snapshot,
            "permissions",
            &format!("limit=1&q=push&cursor={cursor}")
        )),
        "catalog_cursor_invalid"
    );
    assert_eq!(
        error_code(&read(
            snapshot,
            "index",
            &format!("limit=1&cursor={cursor}")
        )),
        "catalog_cursor_invalid"
    );
    for query in [
        "source=command",
        "trust_class=x",
        "extension_id=command.git",
        "q=a&q=b",
    ] {
        assert_eq!(
            error_code(&read(snapshot, "permissions", query)),
            "catalog_query_invalid",
            "{query}"
        );
    }
}

#[test]
fn snapshot_rejects_permission_ids_shared_across_extensions() {
    let rebuild = |catalog: Vec<Value>| {
        let digest = hex_prefix(&Sha256::digest(serde_json::to_vec(&catalog).unwrap()), 64);
        let bytes =
            serde_json::to_vec(&json!({"catalog_digest": digest, "catalog": catalog})).unwrap();
        CatalogReadSnapshot::from_catalog_bytes(&bytes).map(|_| ())
    };
    let mut catalog = source_catalog();
    let mut copy = catalog[0].clone();
    copy["extension_id"] = Value::String("command.zz-copy".into());
    catalog.push(copy);
    assert_eq!(
        rebuild(catalog),
        Err("catalog_read_model_duplicate_permission")
    );
}
