use super::*;

const VECTORS: &str = include_str!("../testdata/daemon_edge_extensions_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn key() -> Vec<u8> {
    vectors()["key"].as_str().unwrap().as_bytes().to_vec()
}

#[test]
fn rejects_queries_with_the_code_the_daemon_raises() {
    let key = key();
    for case in vectors()["errors"].as_array().unwrap() {
        let query = case["query"].as_str().unwrap();
        let code = extensions_page(query, &key).expect(query).expect_err(query);
        assert_eq!(json!({"error": code}), case["body"], "{query}");
    }
}

#[test]
fn signs_the_next_page_cursor_as_the_daemon_signs_it() {
    let vectors = vectors();
    let signed = sign(
        &json!({"kind": "extensions", "after": "command.git"}),
        &key(),
    );
    assert_eq!(
        signed.as_deref(),
        vectors["cursor_after_command_git"].as_str()
    );
}

#[test]
fn pages_through_every_built_in_extension_in_id_order() {
    let vectors = vectors();
    let key = key();
    let mut seen = Vec::new();
    let mut query = "limit=7".to_owned();
    loop {
        let body = extensions_page(&query, &key).unwrap().unwrap();
        assert_eq!(body["schema_version"], vectors["schema_version"]);
        assert_eq!(body["source"], vectors["source"]);
        for item in body["items"].as_array().unwrap() {
            let keys: Vec<&String> = item.as_object().unwrap().keys().collect();
            let mut expected: Vec<&str> = vectors["item_keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|key| key.as_str().unwrap())
                .collect();
            expected.sort_unstable();
            assert_eq!(keys, expected);
            assert_eq!(
                item["rule_count"].as_u64().unwrap() as usize,
                item["rules"].as_array().unwrap().len()
            );
            assert_eq!(item["enabled"], true);
            seen.push(item["extension_id"].as_str().unwrap().to_owned());
        }
        match &body["next_cursor"] {
            Value::String(cursor) => query = format!("limit=7&cursor={cursor}"),
            _ => break,
        }
    }
    let allowlists = allowlists().unwrap();
    let expected: Vec<String> = allowlists["extension_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect();
    assert!(!seen.is_empty());
    assert_eq!(seen, expected);
}

#[test]
fn allowlists_name_the_daemon_constants() {
    let allowlists = allowlists().unwrap();
    assert_eq!(
        allowlists["proof_levels"],
        json!(["pre_hook", "post_hook", "unpaired_post"])
    );
    let harnesses = allowlists["harnesses"].as_array().unwrap();
    let mut sorted = harnesses.clone();
    sorted.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    assert_eq!(harnesses, &sorted);
    assert_eq!(allowlists["error_classes"].as_array().unwrap().len(), 5);
}
