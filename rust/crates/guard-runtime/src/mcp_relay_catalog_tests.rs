use serde_json::json;

use super::*;

fn page(names: &[&str], next: Option<&str>) -> Value {
    let tools: Vec<Value> = names
        .iter()
        .map(|name| json!({"name": name, "inputSchema": {"type": "object"}}))
        .collect();
    let mut result = json!({"tools": tools});
    if let Some(next) = next {
        result["nextCursor"] = json!(next);
    }
    json!({"jsonrpc": "2.0", "id": 1, "result": result})
}

fn names(catalog: &RelayCatalog) -> Vec<String> {
    catalog.catalog.keys().cloned().collect()
}

fn cursor(value: &str) -> McpCatalogCursorV1 {
    McpCatalogCursorV1::String {
        value: value.to_owned(),
    }
}

fn complete(catalog: &mut RelayCatalog, tools: &[&str]) {
    let generation = catalog.begin(McpCatalogCursorV1::None);
    catalog.capture(McpCatalogCursorV1::None, generation, &page(tools, None));
}

#[test]
fn cursor_fact_reads_the_request_cursor() {
    assert_eq!(cursor_fact(None), McpCatalogCursorV1::None);
    assert_eq!(cursor_fact(Some(&json!({}))), McpCatalogCursorV1::None);
    assert_eq!(
        cursor_fact(Some(&json!({"cursor": null}))),
        McpCatalogCursorV1::None
    );
    assert_eq!(cursor_fact(Some(&json!({"cursor": "c2"}))), cursor("c2"));
    assert_eq!(
        cursor_fact(Some(&json!({"cursor": 7}))),
        McpCatalogCursorV1::Other
    );
    assert_eq!(cursor_fact(Some(&json!([]))), McpCatalogCursorV1::Other);
    assert_eq!(cursor_fact(Some(&json!(null))), McpCatalogCursorV1::Other);
}

#[test]
fn starts_unobserved() {
    let catalog = RelayCatalog::default();
    let snapshot = catalog.snapshot();
    assert_eq!(snapshot.state, "unobserved");
    assert_eq!(snapshot.generation, 0);
    assert!(snapshot.fingerprint.is_some());
    assert!(catalog.matches(&snapshot));
}

#[test]
fn a_single_page_listing_completes_the_catalog() {
    let mut catalog = RelayCatalog::default();
    let generation = catalog.begin(McpCatalogCursorV1::None);
    assert_eq!(generation, 1);
    assert_eq!(catalog.snapshot().state, "pending");
    catalog.capture(
        McpCatalogCursorV1::None,
        generation,
        &page(&["read", "write"], None),
    );
    let snapshot = catalog.snapshot();
    assert_eq!(snapshot.state, "complete");
    assert_eq!(snapshot.generation, 1);
    assert_eq!(names(&catalog), vec!["read", "write"]);
    assert_eq!(catalog.catalog["read"]["name"], "read");
    assert!(catalog.matches(&snapshot));
}

#[test]
fn paginated_listings_merge_pages_before_completing() {
    let mut catalog = RelayCatalog::default();
    let first = catalog.begin(McpCatalogCursorV1::None);
    catalog.capture(McpCatalogCursorV1::None, first, &page(&["a"], Some("c2")));
    assert_eq!(catalog.snapshot().state, "pending");
    assert!(names(&catalog).is_empty());
    assert_eq!(catalog.expected_cursor.as_deref(), Some("c2"));

    let second = catalog.begin(cursor("c2"));
    assert_eq!(second, first);
    catalog.capture(cursor("c2"), second, &page(&["b"], None));
    assert_eq!(catalog.snapshot().state, "complete");
    assert_eq!(names(&catalog), vec!["a", "b"]);
    assert!(catalog.pending.is_none());
}

#[test]
fn an_unexpected_cursor_poisons_the_catalog() {
    let mut catalog = RelayCatalog::default();
    let first = catalog.begin(McpCatalogCursorV1::None);
    catalog.capture(McpCatalogCursorV1::None, first, &page(&["a"], Some("c2")));
    catalog.begin(cursor("other"));
    let snapshot = catalog.snapshot();
    assert_eq!(snapshot.state, "error");
    assert!(snapshot.generation > first);
    assert!(names(&catalog).is_empty());
}

#[test]
fn an_error_or_malformed_page_poisons_the_catalog() {
    for response in [
        json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -1, "message": "no"}}),
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": "nope"}}),
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": " padded "}]}}),
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "a"}], "nextCursor": 3}}),
    ] {
        let mut catalog = RelayCatalog::default();
        let generation = catalog.begin(McpCatalogCursorV1::None);
        catalog.capture(McpCatalogCursorV1::None, generation, &response);
        assert_eq!(catalog.snapshot().state, "error", "{response}");
        assert!(names(&catalog).is_empty());
    }
}

#[test]
fn a_repeated_tool_name_across_pages_poisons_the_catalog() {
    let mut catalog = RelayCatalog::default();
    let first = catalog.begin(McpCatalogCursorV1::None);
    catalog.capture(McpCatalogCursorV1::None, first, &page(&["a"], Some("c2")));
    let second = catalog.begin(cursor("c2"));
    catalog.capture(cursor("c2"), second, &page(&["a"], None));
    assert_eq!(catalog.snapshot().state, "error");
}

#[test]
fn a_failed_listing_poisons_only_its_own_generation() {
    let mut catalog = RelayCatalog::default();
    let stale = catalog.begin(McpCatalogCursorV1::None);
    complete(&mut catalog, &["a"]);
    catalog.fail(stale);
    assert_eq!(catalog.snapshot().state, "complete");

    let current = catalog.begin(McpCatalogCursorV1::None);
    catalog.fail(current);
    assert_eq!(catalog.snapshot().state, "error");
}

#[test]
fn invalidate_and_poison_clear_the_catalog_and_break_snapshots() {
    let mut catalog = RelayCatalog::default();
    complete(&mut catalog, &["a"]);
    let decided = catalog.snapshot();
    catalog.invalidate();
    let snapshot = catalog.snapshot();
    assert_eq!(snapshot.state, "invalidated");
    assert_eq!(snapshot.generation, decided.generation + 1);
    assert!(names(&catalog).is_empty());
    assert!(!catalog.matches(&decided));

    complete(&mut catalog, &["a"]);
    let decided = catalog.snapshot();
    catalog.poison();
    assert_eq!(catalog.snapshot().state, "error");
    assert!(!catalog.matches(&decided));
}

#[test]
fn a_relisted_identical_catalog_is_a_new_authority() {
    let mut catalog = RelayCatalog::default();
    complete(&mut catalog, &["a"]);
    let decided = catalog.snapshot();
    complete(&mut catalog, &["a"]);
    assert_eq!(catalog.snapshot().fingerprint, decided.fingerprint);
    assert!(!catalog.matches(&decided));
}

#[test]
fn a_changed_definition_changes_the_fingerprint() {
    let mut first = RelayCatalog::default();
    complete(&mut first, &["a"]);
    let mut second = RelayCatalog::default();
    let generation = second.begin(McpCatalogCursorV1::None);
    second.capture(
        McpCatalogCursorV1::None,
        generation,
        &json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
            {"name": "a", "inputSchema": {"type": "object", "required": ["path"]}}
        ]}}),
    );
    assert_eq!(second.snapshot().state, "complete");
    assert_ne!(first.snapshot().fingerprint, second.snapshot().fingerprint);
}

#[test]
fn an_unappliable_payload_records_an_unavailable_catalog() {
    let mut catalog = RelayCatalog::default();
    complete(&mut catalog, &["a"]);
    let generation = catalog.generation;
    assert!(catalog.rebuild(&json!({"state": {}})).is_none());
    catalog.unavailable();
    assert_eq!(catalog.state, "error");
    assert_eq!(catalog.generation, generation + 1);
    assert!(catalog.catalog.is_empty());
    assert!(catalog.pending.is_none());
    assert!(!catalog.inflight);
}
