//! How the inventory read packs declarations for the classifier: what travels,
//! what is left undescribed, and the bounds every page stays under.
//!
//! Python's transport mirror pages by serialized bytes as well as by item
//! count, so a connector whose commands repeat one large stored schema never
//! builds a page the op would refuse. These pin the same two bounds here.

use guard_contracts::{
    write_canonical_json_with_limit, McpClassificationRequestV1, MCP_CLASSIFICATION_MAX_BYTES,
    MCP_CLASSIFICATION_MAX_ITEMS, MCP_CLASSIFICATION_REQUEST_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::guard_store_local_cli_inventory_rows::{classifications, pack, Page};

/// A declaration carrying roughly `kibibytes` of `filler`. The filler is
/// split across fields because one collection may hold only so many items,
/// and each string stays inside the per-string limit, so the schema is large
/// without being refused by the parser.
fn filled_declaration(name: &str, kibibytes: usize, filler: &str) -> Value {
    let mut schema = Map::new();
    schema.insert("type".to_owned(), Value::from("object"));
    let mut remaining = kibibytes;
    let mut field = 0;
    while remaining > 0 {
        let width = remaining.min(2048);
        let values: Vec<Value> = (0..width).map(|_| Value::from(filler)).collect();
        schema.insert(format!("filler{field}"), Value::Array(values));
        remaining -= width;
        field += 1;
    }
    json!({ "name": name, "inputSchema": Value::Object(schema) })
}

/// A declaration whose schema is ASCII, so canonical JSON and UTF-8 agree on
/// its size.
fn declaration(name: &str, kibibytes: usize) -> Value {
    filled_declaration(name, kibibytes, &"x".repeat(1024))
}

/// A declaration of the same UTF-8 size whose schema is not ASCII: canonical
/// JSON escapes each character to six bytes where UTF-8 spends three, so it
/// reaches the op at twice the size a compact serialization reports.
fn wide_declaration(name: &str, kibibytes: usize) -> Value {
    filled_declaration(name, kibibytes, &"\u{754c}".repeat(341))
}

/// Bytes the op counts for the request a packed page becomes: its canonical
/// serialization, the one `MCP_CLASSIFICATION_MAX_BYTES` is applied to.
fn page_bytes(page: &Page) -> usize {
    let request = McpClassificationRequestV1 {
        schema: MCP_CLASSIFICATION_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        items: page.items.clone(),
    };
    let value = serde_json::to_value(&request).unwrap();
    let mut bytes = Vec::new();
    write_canonical_json_with_limit(&value, &mut bytes, usize::MAX, "oversize").unwrap();
    bytes.len()
}

#[test]
fn a_declaration_no_page_can_carry_is_left_undescribed() {
    let first = declaration("first", 1);
    let huge = declaration("huge", 8192);
    let last = declaration("last", 1);
    let definitions = [&first, &huge, &last];

    let pages = pack(&definitions);
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].indices, vec![0, 2]);

    let described = classifications(&definitions);
    assert!(!described[0].is_null(), "{described:?}");
    assert!(described[1].is_null(), "{described:?}");
    assert!(!described[2].is_null(), "{described:?}");
}

#[test]
fn large_declarations_split_into_pages_under_the_byte_budget() {
    let owned: Vec<Value> = (0..4)
        .map(|index| declaration(&format!("tool{index}"), 2048))
        .collect();
    let definitions: Vec<&Value> = owned.iter().collect();

    let pages = pack(&definitions);
    let count = pages.len();
    assert!(
        count >= 2,
        "four large declarations packed into {count} page"
    );
    for page in &pages {
        let bytes = page_bytes(page);
        assert!(
            bytes <= MCP_CLASSIFICATION_MAX_BYTES,
            "page of {bytes} bytes"
        );
    }
    let order: Vec<usize> = pages.iter().flat_map(|page| page.indices.clone()).collect();
    assert_eq!(order, vec![0, 1, 2, 3]);

    let described = classifications(&definitions);
    assert!(described.iter().all(|entry| !entry.is_null()));
}

#[test]
fn non_ascii_declarations_are_measured_as_the_op_measures_them() {
    // Three declarations of about 1.4 MiB of UTF-8 each. A compact measure
    // reads them as 4.2 MiB and packs all three onto one page; the op counts
    // the canonical escapes instead, reaches 8.4 MiB and refuses it.
    let owned: Vec<Value> = (0..3)
        .map(|index| wide_declaration(&format!("tool{index}"), 1400))
        .collect();
    let definitions: Vec<&Value> = owned.iter().collect();

    let pages = pack(&definitions);
    let count = pages.len();
    assert!(
        count >= 2,
        "three wide declarations packed into {count} page"
    );
    for page in &pages {
        let bytes = page_bytes(page);
        assert!(
            bytes <= MCP_CLASSIFICATION_MAX_BYTES,
            "page of {bytes} bytes"
        );
    }
    let order: Vec<usize> = pages.iter().flat_map(|page| page.indices.clone()).collect();
    assert_eq!(order, vec![0, 1, 2]);
}

#[test]
fn the_item_cap_still_closes_a_page_of_small_declarations() {
    let owned: Vec<Value> = (0..=MCP_CLASSIFICATION_MAX_ITEMS)
        .map(|index| json!({ "name": format!("tool{index}") }))
        .collect();
    let definitions: Vec<&Value> = owned.iter().collect();

    let pages = pack(&definitions);
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].items.len(), MCP_CLASSIFICATION_MAX_ITEMS);
    assert_eq!(pages[1].indices, vec![MCP_CLASSIFICATION_MAX_ITEMS]);

    let described = classifications(&definitions);
    assert!(described.iter().all(|entry| !entry.is_null()));
}
