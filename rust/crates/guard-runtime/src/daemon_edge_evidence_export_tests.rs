use super::*;

/// Recorded from the daemon's `export_evidence_json` and
/// `export_evidence_csv` over fixed records and a fixed `_now_iso()`.
const VECTORS: &str = include_str!("../testdata/daemon_edge_evidence_export_vectors.json");

#[test]
fn exports_match_the_recorded_daemon_bodies() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let exported_at = vectors["exported_at"].as_str().unwrap();
    let items = vectors["items"].as_array().unwrap();
    assert_eq!(json_text(exported_at, items).unwrap(), vectors["json"]);
    assert_eq!(csv_text(exported_at, items).unwrap(), vectors["csv"]);
    assert_eq!(json_text(exported_at, &[]).unwrap(), vectors["empty_json"]);
    assert_eq!(csv_text(exported_at, &[]).unwrap(), vectors["empty_csv"]);
}

#[test]
fn a_float_python_writes_in_exponent_form_goes_to_the_daemon() {
    let mut item = serde_json::Map::new();
    for field in FIELDS {
        item.insert(field.to_owned(), json!("x"));
    }
    item.insert("confidence".to_owned(), json!(1e-7));
    let items = [Value::Object(item)];
    assert_eq!(json_text("t", &items), None);
    assert_eq!(csv_text("t", &items), None);
}

#[test]
fn the_timestamp_always_carries_microseconds() {
    let text = now().unwrap();
    assert!(text.ends_with('Z'), "{text}");
    assert_eq!(text.len(), "2026-01-02T03:04:05.000006Z".len(), "{text}");
}
