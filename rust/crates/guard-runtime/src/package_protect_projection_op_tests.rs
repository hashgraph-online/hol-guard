//! Parity vectors recorded from the legacy Python package-protect projection
//! (`_apply_package_protect_projection` and its helpers) before deletion. The
//! per-call receipt id and timestamp are masked.

use super::*;
use flate2::read::GzDecoder;
use std::io::Read;

const VECTORS: &[u8] = include_bytes!("../testdata/package_protect_projection_vectors.json.gz");
const MASK: &str = "<masked>";

fn vectors() -> Vec<Value> {
    let mut text = String::new();
    GzDecoder::new(VECTORS)
        .read_to_string(&mut text)
        .expect("gunzip vectors");
    serde_json::from_str(&text).expect("vector json")
}

fn mask_receipt(receipt: &mut Value) {
    let receipt = receipt.as_object_mut().expect("receipt object");
    let id = receipt["receipt_id"].as_str().expect("receipt id");
    assert!(id.starts_with("guard-receipt-") && id.len() == "guard-receipt-".len() + 36);
    assert!(receipt["timestamp"]
        .as_str()
        .is_some_and(|t| t.contains('T')));
    receipt.insert("receipt_id".to_owned(), json!(MASK));
    receipt.insert("timestamp".to_owned(), json!(MASK));
}

#[test]
fn recorded_python_protect_projection_vectors_match() {
    let vectors = vectors();
    assert!(vectors.len() >= 1000);
    for (index, vector) in vectors.iter().enumerate() {
        let mut query = vector["query"].clone();
        query.as_object_mut().unwrap().remove("query");
        let query: PackageAuditProtectProjectionQueryV1 =
            serde_json::from_value(query).unwrap_or_else(|error| panic!("vector {index}: {error}"));
        let mut actual =
            protect_projection(&query).unwrap_or_else(|e| panic!("vector {index}: {e}"));
        mask_receipt(&mut actual["fields"]["receipt"]);
        assert_eq!(actual, vector["expected"], "vector {index}");
    }
}

#[test]
fn malformed_intent_is_invalid() {
    let vectors = vectors();
    let mut query = vectors[0]["query"].clone();
    query.as_object_mut().unwrap().remove("query");
    query["intent"]["intent_kind"] = json!("bogus");
    let query: PackageAuditProtectProjectionQueryV1 = serde_json::from_value(query).unwrap();
    assert_eq!(
        protect_projection(&query).unwrap_err(),
        "native_package_audit_projection_invalid"
    );
}
