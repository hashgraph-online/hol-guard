use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde_json::{json, Map, Value};

use super::*;

fn document() -> &'static Value {
    static DOCUMENT: OnceLock<Value> = OnceLock::new();
    DOCUMENT.get_or_init(|| {
        let raw = include_str!("../testdata/inventory_item_metadata_parity.json");
        serde_json::from_str(raw).expect("inventory item metadata parity fixture parses")
    })
}

fn cases(section: &str) -> &'static [Value] {
    document()[section]
        .as_array()
        .unwrap_or_else(|| panic!("fixture section {section} is an array"))
}

fn object(value: &Value) -> Map<String, Value> {
    value
        .as_object()
        .expect("fixture metadata is an object")
        .clone()
}

fn text(value: &Value) -> &str {
    value.as_str().expect("fixture value is a string")
}

/// The fixture is interpreter-dependent in principle, so a regenerated corpus
/// that silently moved interpreter is visible here rather than in a diff.
#[test]
fn fixture_records_the_targeted_interpreter() {
    assert!(
        text(&document()["python_version"]).starts_with("3.12."),
        "regenerate the fixture with `uv run --python 3.12`: {}",
        text(&document()["python_version"]),
    );
}

#[test]
fn item_kind_matches_python() {
    let recorded = cases("item_kind");
    assert!(recorded.len() >= 25, "fixture lost item-kind coverage");
    for case in recorded {
        let artifact_type = text(&case["artifact_type"]);
        assert_eq!(
            item_kind(artifact_type),
            text(&case["kind"]),
            "item kind for {artifact_type:?}",
        );
    }
}

#[test]
fn canonical_content_hash_matches_python() {
    for case in cases("canonical_content_hash") {
        let value = text(&case["value"]);
        assert_eq!(
            canonical_inventory_content_hash(value),
            text(&case["canonical"]),
            "canonical hash for {value:?}",
        );
    }
}

/// A prefixed or mixed-case value is returned in the spelling it arrived in:
/// the lower-casing only decides whether the value is a bare digest.
#[test]
fn canonical_content_hash_returns_the_original_spelling() {
    let prefixed = format!("SHA256:{}", "A".repeat(64));
    assert_eq!(canonical_inventory_content_hash(&prefixed), prefixed);
    assert_eq!(
        canonical_inventory_content_hash(&"A".repeat(64)),
        format!("sha256:{}", "a".repeat(64)),
    );
}

#[test]
fn resolve_content_hash_matches_python() {
    for case in cases("resolve_content_hash") {
        let metadata = object(&case["metadata"]);
        let semantic = text(&case["semantic_text"]);
        assert_eq!(
            resolve_item_content_hash(&metadata, semantic),
            text(&case["resolved"]),
            "resolved hash for {:?}",
            case["metadata"],
        );
    }
}

#[test]
fn validated_directory_hash_matches_python() {
    let recorded = cases("validated_directory_hash");
    let accepted = recorded
        .iter()
        .filter(|case| !case["validated"].is_null())
        .count();
    assert!(accepted >= 3, "fixture lost every accepted identity case");
    assert!(
        accepted < recorded.len(),
        "fixture lost every rejected identity case",
    );
    for case in recorded {
        let metadata = object(&case["metadata"]);
        let expected = case["validated"].as_str().map(str::to_owned);
        assert_eq!(
            validated_complete_skill_directory_hash(&metadata),
            expected,
            "validated hash for {:?}",
            case["metadata"],
        );
        assert_eq!(
            Value::Object(discard_unverified_skill_directory_hash(&metadata)),
            case["sanitized"],
            "sanitized metadata for {:?}",
            case["metadata"],
        );
    }
}

#[test]
fn capabilities_and_risk_match_python() {
    let recorded = cases("capabilities");
    assert!(recorded.len() >= 100, "fixture lost capability coverage");
    for case in recorded {
        let artifact_type = text(&case["artifact_type"]);
        let metadata = object(&case["metadata"]);
        let expected: Vec<&str> = case["capabilities"]
            .as_array()
            .expect("capabilities is an array")
            .iter()
            .map(text)
            .collect();
        assert_eq!(
            capabilities_for_artifact(artifact_type, &metadata),
            expected,
            "capabilities for {artifact_type} {:?}",
            case["metadata"],
        );
        assert_eq!(
            risk_level(&metadata),
            text(&case["risk_level"]),
            "risk level for {:?}",
            case["metadata"],
        );
    }
}

/// `bool("no")` and `bool([0])` are true, so evidence that is present but not
/// a JSON boolean still raises the item's risk level.
#[test]
fn truthy_evidence_is_python_truthiness_not_a_boolean() {
    for present in [
        json!("no"),
        json!([0]),
        json!(1),
        json!({"a": 1}),
        json!(-0.5),
    ] {
        let mut metadata = Map::new();
        metadata.insert("envConfigurationPresent".to_owned(), present.clone());
        assert_eq!(risk_level(&metadata), "high", "risk level for {present}");
        assert!(
            capabilities_for_artifact("skill", &metadata).contains(&"reads_secrets".to_owned()),
            "capabilities for {present}",
        );
    }
    for absent in [
        json!(false),
        json!(0),
        json!(0.0),
        json!(""),
        json!([]),
        json!({}),
        Value::Null,
    ] {
        let mut metadata = Map::new();
        metadata.insert("has_auth_headers".to_owned(), absent.clone());
        assert_eq!(risk_level(&metadata), "info", "risk level for {absent}");
        assert_eq!(
            capabilities_for_artifact("skill", &metadata),
            vec!["unknown".to_owned()],
            "capabilities for {absent}",
        );
    }
    assert!(!python_truthy(None));
}

#[test]
fn skill_document_evidence_matches_python() {
    for case in cases("skill_document_evidence") {
        let metadata = object(&case["metadata"]);
        let primary = case["primary_content_hash"].as_str();
        assert_eq!(
            Value::Object(bind_skill_document_evidence(&metadata, primary)),
            case["bound"],
            "bound evidence for {:?} + {primary:?}",
            case["metadata"],
        );
    }
}

/// The bounded roots a source-of-truth inspection may reach. A workspace is
/// inspected as the workspace even when it sits inside the home directory, so
/// its root stays ahead of the home root.
#[test]
fn a_workspace_root_precedes_the_home_root() {
    let home = Path::new("/home/user");
    for (workspace, expected) in [
        (None, vec![home.to_path_buf()]),
        (
            Some("/home/user/project"),
            vec![PathBuf::from("/home/user/project"), home.to_path_buf()],
        ),
        (
            Some("/srv/work"),
            vec![PathBuf::from("/srv/work"), home.to_path_buf()],
        ),
        (
            Some("/home/user"),
            vec![home.to_path_buf(), home.to_path_buf()],
        ),
    ] {
        assert_eq!(
            safe_roots_for_inspection(home, workspace.map(Path::new)),
            expected,
            "safe roots for {workspace:?}",
        );
    }
}
