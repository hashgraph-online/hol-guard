use super::*;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;

const VECTORS: &str = include_str!("../tests/fixtures/skill_identity_vectors.json");

fn content(case: &Value) -> String {
    let encoded = case["content_b64"].as_str().expect("content_b64");
    let bytes = STANDARD.decode(encoded).expect("base64");
    String::from_utf8(bytes).expect("utf-8")
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item.as_str().expect("string").to_owned())
        .collect()
}

#[test]
fn identity_matches_python_vectors() {
    let corpus: Value = serde_json::from_str(VECTORS).expect("vectors");
    let cases = corpus["cases"].as_array().expect("cases");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let identity = build_skill_identity(&content(case));
        assert_eq!(
            identity.skill_hash,
            case["skill_hash"].as_str().expect("skill_hash"),
            "{name}: skill hash"
        );
        assert_eq!(
            identity.reference_hashes,
            strings(&case["reference_hashes"]),
            "{name}: reference hashes"
        );
        assert_eq!(
            identity.template_hashes,
            strings(&case["template_hashes"]),
            "{name}: template hashes"
        );
        assert_eq!(
            identity.script_hashes,
            strings(&case["script_hashes"]),
            "{name}: script hashes"
        );
        assert_eq!(
            identity.identity_hash(),
            case["identity_hash"].as_str().expect("identity_hash"),
            "{name}: identity hash"
        );
    }
}

#[test]
fn identity_hash_is_order_independent_within_a_group() {
    let one = build_skill_identity("[a](x) and [b](y)");
    let other = build_skill_identity("[b](y) and [a](x)");
    assert_ne!(one.reference_hashes, other.reference_hashes);
    assert_ne!(one.skill_hash, other.skill_hash);
    let shared = SkillIdentity {
        skill_hash: "same".to_owned(),
        template_hashes: Vec::new(),
        script_hashes: Vec::new(),
        reference_hashes: one.reference_hashes,
    };
    let swapped = SkillIdentity {
        skill_hash: "same".to_owned(),
        template_hashes: Vec::new(),
        script_hashes: Vec::new(),
        reference_hashes: other.reference_hashes,
    };
    assert_eq!(shared.identity_hash(), swapped.identity_hash());
}

#[test]
fn groups_stay_separate_in_the_composition() {
    // A digest moved between groups must change the identity, so the joined
    // payload can never be read as one flat list.
    let left = SkillIdentity {
        skill_hash: "s".to_owned(),
        reference_hashes: vec!["a".to_owned()],
        template_hashes: Vec::new(),
        script_hashes: Vec::new(),
    };
    let right = SkillIdentity {
        skill_hash: "s".to_owned(),
        reference_hashes: Vec::new(),
        template_hashes: vec!["a".to_owned()],
        script_hashes: Vec::new(),
    };
    assert_ne!(left.identity_hash(), right.identity_hash());
}
