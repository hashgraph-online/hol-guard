use guard_contracts::is_canonical_business_domain;
use guard_policy_snapshot::business_match::BusinessPolicyMatchV1;
use serde_json::{json, Value};

fn selector(domains: Value) -> bool {
    let value = json!({"schema":"guard.business-policy-match.v1","version":1,
        "services":["google_gmail"],"operations":["mail_send"],"recipientDomains":domains});
    BusinessPolicyMatchV1::from_bounded_json(&serde_json::to_vec(&value).unwrap()).is_ok()
}

#[test]
fn shared_domain_shape_vectors_have_native_parity() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../contracts/business-policy/recipient-domains-v1-fixtures.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        assert_eq!(
            selector(case["domains"].clone()),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
    }
}

#[test]
fn domain_name_label_and_collection_bounds_are_exact() {
    assert!(selector(json!(["a".repeat(63)])));
    assert!(!selector(json!(["a".repeat(64)])));
    let maximum = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(63),
        "a".repeat(61)
    );
    assert_eq!(maximum.len(), 253);
    assert!(selector(json!([maximum.clone()])));
    assert!(!selector(json!([format!("{maximum}a")])));
    assert!(selector(json!((0..256)
        .map(|n| format!("d{n}.test"))
        .collect::<Vec<_>>())));
    assert!(!selector(json!((0..257)
        .map(|n| format!("d{n}.test"))
        .collect::<Vec<_>>())));
    assert!(is_canonical_business_domain("xn--bcher-kva.test"));
    assert!(!is_canonical_business_domain("example.test\n"));
}
