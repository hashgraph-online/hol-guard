use guard_contracts::BusinessActionV1;
use guard_policy_snapshot::business_match::*;
use serde_json::{json, Value};

fn selector(value: &Value) -> Result<BusinessPolicyMatchV1, BusinessPolicyMatchErrorV1> {
    BusinessPolicyMatchV1::from_bounded_json(&serde_json::to_vec(value).unwrap())
}

fn fixtures() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/business-policy/selector-v1-fixtures.json"
    ))
    .unwrap()
}

#[test]
fn shared_cloud_native_validation_vectors() {
    let fixtures = fixtures();
    for case in fixtures["cases"].as_array().unwrap() {
        let mut value = fixtures["base"].clone();
        for (key, patch) in case["patch"].as_object().unwrap() {
            value[key] = patch.clone();
        }
        if let Some(remove) = case["remove"].as_array() {
            for key in remove {
                value.as_object_mut().unwrap().remove(key.as_str().unwrap());
            }
        }
        assert_eq!(
            selector(&value).is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["id"]
        );
    }
}

fn facts_value() -> Value {
    json!({
        "schema": "guard.business-action.v1", "version": 1,
        "provider": {"service": "google_gmail", "account_binding": "a".repeat(64),
            "tenant_binding": "b".repeat(64), "identity_state": "known",
            "tool_identity_digest": "c".repeat(64), "tool_schema_digest": "d".repeat(64)},
        "operation": "mail_send",
        "audience": {"kind": "named", "expansion_state": "known", "recipients": [
            {"identity_binding": "e".repeat(64), "domain": "example.test", "kind": "to"},
            {"identity_binding": "f".repeat(64), "domain": "example.test", "kind": "bcc"}]},
        "content": {"snapshot_digest": "1".repeat(64), "attachment_digests": [],
            "inspection_state": "known", "inspected_bytes": 128, "sensitivity_labels": ["confidential"]},
        "target": {"resource_binding": "3".repeat(64), "revision_binding": "4".repeat(64),
            "field_diff_digest": "5".repeat(64), "batch_manifest_digest": "6".repeat(64)},
        "volume": {"recipient_count": 2, "record_count": 1, "byte_count": 128}, "completeness": "known"
    })
}

fn facts(value: &Value) -> BusinessActionV1 {
    BusinessActionV1::from_bounded_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

#[test]
fn dimensions_intersect_and_thresholds_are_inclusive() {
    let mut value = fixtures()["base"].clone();
    let fixture = fixtures();
    let full = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "all-dimensions")
        .unwrap()["patch"]
        .clone();
    for (key, patch) in full.as_object().unwrap() {
        value[key] = patch.clone();
    }
    let action = facts(&facts_value());
    assert_eq!(selector(&value).unwrap().matches(&action), Ok(true));
    for (key, patch) in [
        ("operations", json!(["mail_read"])),
        ("accountBindings", json!(["0".repeat(64)])),
        ("audienceKinds", json!(["private"])),
        ("sensitivityLabels", json!(["secret"])),
        ("minRecipientCount", json!(3)),
        ("minRecordCount", json!(2)),
        ("minByteCount", json!(129)),
    ] {
        let mut changed = value.clone();
        changed[key] = patch;
        assert_eq!(
            selector(&changed).unwrap().matches(&action),
            Ok(false),
            "{key}"
        );
    }
    value["sensitivityLabels"] = json!(["secret", "confidential"]);
    value["accountBindings"] = json!(["0".repeat(64), "a".repeat(64)]);
    assert_eq!(selector(&value).unwrap().matches(&action), Ok(true));
    assert_eq!(
        selector(&fixtures()["base"]).unwrap().matches(&action),
        Ok(true)
    );
}

#[test]
fn uncertainty_is_an_error_even_before_a_nonmatching_service() {
    let mut value = fixtures()["base"].clone();
    value["services"] = json!(["google_drive"]);
    value["operations"] = json!(["drive_share"]);
    let matcher = selector(&value).unwrap();
    assert_eq!(matcher.matches(&facts(&facts_value())), Ok(false));
    for (object, field) in [
        ("provider", "identity_state"),
        ("audience", "expansion_state"),
        ("content", "inspection_state"),
    ] {
        let mut changed = facts_value();
        changed[object][field] = json!("unknown");
        assert_eq!(
            matcher.matches(&facts(&changed)),
            Err(BusinessPolicyMatchErrorV1::IncompleteFacts)
        );
    }
    let mut changed = facts_value();
    changed["content"]["sensitivity_labels"] = json!(["unknown"]);
    assert_eq!(
        matcher.matches(&facts(&changed)),
        Err(BusinessPolicyMatchErrorV1::IncompleteFacts)
    );
    let mut contradictory = facts(&facts_value());
    contradictory.volume.recipient_count = 0;
    assert_eq!(
        matcher.matches(&contradictory),
        Err(BusinessPolicyMatchErrorV1::InvalidFacts)
    );
}

#[test]
fn wire_and_direct_struct_bounds_cannot_be_bypassed() {
    let encoded = serde_json::to_string(&fixtures()["base"]).unwrap();
    let duplicate = encoded.replacen("\"version\":1", "\"version\":1,\"version\":1", 1);
    assert_eq!(
        BusinessPolicyMatchV1::from_bounded_json(duplicate.as_bytes()),
        Err(BusinessPolicyMatchErrorV1::Invalid)
    );
    assert_eq!(
        BusinessPolicyMatchV1::from_bounded_json(&vec![b' '; BUSINESS_POLICY_MATCH_MAX_BYTES + 1]),
        Err(BusinessPolicyMatchErrorV1::BoundsExceeded)
    );
    let mut direct = selector(&fixtures()["base"]).unwrap();
    direct.min_byte_count = Some(u64::MAX);
    assert_eq!(
        direct.matches(&facts(&facts_value())),
        Err(BusinessPolicyMatchErrorV1::BoundsExceeded)
    );
}
