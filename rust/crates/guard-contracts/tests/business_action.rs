use guard_contracts::*;
use serde_json::{json, Value};

fn prepared_mail() -> Value {
    json!({
        "schema": BUSINESS_ACTION_V1_SCHEMA,
        "version": 1,
        "provider": {
            "service": "google_gmail",
            "account_binding": "a".repeat(64),
            "tenant_binding": "b".repeat(64),
            "identity_state": "known",
            "tool_identity_digest": "c".repeat(64),
            "tool_schema_digest": "d".repeat(64)
        },
        "operation": "mail_send",
        "audience": {
            "kind": "named",
            "expansion_state": "known",
            "recipients": [
                {"identity_binding": "e".repeat(64), "domain": "example.test", "kind": "to"},
                {"identity_binding": "f".repeat(64), "domain": "example.test", "kind": "bcc"}
            ]
        },
        "content": {
            "snapshot_digest": "1".repeat(64),
            "attachment_digests": ["2".repeat(64)],
            "inspection_state": "known",
            "inspected_bytes": 128,
            "sensitivity_labels": ["confidential"]
        },
        "target": {
            "resource_binding": "3".repeat(64),
            "revision_binding": "4".repeat(64),
            "field_diff_digest": "5".repeat(64),
            "batch_manifest_digest": "6".repeat(64)
        },
        "volume": {"recipient_count": 2, "record_count": 1, "byte_count": 128},
        "completeness": "known"
    })
}

fn decode(value: &Value) -> Result<BusinessActionV1, BusinessActionErrorV1> {
    BusinessActionV1::from_bounded_json(&serde_json::to_vec(value).unwrap())
}

fn object_mut<'a>(value: &'a mut Value, name: Option<&str>) -> &'a mut Value {
    match name {
        Some(name) => &mut value[name],
        None => value,
    }
}

#[test]
fn complete_facts_round_trip_preserves_hidden_audience_and_all_bindings() {
    let value = prepared_mail();
    let action = decode(&value).unwrap();
    action.require_complete_facts().unwrap();
    assert_eq!(serde_json::to_value(&action).unwrap(), value);
    assert_eq!(
        action.audience.recipients[1].kind,
        BusinessRecipientKindV1::Bcc
    );
    // Complete shape is deliberately not an allow decision or execution grant.
    let encoded = serde_json::to_value(&action).unwrap();
    assert!(encoded.get("decision").is_none());
    assert!(encoded.get("approval").is_none());
}

#[test]
fn complete_drive_and_calendar_facts_round_trip() {
    for (service, operation, recipient_kind) in [
        ("google_drive", "drive_share", "collaborator"),
        ("google_calendar", "calendar_invite", "calendar_attendee"),
    ] {
        let mut value = prepared_mail();
        value["provider"]["service"] = json!(service);
        value["operation"] = json!(operation);
        for recipient in value["audience"]["recipients"].as_array_mut().unwrap() {
            recipient["kind"] = json!(recipient_kind);
        }
        let action = decode(&value).unwrap();
        action.require_complete_facts().unwrap();
        assert_eq!(serde_json::to_value(action).unwrap(), value);
    }
    let mut public_share = prepared_mail();
    public_share["provider"]["service"] = json!("google_drive");
    public_share["operation"] = json!("drive_share");
    public_share["audience"]["kind"] = json!("public");
    public_share["audience"]["recipients"] = json!([]);
    public_share["volume"]["recipient_count"] = json!(0);
    decode(&public_share)
        .unwrap()
        .require_complete_facts()
        .unwrap();
}

#[test]
fn every_object_rejects_unknown_and_missing_fields() {
    for object in [
        None,
        Some("provider"),
        Some("audience"),
        Some("content"),
        Some("target"),
        Some("volume"),
    ] {
        let value = prepared_mail();
        let keys: Vec<_> = object
            .map_or(&value, |name| &value[name])
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for key in keys {
            let mut changed = value.clone();
            object_mut(&mut changed, object)
                .as_object_mut()
                .unwrap()
                .remove(&key);
            assert!(decode(&changed).is_err(), "missing {object:?}.{key}");
        }
        let mut changed = value;
        object_mut(&mut changed, object)["future_send_override"] = json!(true);
        assert_eq!(decode(&changed), Err(BusinessActionErrorV1::Invalid));
    }
    let mut changed = prepared_mail();
    changed["audience"]["recipients"][0]["unlisted_recipient"] = json!("hidden@example.test");
    assert_eq!(decode(&changed), Err(BusinessActionErrorV1::Invalid));
}

#[test]
fn duplicate_keys_are_rejected_before_they_can_hide_an_action() {
    let encoded = serde_json::to_string(&prepared_mail()).unwrap();
    for (key, extra) in [
        ("operation", "\"mail_read\""),
        ("recipient_count", "0"),
        ("account_binding", "null"),
    ] {
        let duplicate = encoded.replacen(
            &format!("\"{key}\":"),
            &format!("\"{key}\":{extra},\"{key}\":"),
            1,
        );
        assert_eq!(
            BusinessActionV1::from_bounded_json(duplicate.as_bytes()),
            Err(BusinessActionErrorV1::Invalid)
        );
    }
}

#[test]
fn unsupported_version_and_operations_do_not_downgrade_to_legacy() {
    let mut value = prepared_mail();
    value["version"] = json!(2);
    assert_eq!(
        decode(&value),
        Err(BusinessActionErrorV1::UnsupportedVersion)
    );
    value["version"] = json!(1);
    value["schema"] = json!("guard.business-action.v2");
    assert_eq!(
        decode(&value),
        Err(BusinessActionErrorV1::UnsupportedVersion)
    );
    value["schema"] = json!(BUSINESS_ACTION_V1_SCHEMA);
    value["operation"] = json!("generic_api_call");
    assert_eq!(decode(&value), Err(BusinessActionErrorV1::Invalid));
}

#[test]
fn unknown_identity_expansion_or_inspection_never_meets_complete_fact_admission() {
    for (object, field) in [
        ("provider", "identity_state"),
        ("audience", "expansion_state"),
        ("content", "inspection_state"),
    ] {
        for state in ["unknown", "unsupported"] {
            let mut value = prepared_mail();
            value[object][field] = json!(state);
            let action = decode(&value).unwrap();
            assert_eq!(
                action.require_complete_facts(),
                Err(BusinessActionErrorV1::Incomplete)
            );
        }
    }
    let mut value = prepared_mail();
    value["provider"]["account_binding"] = Value::Null;
    assert_eq!(decode(&value), Err(BusinessActionErrorV1::Inconsistent));
    value["provider"]["identity_state"] = json!("unknown");
    assert_eq!(
        decode(&value).unwrap().require_complete_facts(),
        Err(BusinessActionErrorV1::Incomplete)
    );
}

#[test]
fn service_count_audience_and_inspection_contradictions_are_rejected() {
    for (object, field, replacement) in [
        ("provider", "service", json!("google_drive")),
        ("volume", "recipient_count", json!(1)),
        ("audience", "kind", json!("private")),
        ("content", "inspected_bytes", json!(127)),
        ("content", "inspected_bytes", json!(129)),
    ] {
        let mut value = prepared_mail();
        value[object][field] = replacement;
        assert_eq!(decode(&value), Err(BusinessActionErrorV1::Inconsistent));
    }
    let mut value = prepared_mail();
    value["audience"]["recipients"][1] = value["audience"]["recipients"][0].clone();
    assert_eq!(decode(&value), Err(BusinessActionErrorV1::Inconsistent));
}

#[test]
fn same_identity_in_two_fields_is_preserved_but_counted_once() {
    let mut value = prepared_mail();
    value["audience"]["recipients"][1]["identity_binding"] = json!("e".repeat(64));
    value["volume"]["recipient_count"] = json!(1);
    let action = decode(&value).unwrap();
    assert_eq!(action.audience.recipients.len(), 2);
    assert_eq!(action.volume.recipient_count, 1);
}

#[test]
fn recipient_kind_domain_and_public_audience_cannot_contradict_service() {
    let mut value = prepared_mail();
    value["audience"]["recipients"][0]["kind"] = json!("calendar_attendee");
    assert_eq!(decode(&value), Err(BusinessActionErrorV1::Inconsistent));
    value = prepared_mail();
    value["audience"]["kind"] = json!("public");
    assert_eq!(decode(&value), Err(BusinessActionErrorV1::Inconsistent));
    value = prepared_mail();
    value["audience"]["recipients"][1]["identity_binding"] = json!("e".repeat(64));
    value["audience"]["recipients"][1]["domain"] = json!("other.test");
    value["volume"]["recipient_count"] = json!(1);
    assert_eq!(decode(&value), Err(BusinessActionErrorV1::Inconsistent));
}

#[test]
fn excessive_collection_and_deep_unknown_data_never_decode_as_complete() {
    let mut value = prepared_mail();
    value["content"]["attachment_digests"] =
        json!(vec!["2".repeat(64); MAX_BUSINESS_ACTION_ITEMS + 1]);
    assert_eq!(decode(&value), Err(BusinessActionErrorV1::LimitExceeded));
    let encoded = serde_json::to_string(&prepared_mail()).unwrap();
    let nested = format!("{}0{}", "[".repeat(17), "]".repeat(17));
    let unknown = encoded.replacen('{', &format!("{{\"opaque_send\":{nested},"), 1);
    assert_eq!(
        BusinessActionV1::from_bounded_json(unknown.as_bytes()),
        Err(BusinessActionErrorV1::Invalid)
    );
}

#[test]
fn oversized_inputs_and_unsafe_wire_counts_stop_without_truncation() {
    assert_eq!(
        BusinessActionV1::from_bounded_json(&vec![b' '; MAX_BUSINESS_ACTION_BYTES + 1]),
        Err(BusinessActionErrorV1::LimitExceeded)
    );
    let mut value = prepared_mail();
    value["volume"]["record_count"] = json!(MAX_BUSINESS_WIRE_COUNT + 1);
    assert_eq!(decode(&value), Err(BusinessActionErrorV1::LimitExceeded));
    value["volume"]["record_count"] = json!(1);
    value["volume"]["byte_count"] = json!(MAX_BUSINESS_INLINE_BYTES + 1);
    value["content"]["inspected_bytes"] = value["volume"]["byte_count"].clone();
    assert_eq!(decode(&value), Err(BusinessActionErrorV1::Inconsistent));
    value["content"]["inspection_state"] = json!("unsupported");
    assert_eq!(
        decode(&value).unwrap().require_complete_facts(),
        Err(BusinessActionErrorV1::Incomplete)
    );
}

#[test]
fn identity_and_domain_errors_never_become_known_facts() {
    for invalid in ["", "A".repeat(64).as_str(), "not-a-digest"] {
        let mut value = prepared_mail();
        value["provider"]["tool_identity_digest"] = json!(invalid);
        assert_eq!(decode(&value), Err(BusinessActionErrorV1::Invalid));
    }
    for invalid in [
        "Example.test",
        "example.test\nBcc:hidden.test",
        "-example.test",
        "example..test",
        "example.test.",
        "例.test",
    ] {
        let mut value = prepared_mail();
        value["audience"]["recipients"][0]["domain"] = json!(invalid);
        assert_eq!(decode(&value), Err(BusinessActionErrorV1::Invalid));
    }
}

#[test]
fn missing_duplicate_or_unknown_sensitivity_does_not_admit_complete_facts() {
    let mut value = prepared_mail();
    value["content"]["sensitivity_labels"] = json!([]);
    assert_eq!(decode(&value), Err(BusinessActionErrorV1::Inconsistent));
    value["content"]["sensitivity_labels"] = json!(["secret", "secret"]);
    assert_eq!(decode(&value), Err(BusinessActionErrorV1::Inconsistent));
    value["content"]["sensitivity_labels"] = json!(["unknown"]);
    assert_eq!(
        decode(&value).unwrap().require_complete_facts(),
        Err(BusinessActionErrorV1::Incomplete)
    );
    value["content"]["sensitivity_labels"] = json!(["public", "secret"]);
    decode(&value).unwrap().require_complete_facts().unwrap();
}

#[test]
fn unknown_accounts_require_explicit_nullable_bindings() {
    for state in ["unknown", "unsupported"] {
        let mut value = prepared_mail();
        value["provider"]["identity_state"] = json!(state);
        value["provider"]["account_binding"] = Value::Null;
        value["provider"]["tenant_binding"] = Value::Null;
        assert_eq!(
            decode(&value).unwrap().require_complete_facts(),
            Err(BusinessActionErrorV1::Incomplete)
        );
        for field in ["account_binding", "tenant_binding"] {
            let mut omitted = value.clone();
            omitted["provider"].as_object_mut().unwrap().remove(field);
            assert_eq!(decode(&omitted), Err(BusinessActionErrorV1::Invalid));
        }
    }
}
