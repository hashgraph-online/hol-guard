//! A v1 selector and its lifted v2 alternatives agree on every lifted fact.

use std::collections::BTreeMap;

use guard_contracts::{ActionFactsV2, BusinessActionV1, FactSubjectV2, Match3};
use guard_policy_snapshot::business_match::*;
use serde_json::{json, Value};

fn fixtures() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/business-policy/selector-v1-fixtures.json"
    ))
    .unwrap()
}

fn base_facts() -> Value {
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

/// Complete v1 facts across services, operations, audiences and volumes.
fn fact_variants() -> Vec<BusinessActionV1> {
    let mut variants = Vec::new();
    let collaborator = |kind: &str| {
        json!([{"identity_binding": "e".repeat(64), "domain": "example.test", "kind": kind},
               {"identity_binding": "f".repeat(64), "domain": "other.test", "kind": kind}])
    };
    let operations = [
        (
            "google_gmail",
            "to",
            [
                "mail_read",
                "mail_draft",
                "mail_send",
                "mail_label",
                "mail_permanent_delete",
                "mail_settings",
            ]
            .as_slice(),
        ),
        (
            "google_drive",
            "collaborator",
            ["drive_read", "drive_edit", "drive_share", "drive_export"].as_slice(),
        ),
        (
            "google_calendar",
            "calendar_attendee",
            ["calendar_read", "calendar_invite"].as_slice(),
        ),
    ];
    for (service, kind, ops) in operations {
        for op in ops {
            for audience in ["named", "private", "public"] {
                for labels in [
                    json!(["confidential"]),
                    json!(["personal", "secret"]),
                    json!(["public"]),
                ] {
                    for (records, bytes) in [(1, 128), (40, 9000)] {
                        let mut value = base_facts();
                        value["provider"]["service"] = json!(service);
                        value["operation"] = json!(op);
                        value["audience"]["kind"] = json!(audience);
                        value["audience"]["recipients"] = if audience == "private" {
                            json!([])
                        } else {
                            collaborator(kind)
                        };
                        value["volume"]["recipient_count"] =
                            json!(if audience == "private" { 0 } else { 2 });
                        value["volume"]["record_count"] = json!(records);
                        value["volume"]["byte_count"] = json!(bytes);
                        value["content"]["inspected_bytes"] = json!(bytes.min(128));
                        value["content"]["inspection_state"] = json!("unknown");
                        value["content"]["sensitivity_labels"] = labels.clone();
                        if let Ok(facts) = BusinessActionV1::from_bounded_json(
                            &serde_json::to_vec(&value).unwrap(),
                        ) {
                            let mut complete = facts.clone();
                            complete.content.inspection_state =
                                guard_contracts::BusinessFactStateV1::Known;
                            complete.content.inspected_bytes = complete.volume.byte_count;
                            if complete.require_complete_facts().is_ok() {
                                variants.push(complete);
                            }
                        }
                    }
                }
            }
        }
    }
    variants
}

fn selectors() -> Vec<BusinessPolicyMatchV1> {
    let fixtures = fixtures();
    let mut out = Vec::new();
    let mut push = |value: Value| {
        if let Ok(selector) =
            BusinessPolicyMatchV1::from_bounded_json(&serde_json::to_vec(&value).unwrap())
        {
            out.push(selector);
        }
    };
    for case in fixtures["cases"].as_array().unwrap() {
        let mut value = fixtures["base"].clone();
        for (key, patch) in case["patch"].as_object().unwrap() {
            value[key] = patch.clone();
        }
        value.as_object_mut().unwrap().remove("accountBindings");
        push(value);
    }
    let all = json!({"schema": "guard.business-policy-match.v1", "version": 1,
        "services": ["google_gmail", "google_drive", "google_calendar"],
        "operations": ["mail_read", "drive_share", "calendar_invite", "mail_permanent_delete"]});
    for (key, patch) in [
        ("recipientDomains", json!(["example.test"])),
        ("recipientDomains", json!(["example.test", "other.test"])),
        ("audienceKinds", json!(["public", "private"])),
        ("audienceKinds", json!(["private"])),
        ("sensitivityLabels", json!(["secret"])),
        ("minRecordCount", json!(2)),
        ("minByteCount", json!(1000)),
        ("minRecipientCount", json!(2)),
    ] {
        let mut value = all.clone();
        value[key] = patch;
        push(value.clone());
        value["audienceKinds"] = json!(["named"]);
        push(value);
    }
    push(all);
    out
}

#[test]
fn lifted_selectors_agree_with_v1_on_every_complete_fact() {
    let variants = fact_variants();
    let selectors = selectors();
    assert!(variants.len() >= 60, "{}", variants.len());
    assert!(selectors.len() >= 15, "{}", selectors.len());
    let windows = BTreeMap::new();
    let mut compared = 0;
    for selector in &selectors {
        let lifted = selector.lift_to_fact_selectors_v2().unwrap();
        for v2 in &lifted {
            v2.validate().unwrap();
        }
        for facts in &variants {
            let expected = selector.matches(facts).unwrap();
            let lifted_facts = ActionFactsV2::from_business_action_v1(facts);
            lifted_facts.validate().unwrap();
            let subject = FactSubjectV2 {
                provider: business_service_token(facts.provider.service),
                facts: &lifted_facts,
                session: None,
                windows: &windows,
            };
            let answers: Vec<Match3> = lifted.iter().map(|s| s.matches(&subject)).collect();
            assert!(
                !answers.contains(&Match3::Unknown),
                "{selector:?} {facts:?}"
            );
            assert_eq!(
                answers.contains(&Match3::Yes),
                expected,
                "{selector:?} {facts:?}"
            );
            compared += 1;
        }
    }
    assert!(compared > 1000, "{compared}");
}

#[test]
fn account_bound_selectors_stay_on_v1() {
    let mut value = fixtures()["base"].clone();
    value["accountBindings"] = json!(["a".repeat(64)]);
    let selector =
        BusinessPolicyMatchV1::from_bounded_json(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        selector.lift_to_fact_selectors_v2(),
        Err(BusinessSelectorLiftErrorV1::AccountBindingsUnsupported)
    );
}
