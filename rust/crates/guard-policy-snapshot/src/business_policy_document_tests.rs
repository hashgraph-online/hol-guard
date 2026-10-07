use super::*;
use serde_json::json;

fn document() -> Value {
    json!({
        "apiVersion": "guard.hashgraphonline.com/v1alpha1", "kind": "GuardPolicy",
        "metadata": {"id": "policy.business", "name": "Business", "revision": 1},
        "spec": {"defaults": {"mode": "enforce", "defaultAction": "block"},
        "rules": [{"id": "rule.send", "enabled": true, "effect": "review",
            "match": {"business": {"schema": "guard.business-policy-match.v1",
                "version": 1, "services": ["google_gmail"], "operations": ["mail_send"]}},
            "lifetime": {"mode": "permanent", "expiresAt": null},
            "provenance": {"source": "local", "createdAt": "2026-07-15T12:00:00Z"}}]}
    })
}

#[test]
fn complete_source_is_retained_and_bound() {
    let source = document();
    let compiled = compile_business_document(&source).unwrap();
    assert_eq!(
        compiled.binding().source_document_digest.as_deref(),
        Some(compiled.source_digest())
    );
    assert_eq!(compiled.binding().rules[0].action, "review");
    assert_eq!(
        serde_json::from_slice::<Value>(compiled.canonical_source()).unwrap(),
        source
    );
    for (pointer, value) in [
        ("/metadata/revision", json!(2)),
        ("/spec/rules/0/provenance/source", json!("cloud")),
        ("/spec/rules/0/description", json!("Updated rule")),
    ] {
        let mut changed = source.clone();
        if pointer.ends_with("description") {
            changed["spec"]["rules"][0]["description"] = value;
        } else {
            *changed.pointer_mut(pointer).unwrap() = value;
        }
        let updated = compile_business_document(&changed).unwrap();
        assert_ne!(updated.source_digest(), compiled.source_digest());
        assert_ne!(
            updated.binding().source_document_digest,
            compiled.binding().source_document_digest
        );
    }
}

#[test]
fn co_selectors_are_refused_instead_of_widened() {
    for field in [
        "actors",
        "workspaces",
        "harnesses",
        "tools",
        "operations",
        "origins",
    ] {
        let mut source = document();
        source["spec"]["rules"][0]["match"][field] = json!(["restricted"]);
        assert_eq!(
            compile_business_document(&source).unwrap_err(),
            BusinessDocumentError::UnsupportedRule
        );
    }
}

#[test]
fn scoped_lifetimes_and_unrepresented_defaults_refuse() {
    for mode in ["once", "session", "project", "machine", "workspace", "team"] {
        let mut source = document();
        source["spec"]["rules"][0]["lifetime"] = json!({"mode": mode});
        assert_eq!(
            compile_business_document(&source).unwrap_err(),
            BusinessDocumentError::UnsupportedLifetime
        );
    }
    for mode in ["observe", "prompt"] {
        let mut source = document();
        source["spec"]["defaults"]["mode"] = json!(mode);
        assert_eq!(
            compile_business_document(&source).unwrap_err(),
            BusinessDocumentError::UnsupportedDefaults
        );
    }
    let mut source = document();
    source["spec"]["defaults"]["unknownPublisherAction"] = json!("block");
    assert_eq!(
        compile_business_document(&source).unwrap_err(),
        BusinessDocumentError::UnsupportedDefaults
    );
}

#[test]
fn until_preserves_exact_expiry_and_complete_source_identity() {
    let mut source = document();
    let permanent = compile_business_document(&source).unwrap();
    source["spec"]["rules"][0]["lifetime"] =
        json!({"mode": "until", "expiresAt": "2026-07-16T12:00:00.123456789Z"});
    let compiled = compile_business_document(&source).unwrap();
    assert_eq!(
        compiled.binding().rules[0].expires_at.as_deref(),
        Some("2026-07-16T12:00:00.123456789Z")
    );
    assert_ne!(compiled.source_digest(), permanent.source_digest());
    assert_eq!(
        serde_json::from_slice::<Value>(compiled.canonical_source()).unwrap(),
        source
    );
    for expiry in [
        "2026-02-29T12:00:00Z",
        "2026-04-31T12:00:00Z",
        "0000-01-01T00:00:00Z",
    ] {
        source["spec"]["rules"][0]["lifetime"]["expiresAt"] = json!(expiry);
        assert_eq!(
            compile_business_document(&source).unwrap_err(),
            BusinessDocumentError::InvalidDocument
        );
    }
}

#[test]
fn malformed_inactive_rules_cannot_hide() {
    for enabled in [true, false] {
        let mut source = document();
        source["spec"]["rules"][0]["enabled"] = json!(enabled);
        source["spec"]["rules"][0]["match"]["business"]["accountBindings"] =
            json!(["a".repeat(64) + "\n"]);
        assert_eq!(
            compile_business_document(&source).unwrap_err(),
            BusinessDocumentError::InvalidDocument
        );
    }
    let mut source = document();
    let duplicate = source["spec"]["rules"][0].clone();
    source["spec"]["rules"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert_eq!(
        compile_business_document(&source).unwrap_err(),
        BusinessDocumentError::DuplicateRule
    );
    source["metadata"]["x-future"] = json!(true);
    assert_eq!(
        compile_business_document(&source).unwrap_err(),
        BusinessDocumentError::UnsupportedExtension
    );
}

#[test]
fn real_calendar_dates_and_input_bounds_are_checked() {
    for timestamp in [
        "2026-02-30T12:00:00Z",
        "0000-01-01T00:00:00Z",
        "2025-02-29T00:00:00Z",
    ] {
        let mut source = document();
        source["spec"]["rules"][0]["provenance"]["createdAt"] = json!(timestamp);
        assert_eq!(
            compile_business_document(&source).unwrap_err(),
            BusinessDocumentError::InvalidDocument
        );
    }
    let mut source = document();
    source["spec"]["rules"][0]["provenance"]["createdAt"] = json!("2024-02-29T00:00:00Z");
    source["metadata"]["labels"] = json!({"x-team": "operations"});
    assert!(compile_business_document(&source).is_ok());
    source["spec"]["rules"][0]["description"] = json!("a".repeat(4097));
    assert_eq!(
        compile_business_document(&source).unwrap_err(),
        BusinessDocumentError::Bounds
    );
}

#[test]
fn inactive_only_documents_do_not_create_a_default_business_floor() {
    let mut source = document();
    source["spec"]["rules"][0]["enabled"] = json!(false);
    assert_eq!(
        compile_business_document(&source).unwrap_err(),
        BusinessDocumentError::UnsupportedRule
    );
}

#[test]
fn binding_capacity_overflow_is_distinct_from_malformed_source() {
    for count in [256, 257] {
        let mut source = document();
        let template = source["spec"]["rules"][0].clone();
        source["spec"]["rules"] = Value::Array(
            (0..count)
                .map(|index| {
                    let mut rule = template.clone();
                    rule["id"] = json!(format!("rule.{index}"));
                    rule
                })
                .collect(),
        );
        let result = compile_business_document(&source);
        if count == 256 {
            assert_eq!(result.unwrap().binding().rules.len(), 256);
        } else {
            assert_eq!(result.unwrap_err(), BusinessDocumentError::Bounds);
        }
    }
}

#[test]
fn whole_document_compilation_agrees_with_shared_business_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../contracts/business-policy/selector-v1-fixtures.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let mut business = vectors["base"].clone();
        for (key, value) in case["patch"].as_object().unwrap() {
            business[key] = value.clone();
        }
        if let Some(remove) = case["remove"].as_array() {
            for key in remove {
                business
                    .as_object_mut()
                    .unwrap()
                    .remove(key.as_str().unwrap());
            }
        }
        let mut source = document();
        source["spec"]["rules"][0]["match"]["business"] = business;
        assert_eq!(
            compile_business_document(&source).is_ok(),
            case["valid"].as_bool().unwrap(),
            "vector {}",
            case["id"]
        );
    }
}
