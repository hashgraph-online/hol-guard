//! Every `BrowserActionV2` field is classified as shareable with a provider or never shareable
//! (BP-T101, PRD 6.4). Adding a field to the action without classifying it fails here.

use std::collections::BTreeSet;

use guard_contracts::*;
use serde_json::{json, Value};

/// A browser action with every optional part present, so every field is serialized.
fn full_action() -> BrowserActionV2 {
    serde_json::from_value(json!({
        "version": 2,
        "driver": {
            "id": "driver.example-browser",
            "kind": "mcp",
            "identity_hash": "a".repeat(64),
            "trust_class": "first-party"
        },
        "session": {
            "harness": "example-harness",
            "session_ref_digest": "b".repeat(64),
            "profile_mode": "isolated"
        },
        "intent": "browser.interact",
        "operation": "browser_type",
        "verb": "type",
        "target": {
            "origin": "https://shop.example.test",
            "site_group": "example.test",
            "path_prefix": "/checkout",
            "is_loopback": false,
            "is_guard_origin": false,
            "url_redacted": "https://shop.example.test/checkout?step=[redacted]"
        },
        "element": {
            "role": "textbox",
            "name_digest": "c".repeat(64),
            "name_preview": "Card number",
            "is_password": false,
            "is_payment": true,
            "is_file_input": false
        },
        "input": {
            "kind": "text",
            "length": 16,
            "digest": "d".repeat(64),
            "preview_class": "looks_like_payment"
        },
        "sensitive_surface_flags": ["password_field"],
        "cdp": {"domain": "Input", "method": "dispatchKeyEvent", "classified": true},
        "volatile_fields_dropped": ["ref"]
    }))
    .expect("the full action matches BrowserActionV2")
}

/// The JSON pointer of every field. Objects are walked; a list or a scalar is one field.
fn field_pointers(value: &Value, prefix: &str, out: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            for (key, field) in fields {
                field_pointers(field, &format!("{prefix}/{key}"), out);
            }
        }
        _ => {
            out.insert(prefix.to_owned());
        }
    }
}

#[test]
fn every_browser_action_field_is_classified_for_sharing() {
    let mut fields = BTreeSet::new();
    field_pointers(
        &serde_json::to_value(full_action()).unwrap(),
        "",
        &mut fields,
    );
    let classified: BTreeSet<String> = BROWSER_ACTION_FIELD_SHARING
        .iter()
        .map(|(field, _)| (*field).to_owned())
        .collect();
    assert_eq!(
        classified.len(),
        BROWSER_ACTION_FIELD_SHARING.len(),
        "a field is classified twice"
    );
    let unclassified: Vec<_> = fields.difference(&classified).collect();
    assert!(
        unclassified.is_empty(),
        "classify each new BrowserActionV2 field in BROWSER_ACTION_FIELD_SHARING: {unclassified:?}"
    );
    let stale: Vec<_> = classified.difference(&fields).collect();
    assert!(stale.is_empty(), "no such BrowserActionV2 field: {stale:?}");
}

#[test]
fn only_the_declared_target_and_action_facts_come_from_the_action() {
    let shared: BTreeSet<_> = BROWSER_ACTION_FIELD_SHARING
        .iter()
        .filter_map(|(field, fact)| fact.map(|fact| (*field, fact)))
        .collect();
    assert_eq!(
        shared,
        BTreeSet::from([
            ("/intent", ProviderShareableFactV1::ActionIntent),
            ("/verb", ProviderShareableFactV1::ActionVerb),
            ("/target/origin", ProviderShareableFactV1::TargetOrigin),
            (
                "/target/site_group",
                ProviderShareableFactV1::TargetSiteGroup
            ),
            (
                "/target/path_prefix",
                ProviderShareableFactV1::TargetPathPrefix
            ),
        ])
    );
    // Each shared field's fact name is the field it reads, so a rename is visible in review.
    for (field, fact) in shared {
        let name = serde_json::to_value(fact).unwrap();
        let name = name.as_str().unwrap();
        let leaf = field.rsplit('/').next().unwrap();
        assert!(name.ends_with(leaf), "{field} shared as {name}");
    }
}

#[test]
fn identifying_and_content_fields_never_leave_the_device() {
    for field in [
        "/target/url_redacted",
        "/target/is_loopback",
        "/element/name_preview",
        "/element/name_digest",
        "/input/digest",
        "/input/length",
        "/session/harness",
        "/session/session_ref_digest",
        "/driver/identity_hash",
        "/operation",
        "/cdp/method",
        "/volatile_fields_dropped",
    ] {
        assert!(
            BROWSER_ACTION_FIELD_SHARING
                .iter()
                .any(|(known, _)| *known == field),
            "{field} is not a field"
        );
        assert_eq!(browser_action_field_fact(field), None, "{field}");
    }
    assert_eq!(browser_action_field_fact("/target/query"), None);
}

#[test]
fn the_fact_list_is_closed_and_complete() {
    let names: Vec<_> = ProviderShareableFactV1::ALL
        .iter()
        .map(|fact| serde_json::to_value(fact).unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "target.origin",
            "target.site_group",
            "target.path_prefix",
            "action.verb",
            "action.intent",
            "page.script_hashes",
            "download.sha256",
            "guard.version",
        ]
    );
    assert!(serde_json::from_value::<ProviderShareableFactV1>(json!("page.text")).is_err());
    let opt_in: Vec<_> = ProviderShareableFactV1::ALL
        .into_iter()
        .filter(|fact| fact.opt_in_only())
        .collect();
    assert_eq!(opt_in, [ProviderShareableFactV1::TargetPathPrefix]);
}
