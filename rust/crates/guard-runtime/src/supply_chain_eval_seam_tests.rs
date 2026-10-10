//! Bounds on the two caller-supplied fields of `supply-chain-eval-v1` that are
//! not part of the artifact: the test-only Cloud seams and the saved-policy
//! probe. Both are validated before the resident acts on them.

use super::*;
use guard_contracts::{SavedPolicyProbeV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA};
use serde_json::json;

fn request() -> SupplyChainEvalRequestV1 {
    SupplyChainEvalRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "seam-test".to_owned(),
        store_path: String::new(),
        guard_home: String::new(),
        artifact: Value::Null,
        workspace_dir: None,
        now: None,
        external_archive_network_authorized: false,
        retain_external_archive_blob: false,
        runtime_private_metadata: None,
        sync_auth_context_override: None,
        package_entitlement_override: None,
        registry_metadata_override: None,
        saved_policy_probe: None,
    }
}

#[test]
fn absent_seams_are_valid() {
    assert!(test_seam_overrides_are_valid(&request()));
}

#[test]
fn known_bounded_seams_are_valid() {
    let mut request = request();
    request.sync_auth_context_override = Some(json!({
        "sync_url": "http://127.0.0.1:1/api",
        "access_token": "t",
        "dpop_key_material": null,
    }));
    request.package_entitlement_override = Some(json!({"allowed": false, "reason": "x"}));
    assert!(test_seam_overrides_are_valid(&request));
}

#[test]
fn unknown_wrongly_typed_or_oversized_seams_are_refused() {
    let refused = |auth: Option<Value>, entitlement: Option<Value>| {
        let mut request = request();
        request.sync_auth_context_override = auth;
        request.package_entitlement_override = entitlement;
        !test_seam_overrides_are_valid(&request)
    };
    assert!(refused(Some(json!({"unexpected": "x"})), None));
    assert!(refused(Some(json!({"access_token": 7})), None));
    assert!(refused(Some(json!(["not", "an", "object"])), None));
    assert!(refused(None, Some(json!("not an object"))));
    let oversized = "x".repeat(TEST_SEAM_MAX_BYTES + 1);
    assert!(refused(
        Some(json!({"access_token": oversized.clone()})),
        None
    ));
    assert!(refused(None, Some(json!({"reason": oversized}))));
}

#[test]
fn diagnostics_alone_never_enable_the_test_seams() {
    let only = |wanted: &'static str| {
        move |name: &str| (name == wanted).then(|| std::ffi::OsString::from("1"))
    };
    assert!(!test_seams_enabled_from(only(
        "HOL_GUARD_NATIVE_DIAGNOSTIC"
    )));
    assert!(!test_seams_enabled_from(|_| None));
    assert!(test_seams_enabled_from(only(
        "HOL_GUARD_RESIDENT_TEST_SEAMS"
    )));
}

#[test]
fn entitlement_override_requires_known_keys_and_types() {
    let valid = |entitlement: Value| {
        let mut request = request();
        request.package_entitlement_override = Some(entitlement);
        test_seam_overrides_are_valid(&request)
    };
    assert!(valid(json!({
        "allowed": false,
        "reason": "paid_guard_cloud_required",
        "tier": "free",
        "upgrade_cta": null,
    })));
    assert!(valid(json!({"upgrade_cta": "https://hol.org/upgrade"})));
    assert!(!valid(json!({"allowed": "no"})));
    assert!(!valid(json!({"reason": 7})));
    assert!(!valid(json!({"tier": null})));
    assert!(!valid(json!({"upgrade_cta": 1})));
    assert!(!valid(json!({"unexpected": true})));
}

#[test]
fn registry_override_requires_registry_urls_and_object_or_null_values() {
    let valid = |fixtures: Value| {
        let mut request = request();
        request.registry_metadata_override = Some(fixtures);
        test_seam_overrides_are_valid(&request)
    };
    assert!(valid(json!({
        "https://registry.npmjs.org/left-pad": {"versions": {"1.0.0": {}}},
        "https://pypi.org/pypi/requests/json": null,
    })));
    assert!(!valid(json!({"https://evil.example/left-pad": {}})));
    assert!(!valid(
        json!({"https://registry.npmjs.org/left-pad": "1.0.0"})
    ));
    assert!(!valid(json!(["https://registry.npmjs.org/left-pad"])));
    let oversized = "x".repeat(TEST_SEAM_MAX_BYTES + 1);
    assert!(!valid(
        json!({"https://registry.npmjs.org/p": {"v": oversized}})
    ));
}

fn probe_of(decision: Option<Value>) -> Option<SavedPolicyProbe> {
    let mut request = request();
    request.saved_policy_probe = Some(SavedPolicyProbeV1 { decision });
    saved_policy_probe(&request)
}

#[test]
fn absent_probe_asks_the_caller_for_a_lookup() {
    assert!(matches!(
        saved_policy_probe(&request()),
        Some(SavedPolicyProbe::Required)
    ));
}

#[test]
fn supplied_probe_carries_the_lookup_row_or_none() {
    assert!(matches!(
        probe_of(None),
        Some(SavedPolicyProbe::Supplied(None))
    ));
    assert!(matches!(
        probe_of(Some(Value::Null)),
        Some(SavedPolicyProbe::Supplied(None))
    ));
    let row = json!({"action": "block", "scope": "global", "source": "manual"});
    match probe_of(Some(row.clone())) {
        Some(SavedPolicyProbe::Supplied(Some(decision))) => assert_eq!(decision, row),
        _ => panic!("object row must be carried through"),
    }
}

#[test]
fn malformed_or_oversized_probe_is_refused_not_treated_as_no_policy() {
    assert!(probe_of(Some(json!("block"))).is_none());
    assert!(probe_of(Some(json!([1, 2]))).is_none());
    let oversized = json!({"reason": "x".repeat(SAVED_POLICY_MAX_BYTES + 1)});
    assert!(probe_of(Some(oversized)).is_none());
}
