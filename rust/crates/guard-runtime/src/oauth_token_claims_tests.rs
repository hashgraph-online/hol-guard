use serde_json::{json, Map, Value};

use super::{binding, binding_from_credentials, dispatch, refresh_binding};

fn claims(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

fn issued() -> Value {
    json!({
        "iss": "https://cloud.example.test/",
        "grant": {"grantId": "grant-1"},
        "machine": {"machineId": "machine-1", "deviceId": "device-from-machine"},
        "workspace": {"workspaceId": "workspace-1"},
    })
}

#[test]
fn the_binding_reads_nested_claims_and_ignores_a_trailing_issuer_slash() {
    let result = binding(&claims(issued()), Some("https://cloud.example.test"));
    assert_eq!(
        Value::Object(result),
        json!({
            "grant_id": "grant-1",
            "machine_id": "machine-1",
            "workspace_id": "workspace-1",
            "device_id": "device-from-machine",
        })
    );
}

#[test]
fn flat_claim_names_are_not_a_binding() {
    let flat = json!({"grant": "grant-1", "machine": "machine-1", "workspace": "workspace-1"});
    assert!(binding(&claims(flat), None).is_empty());
}

#[test]
fn a_token_from_another_issuer_or_missing_a_field_binds_nothing() {
    assert!(binding(&claims(issued()), Some("https://other.example.test")).is_empty());
    let mut partial = issued();
    partial["workspace"] = json!({"workspaceId": "   "});
    assert!(binding(&claims(partial), None).is_empty());
}

#[test]
fn the_top_level_device_claim_wins() {
    let mut token = issued();
    token["deviceId"] = json!(" device-top ");
    token["device"] = json!({"deviceId": "device-nested"});
    let result = binding(&claims(token), None);
    assert_eq!(result.get("device_id"), Some(&json!("device-top")));
}

#[test]
fn saved_fields_that_disagree_drop_the_recovered_binding() {
    let saved = claims(json!({"grant_id": "grant-other"}));
    assert!(binding_from_credentials(
        &claims(issued()),
        Some("https://cloud.example.test"),
        &saved
    )
    .is_empty());
    let agreeing = claims(json!({"grant_id": "grant-1"}));
    let recovered = binding_from_credentials(
        &claims(issued()),
        Some("https://cloud.example.test"),
        &agreeing,
    );
    assert_eq!(recovered.get("workspace_id"), Some(&json!("workspace-1")));
    assert!(binding_from_credentials(&claims(issued()), Some("  "), &agreeing).is_empty());
}

#[test]
fn refreshed_claims_replace_saved_fields_and_saved_fields_otherwise_stay() {
    let saved = claims(json!({"grant_id": " grant-saved ", "machine_id": ""}));
    let recovered = claims(json!({"grant_id": "grant-new", "machine_id": "machine-new"}));
    let kept = refresh_binding(&saved, &recovered, false);
    assert_eq!(kept.get("grant_id"), Some(&json!("grant-saved")));
    assert_eq!(kept.get("machine_id"), Some(&json!("machine-new")));
    let replaced = refresh_binding(&saved, &recovered, true);
    assert_eq!(replaced.get("grant_id"), Some(&json!("grant-new")));
}

#[test]
fn the_effective_binding_answers_all_four_fields() {
    let answer = dispatch(&json!({
        "op": "effective_binding",
        "claims": issued(),
        "issuer": "https://cloud.example.test",
        "credentials": {"grant_id": "grant-1"},
        "refreshed": false,
    }))
    .expect("answer");
    assert_eq!(
        answer,
        json!({"binding": {
            "device_id": "device-from-machine",
            "grant_id": "grant-1",
            "machine_id": "machine-1",
            "workspace_id": "workspace-1",
        }})
    );
    let without_claims = dispatch(&json!({
        "op": "effective_binding",
        "claims": null,
        "issuer": null,
        "credentials": {"grant_id": "grant-1"},
        "refreshed": true,
    }))
    .expect("answer");
    assert_eq!(without_claims["binding"]["grant_id"], Value::Null);
}

#[test]
fn identity_reports_each_claim_or_null() {
    let answer = dispatch(&json!({"op": "identity", "claims": issued()})).expect("answer");
    assert_eq!(answer["identity"]["machine_id"], json!("machine-1"));
    let empty = dispatch(&json!({"op": "identity", "claims": null})).expect("answer");
    assert_eq!(empty["identity"]["grant_id"], Value::Null);
}

fn expires(claims: Value, expires_in: Value) -> Value {
    dispatch(&json!({
        "op": "expires_at",
        "claims": claims,
        "expires_in": expires_in,
        "now": "2026-11-20T10:00:00.250000+00:00",
    }))
    .expect("answer")["expires_at"]
        .clone()
}

#[test]
fn the_token_exp_sets_the_expiry_before_expires_in() {
    assert_eq!(
        expires(json!({"exp": 1_795_000_000}), json!(60)),
        json!("2026-11-18T11:06:40+00:00")
    );
    assert_eq!(
        expires(json!({"exp": 1_795_000_000.5}), json!(60)),
        json!("2026-11-18T11:06:40.500000+00:00")
    );
}

#[test]
fn without_exp_the_expiry_is_now_plus_expires_in() {
    assert_eq!(
        expires(json!({}), json!(90)),
        json!("2026-11-20T10:01:30.250000+00:00")
    );
    assert_eq!(
        expires(json!({"exp": 0}), json!(" 1_0 ")),
        json!("2026-11-20T10:00:10.250000+00:00")
    );
    assert_eq!(
        expires(json!({"exp": true}), json!(30.9)),
        json!("2026-11-20T10:00:30.250000+00:00")
    );
}

#[test]
fn no_usable_lifetime_has_no_expiry() {
    for expires_in in [
        json!(0),
        json!(-5),
        json!("soon"),
        json!(true),
        json!(null),
        json!("1__0"),
    ] {
        assert_eq!(expires(json!({}), expires_in), Value::Null);
    }
}

#[test]
fn malformed_requests_are_refused() {
    assert!(dispatch(&json!({"op": "identity", "claims": "not-an-object"})).is_err());
    assert!(dispatch(&json!({"op": "binding", "claims": [], "issuer": null})).is_err());
    assert!(dispatch(&json!({"op": "identity", "claims": null, "token": "x"})).is_err());
}

#[test]
fn the_credential_binding_needs_an_issuer_and_agreeing_saved_fields() {
    let ask = |issuer: Value, credentials: Value| {
        dispatch(&json!({
            "op": "credential_binding",
            "claims": issued(),
            "issuer": issuer,
            "credentials": credentials,
        }))
        .expect("answer")["binding"]
            .clone()
    };
    assert_eq!(
        ask(
            json!("https://cloud.example.test"),
            json!({"machine_id": "machine-1"})
        )["grant_id"],
        json!("grant-1")
    );
    assert_eq!(ask(json!(null), json!({})), json!({}));
    assert_eq!(
        ask(
            json!("https://cloud.example.test"),
            json!({"machine_id": "machine-2"})
        ),
        json!({})
    );
}
