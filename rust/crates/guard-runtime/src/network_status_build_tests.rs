use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn profile(platform: &str, backend_id: &str, maximum_grade: &str, production_ready: bool) -> Value {
    json!({
        "backend_id": backend_id,
        "platform": platform,
        "maximum_grade": maximum_grade,
        "production_ready": production_ready,
        "requires_privilege": true,
        "reason_code": "alpha-not-validated",
    })
}

fn health(backend_id: Value, grade: &str, permits: bool) -> Value {
    json!({
        "phase": "healthy",
        "backend_id": backend_id,
        "backend_digest": "sha256:abc",
        "effective_grade": grade,
        "healthy_until_epoch_ms": 10,
        "retry_attempt": 0,
        "next_retry_seconds": null,
        "permits_enforcement": permits,
        "independently_observed": false,
    })
}

fn build(
    platform: &str,
    profiles: Value,
    explicit: bool,
    host_only: bool,
    supervisor: Value,
) -> Value {
    dispatch(&json!({
        "platform": platform,
        "profiles": profiles,
        "explicit": explicit,
        "host_only": host_only,
        "supervisor": supervisor,
        "legacy_domain_policy": null,
    }))
    .expect("status answer")
}

fn defaults() -> Value {
    json!([
        profile("linux", "linux.oci-proxy", "proxy-only", false),
        profile("macos", "macos.observe", "observe", false),
    ])
}

#[test]
fn a_static_profile_is_never_protection() {
    let status = build("darwin", defaults(), false, true, Value::Null);
    assert_eq!(status["schema"], "guard.network-status.v1");
    assert_eq!(status["host_platform"], "macos");
    assert_eq!(status["protection_active"], false);
    assert_eq!(status["effective_grade"], "unavailable");
    assert_eq!(status["reason_code"], "no-verified-installed-backend");
    let backends = status["backends"].as_array().expect("backends");
    assert_eq!(backends.len(), 1);
    assert_eq!(backends[0]["backend_id"], "macos.observe");
    assert_eq!(backends[0]["supported"], true);
    assert_eq!(backends[0]["reason_code"], "no-live-provider-probe");
    assert_eq!(backends[0]["reference_reason_code"], "alpha-not-validated");
    assert!(status.get("supervisor").is_none());
}

#[test]
fn every_profile_is_listed_unless_the_host_is_named() {
    let status = build("linux", defaults(), false, false, Value::Null);
    let supported: Vec<&Value> = status["backends"]
        .as_array()
        .expect("backends")
        .iter()
        .map(|backend| &backend["supported"])
        .collect();
    assert_eq!(supported, [&json!(true), &json!(false)]);
    let explicit = build("linux", defaults(), true, false, Value::Null);
    assert_eq!(explicit["backends"][1]["supported"], true);
}

#[test]
fn an_unknown_host_or_no_profile_says_why() {
    let status = build("freebsd14", defaults(), false, true, Value::Null);
    assert_eq!(status["host_platform"], "unsupported");
    assert_eq!(status["reason_code"], "unsupported-host-platform");
    assert_eq!(status["backends"], json!([]));
    let status = build("win32", json!([]), true, false, Value::Null);
    assert_eq!(status["host_platform"], "windows");
    assert_eq!(status["reason_code"], "no-platform-provider-profile");
}

#[test]
fn a_verified_production_backend_that_permits_enforcement_is_active() {
    let profiles = json!([profile("linux", "linux.oci-proxy", "proxy-only", true)]);
    let supervisor = health(json!("linux.oci-proxy"), "deny-all", true);
    let status = build("linux", profiles, true, false, supervisor);
    assert_eq!(status["protection_active"], true);
    assert_eq!(status["effective_grade"], "deny-all");
    let backend = &status["backends"][0];
    assert_eq!(backend["installed"], true);
    assert_eq!(backend["verified"], true);
    assert_eq!(backend["active"], true);
    assert_eq!(backend["reason_code"], "independent-observer-unavailable");
    assert_eq!(status["supervisor"]["effective_grade"], "deny-all");
    assert_eq!(status["supervisor"]["permits_enforcement"], true);
}

#[test]
fn a_probe_that_cannot_enforce_is_reported_as_such() {
    let profiles = json!([profile("linux", "linux.oci-proxy", "proxy-only", true)]);
    for supervisor in [
        health(json!("linux.oci-proxy"), "destination-enforced", true),
        health(json!("linux.oci-proxy"), "unavailable", true),
        health(json!("linux.oci-proxy"), "deny-all", false),
    ] {
        let status = build("linux", profiles.clone(), true, false, supervisor);
        assert_eq!(status["protection_active"], false);
        assert_eq!(status["reason_code"], "provider-probe-not-enforcing");
        assert_eq!(status["supervisor"]["effective_grade"], "unavailable");
        assert_eq!(status["supervisor"]["permits_enforcement"], false);
        assert_eq!(status["backends"][0]["reason_code"], "alpha-not-validated");
    }
    let status = build(
        "linux",
        profiles,
        true,
        false,
        health(Value::Null, "deny-all", true),
    );
    assert_eq!(status["reason_code"], "no-verified-installed-backend");
    assert_eq!(
        status["backends"][0]["reason_code"],
        "no-live-provider-probe"
    );
}

#[test]
fn the_legacy_domain_policy_rides_along() {
    let status = dispatch(&json!({
        "platform": "darwin",
        "profiles": [],
        "explicit": true,
        "host_only": false,
        "supervisor": null,
        "legacy_domain_policy": {"action": "approve", "sandbox_required": true},
    }))
    .expect("status answer");
    assert_eq!(
        status["legacy_domain_policy"],
        json!({"action": "approve", "sandbox_required": true})
    );
}

#[test]
fn malformed_requests_are_refused() {
    let base = json!({
        "platform": "linux",
        "profiles": [profile("linux", "linux.oci-proxy", "proxy-only", true)],
        "explicit": true,
        "host_only": false,
        "supervisor": health(json!("linux.oci-proxy"), "deny-all", true),
    });
    assert!(dispatch(&base).is_ok());
    for (key, value) in [
        ("platform", json!(7)),
        (
            "profiles",
            json!([profile("linux", "x", "strongest", true)]),
        ),
        (
            "supervisor",
            health(json!("linux.oci-proxy"), "strongest", true),
        ),
        ("supervisor", health(json!(7), "deny-all", true)),
        ("extra", json!(true)),
    ] {
        let mut args = base.clone();
        args[key] = value;
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{key}");
    }
}
