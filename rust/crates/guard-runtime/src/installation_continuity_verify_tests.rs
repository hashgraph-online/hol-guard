use serde_json::json;

use super::{answer, boot, encoded, issued, keys, outcome, raised, uninitialized, verified};

#[test]
fn a_fresh_record_with_its_key_is_healthy_and_uninitialized() {
    let answer = verified(&uninitialized(), keys(&["active-key"]), boot("boot-a", 1));
    assert_eq!(
        outcome(&answer),
        (
            "healthy",
            "installation_identity_active",
            "lease_continuity_uninitialized",
            true,
            true
        )
    );
    assert_eq!(
        answer["record"]["key_id_at_generation_creation"],
        json!("active-key")
    );
}

#[test]
fn an_issued_record_is_active_and_a_retained_rotation_key_still_counts() {
    let answer = verified(
        &issued(8, "boot-a", 5),
        keys(&["new-key", "active-key"]),
        boot("boot-a", 5),
    );
    assert_eq!(
        outcome(&answer),
        (
            "healthy",
            "installation_identity_active",
            "lease_continuity_active",
            true,
            true
        )
    );
}

#[test]
fn an_invalid_record_wins_over_every_probe() {
    let mut record = uninitialized();
    record["schemaVersion"] = json!("wrong");
    let answer = verified(
        &record,
        raised("os", "device_key_rotation_incomplete"),
        boot("b", 1),
    );
    assert_eq!(
        outcome(&answer),
        (
            "tampered",
            "installation_identity_invalid",
            "lease_continuity_invalid",
            false,
            false
        )
    );
}

#[test]
fn an_unrelated_key_is_a_key_mismatch() {
    let answer = verified(&uninitialized(), keys(&["new-key"]), boot("boot-a", 1));
    assert_eq!(
        outcome(&answer),
        (
            "tampered",
            "installation_identity_key_mismatch",
            "lease_continuity_invalid",
            false,
            false
        )
    );
}

#[test]
fn key_probe_failures_map_like_the_python_handlers() {
    let cases = [
        (
            raised("permission", "device_key_absent"),
            ("tampered", "installation_identity_acl_invalid"),
        ),
        (
            raised("value", "anything"),
            ("tampered", "installation_identity_invalid"),
        ),
        (
            raised("os", "device_key_absent"),
            ("tampered", "installation_identity_key_mismatch"),
        ),
        (
            raised("os", "device_key_revoked"),
            ("tampered", "installation_identity_key_mismatch"),
        ),
        (
            raised("os", "device_key_public_mismatch"),
            ("tampered", "installation_identity_key_mismatch"),
        ),
        (
            raised("os", "device_key_rotation_incomplete"),
            ("unknown", "installation_identity_probe_failed"),
        ),
        (
            raised("os", "[Errno 5] Input/output error"),
            ("unknown", "installation_identity_probe_failed"),
        ),
    ];
    for (key, (state, identity)) in cases {
        let answer = verified(&uninitialized(), key.clone(), boot("boot-a", 1));
        let (got_state, got_identity, lease, record, observed) = outcome(&answer);
        assert_eq!((got_state, got_identity), (state, identity), "{key}");
        let expected_lease = if state == "unknown" {
            "lease_continuity_probe_failed"
        } else {
            "lease_continuity_invalid"
        };
        assert_eq!(lease, expected_lease, "{key}");
        assert!(!record && !observed, "{key}");
    }
}

#[test]
fn boot_probe_failures_keep_the_verified_identity() {
    let cases = [
        (
            "os",
            "lease_continuity_platform_unsupported",
            "unsupported",
            "lease_continuity_platform_unsupported",
        ),
        (
            "os",
            "lease_continuity_boot_probe_failed",
            "unknown",
            "lease_continuity_boot_probe_failed",
        ),
        (
            "os",
            "lease_continuity_monotonic_probe_failed",
            "unknown",
            "lease_continuity_monotonic_probe_failed",
        ),
        (
            "permission",
            "denied",
            "unknown",
            "lease_continuity_probe_failed",
        ),
        (
            "os",
            "[Errno 2] No such file",
            "unknown",
            "lease_continuity_probe_failed",
        ),
    ];
    for (kind, error, state, lease) in cases {
        let answer = verified(&uninitialized(), keys(&["active-key"]), raised(kind, error));
        assert_eq!(
            outcome(&answer),
            (state, "installation_identity_active", lease, true, false),
            "{kind} {error}"
        );
    }
}

#[test]
fn a_boot_probe_value_error_is_an_invalid_identity() {
    let answer = verified(
        &uninitialized(),
        keys(&["active-key"]),
        raised("value", "bad boot id"),
    );
    assert_eq!(
        outcome(&answer),
        (
            "tampered",
            "installation_identity_invalid",
            "lease_continuity_invalid",
            false,
            false
        )
    );
}

#[test]
fn a_same_boot_uptime_regression_is_tampering() {
    let record = issued(8, "boot-a", 20_000_000_000);
    let answer = verified(
        &record,
        keys(&["active-key"]),
        boot("boot-a", 10_000_000_000),
    );
    assert_eq!(
        outcome(&answer),
        (
            "tampered",
            "installation_identity_active",
            "lease_continuity_monotonic_regression",
            true,
            true
        )
    );
    let equal = verified(
        &record,
        keys(&["active-key"]),
        boot("boot-a", 20_000_000_000),
    );
    assert_eq!(outcome(&equal).0, "healthy");
}

#[test]
fn a_lower_uptime_after_a_reboot_is_healthy() {
    let record = issued(8, "boot-before", 20_000_000_000);
    let answer = verified(
        &record,
        keys(&["active-key"]),
        boot("boot-a", 10_000_000_000),
    );
    assert_eq!(
        outcome(&answer),
        (
            "healthy",
            "installation_identity_active",
            "lease_continuity_active",
            true,
            true
        )
    );
}

#[test]
fn the_maximum_sequence_is_degraded() {
    let answer = verified(
        &issued(u64::MAX, "boot-before", 1),
        keys(&["active-key"]),
        boot("boot-a", 1),
    );
    assert_eq!(
        outcome(&answer),
        (
            "degraded",
            "installation_identity_active",
            "lease_continuity_sequence_exhausted",
            true,
            true
        )
    );
}

#[test]
fn a_regression_is_reported_before_an_exhausted_sequence() {
    let record = issued(u64::MAX, "boot-a", 9);
    let answer = verified(&record, keys(&["active-key"]), boot("boot-a", 8));
    assert_eq!(outcome(&answer).2, "lease_continuity_monotonic_regression");
}

#[test]
fn malformed_requests_fail_the_command() {
    let content = encoded(&uninitialized());
    let requests = [
        json!({"op": "parse", "content": content}),
        json!({"schema": "installation-continuity.v1", "op": "erase", "content": content}),
        json!({"schema": "installation-continuity.v1", "op": "parse"}),
        json!({"schema": "installation-continuity.v1", "op": "parse", "content": "%%%"}),
        json!({"schema": "installation-continuity.v1", "op": "parse", "content": content, "extra": 1}),
        json!({"schema": "installation-continuity.v1", "op": "verify", "content": content, "key": keys(&[])}),
        json!({
            "schema": "installation-continuity.v1",
            "op": "verify",
            "content": content,
            "key": {"ids": "active-key"},
            "boot": boot("boot-a", 1),
        }),
        json!({
            "schema": "installation-continuity.v1",
            "op": "verify",
            "content": content,
            "key": keys(&["active-key"]),
            "boot": {"boot_session_id": "boot-a", "monotonic_uptime_ns": -1},
        }),
    ];
    for request in requests {
        let bytes = serde_json::to_vec(&request).expect("request");
        assert_eq!(
            answer(&bytes),
            Err("installation_continuity_request_invalid".to_owned()),
            "{request}"
        );
    }
    assert!(answer(b"[]").is_err());
}
