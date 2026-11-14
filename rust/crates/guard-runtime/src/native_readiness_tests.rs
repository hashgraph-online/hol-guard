use std::collections::BTreeSet;

use super::*;

#[test]
fn the_contract_declares_exactly_the_seven_states() {
    let declared: BTreeSet<&str> = contract().states.keys().map(String::as_str).collect();
    let known: BTreeSet<&str> = ReadinessState::ALL
        .iter()
        .map(|state| state.as_str())
        .collect();
    assert_eq!(declared, known);
}

#[test]
fn only_ready_carries_a_verdict() {
    for state in ReadinessState::ALL {
        let verdict = entry(state).verdict.as_str();
        if state == ReadinessState::Ready {
            assert_eq!(verdict, "evaluated");
        } else {
            assert_eq!(verdict, "not_evaluated", "{}", state.as_str());
        }
        assert!(!entry(state).summary.is_empty(), "{}", state.as_str());
    }
}

#[test]
fn every_state_is_reachable_from_a_reason() {
    let reached: BTreeSet<&str> = contract()
        .reasons
        .values()
        .map(|state| state.as_str())
        .collect();
    for state in ReadinessState::ALL {
        assert!(reached.contains(state.as_str()), "{}", state.as_str());
    }
}

#[test]
fn the_default_state_is_not_ready() {
    assert_eq!(contract().default_state, ReadinessState::Unavailable);
}

#[test]
fn every_reason_the_runtime_records_is_mapped() {
    // The reason codes the resilience state machine, the admission check and
    // the resident spawn write. A new one must be added to the contract.
    let recorded = [
        ("native_ready", "ready"),
        ("native_oneshot_fallback", "ready"),
        ("native_starting", "starting"),
        ("native_recovering", "starting"),
        ("native_state_uninitialized", "starting"),
        ("native_circuit_half_open", "starting"),
        ("native_overloaded", "overloaded"),
        ("native_oneshot_capacity", "overloaded"),
        ("native_unavailable", "unavailable"),
        ("native_disabled", "unavailable"),
        ("native_circuit_open", "unavailable"),
        ("native_resident_failed", "unavailable"),
        ("native_oneshot_failed", "unavailable"),
        ("native_version_mismatch", "incompatible"),
        ("native_manifest_missing", "incompatible"),
        ("native_manifest_invalid", "incompatible"),
        ("native_manifest_runtime_mismatch", "incompatible"),
        ("native_manifest_version_mismatch", "incompatible"),
        ("native_manifest_protocol_mismatch", "incompatible"),
        ("native_manifest_rule_mismatch", "incompatible"),
        ("native_manifest_build_mismatch", "incompatible"),
        (
            "native_capabilities_protocol_version_mismatch",
            "incompatible",
        ),
        (
            "native_capabilities_missing_resident_protocol",
            "incompatible",
        ),
        ("native_resident_spawn_auth_failed", "unauthenticated"),
        ("native_resident_state_token_invalid", "unauthenticated"),
        ("native_integrity_failed", "failed"),
    ];
    for (reason, state) in recorded {
        assert!(contract().reasons.contains_key(reason), "{reason}");
        assert_eq!(state_for_reason(reason).as_str(), state, "{reason}");
    }
}

#[test]
fn a_ready_payload_has_a_verdict_and_no_recovery() {
    let payload = readiness_payload("native_ready");
    assert_eq!(payload["schema"], PAYLOAD_SCHEMA);
    assert_eq!(payload["state"], "ready");
    assert_eq!(payload["verdict"], "evaluated");
    assert_eq!(payload["safe_verdict"], true);
    assert_eq!(payload["recovery_commands"], json!([]));
}

#[test]
fn each_failure_state_is_distinguishable_and_never_safe() {
    let cases = [
        ("native_starting", "starting", true),
        ("native_overloaded", "overloaded", true),
        ("daemon_start_timeout", "unavailable", false),
        ("native_manifest_build_mismatch", "incompatible", false),
        (
            "native_resident_spawn_auth_failed",
            "unauthenticated",
            false,
        ),
        ("native_evaluation_failed", "failed", false),
    ];
    let mut seen = BTreeSet::new();
    for (reason, state, retry) in cases {
        let payload = readiness_payload(reason);
        assert_eq!(payload["state"], state, "{reason}");
        assert_eq!(payload["reason_code"], reason);
        assert_eq!(payload["verdict"], "not_evaluated", "{reason}");
        assert_eq!(payload["safe_verdict"], false, "{reason}");
        assert_eq!(payload["retry"], retry, "{reason}");
        assert!(
            !payload["recovery_commands"]
                .as_array()
                .expect("recovery")
                .is_empty(),
            "{reason}"
        );
        seen.insert(state);
    }
    assert_eq!(seen.len(), cases.len());
}

#[test]
fn an_unknown_reason_is_unavailable_and_not_echoed() {
    let payload = readiness_payload("Some free text /Users/x/secret");
    assert_eq!(payload["state"], "unavailable");
    assert_eq!(payload["reason_code"], "native_reason_unrecognized");
    assert_eq!(payload["safe_verdict"], false);
    assert!(!payload.to_string().contains("/Users/"));
}

#[test]
fn the_payload_carries_only_declared_fields() {
    let payload = readiness_payload("native_starting");
    let keys: BTreeSet<&str> = payload
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "schema",
        "state",
        "reason_code",
        "verdict",
        "safe_verdict",
        "retry",
        "summary",
        "recovery_commands",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, expected);
}

#[test]
fn the_cli_support_operation_returns_the_payload() {
    let payload = crate::cli_runtime_support_op::evaluate(
        "native_readiness",
        &json!({"reason_code": "native_overloaded"}),
    )
    .expect("operation")["result"]
        .clone();
    assert_eq!(payload["state"], "overloaded");
    assert_eq!(payload["retry"], true);
    assert!(crate::cli_runtime_support_op::evaluate("native_readiness", &json!({})).is_err());
}
