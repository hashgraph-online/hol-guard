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

/// The modules that write a runtime health reason or a resident start,
/// stop or client failure code. A code in their production source that the
/// contract does not map would reach the payload as unrecognized. The
/// resident's listener setup (`resident_transport_service.rs`) is left out:
/// its failures stop the resident before it serves, and the client reports
/// that as a start failure or timeout.
fn emits_runtime_reasons(name: &str) -> bool {
    !name.ends_with("_tests.rs")
        && (matches!(
            name,
            "native_runtime_resilience.rs"
                | "native_runtime_admission.rs"
                | "resident_client.rs"
                | "resident_endpoint.rs"
                | "resident_health_op.rs"
                | "resident_lifecycle_journal.rs"
                | "resident_private_file.rs"
                | "resident_process_identity.rs"
                | "resident_requested_stop.rs"
                | "resident_runtime_verification.rs"
                | "resident_startup_lock.rs"
                | "resident_transport.rs"
                | "resident_update_lock.rs"
                | "resident_restart_budget.rs"
        ) || name.starts_with("managed_resident")
            || name.starts_with("resident_state"))
}

/// Production lines of a source file. An item gated on a test cfg is
/// dropped whole (its attributes, then the item up to its `;` or the brace
/// that closes it); everything after it is still read.
fn production_lines(text: &str) -> Vec<&str> {
    let mut kept = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        if !is_test_gate(line) {
            kept.push(line);
            continue;
        }
        let mut depth = 0i64;
        let mut opened = false;
        for item in lines.by_ref() {
            let trimmed = item.trim();
            if !opened && (trimmed.is_empty() || trimmed.starts_with("#[")) {
                continue;
            }
            for character in item.chars() {
                match character {
                    '{' => {
                        depth += 1;
                        opened = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            if depth <= 0 && (opened || trimmed.ends_with(';')) {
                break;
            }
        }
    }
    kept
}

fn is_test_gate(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("#[cfg(")
        && !trimmed.contains("not(test")
        && regex::Regex::new(r"\btest\b")
            .expect("pattern")
            .is_match(trimmed)
}

/// Literals in those modules that name an operation, not a reason.
const NOT_REASONS: [&str; 1] = ["native_bash_execute"];

fn emitted_reason_codes() -> BTreeSet<String> {
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let literal = regex::Regex::new(r#""(native_[a-z0-9_]*[a-z0-9])""#).expect("pattern");
    let mut codes = BTreeSet::new();
    for entry in std::fs::read_dir(source).expect("source directory") {
        let path = entry.expect("entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if !emits_runtime_reasons(name) {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("source file");
        for line in production_lines(&text) {
            if line.trim_start().starts_with("//") {
                continue;
            }
            for capture in literal.captures_iter(line) {
                codes.insert(capture[1].to_owned());
            }
        }
    }
    for code in NOT_REASONS {
        codes.remove(code);
    }
    codes
}

#[test]
fn every_reason_the_runtime_writes_is_mapped() {
    let emitted = emitted_reason_codes();
    // The scan must find the codes it exists to check.
    for known in [
        "native_ready",
        "native_overloaded",
        "native_resident_spawn_failed",
        "native_resident_start_in_progress",
        // Written after a test-gated item near the top of their files.
        "native_resident_lease_lock_failed",
        "native_resident_state_invalid",
        // Written by the client, not the resident.
        "native_client_auth_rejected",
    ] {
        assert!(emitted.contains(known), "scan missed {known}");
    }
    let unmapped: Vec<&String> = emitted
        .iter()
        .filter(|code| !contract().reasons.contains_key(code.as_str()))
        .collect();
    assert!(
        unmapped.is_empty(),
        "map these in the contract: {unmapped:?}"
    );
}

#[test]
fn key_reasons_reach_their_state() {
    let cases = [
        ("native_ready", "ready"),
        ("native_oneshot_fallback", "ready"),
        ("native_starting", "starting"),
        ("native_resident_start_in_progress", "starting"),
        ("native_overloaded", "overloaded"),
        ("native_circuit_open", "unavailable"),
        ("native_resident_spawn_failed", "unavailable"),
        ("native_client_deadline_exceeded", "unavailable"),
        ("native_manifest_build_mismatch", "incompatible"),
        ("native_resident_spawn_auth_failed", "unauthenticated"),
        ("native_resident_state_mac_invalid", "unauthenticated"),
        ("native_integrity_failed", "failed"),
        ("native_client_stream_frame_truncated", "failed"),
    ];
    for (reason, state) in cases {
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
