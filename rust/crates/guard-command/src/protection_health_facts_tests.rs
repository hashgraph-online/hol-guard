use std::collections::BTreeMap;

use guard_contracts::ProtectionHealthFactsRequestV1;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::protection_health::{evaluate_protection_health, PROTECTION_CHECK_IDS};
use crate::protection_health_facts::{signals_from_facts, FactSignals, CONTAINMENT_CHECK_IDS};

pub(crate) const NOW: &str = "2026-07-19T15:00:00+00:00";

pub(crate) fn sha(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

pub(crate) fn evidence() -> Value {
    let fingerprint = sha(b"stable");
    json!({
        "backend": "macos-sandbox",
        "backend_digest": sha(b"backend"),
        "policy_contract_digest": sha(
            b"guard.containment-policy.v1\x00deny-network\x00deny-external-writes\x00deny-live-workspace-reads"
        ),
        "daemon_fingerprint": fingerprint,
        "runtime_fingerprint": fingerprint,
        "probe_at": NOW,
        "probe_enforced": true,
        "containment_schema_version": "guard.containment.v1",
        "policy_version": "guard.containment-policy.v1",
        "effect_contract_schema_version": "1.0.0",
        "effect_decision_schema_version": "1.1.0",
        "schema_version": "guard.containment-health.v1",
    })
}

/// The facts `build_runtime_protection_health` sends for a fresh daemon
/// heartbeat with compatible containment, before any test overrides them.
fn facts(overrides: Value) -> ProtectionHealthFactsRequestV1 {
    let mut base = json!({
        "schema": "guard-protection-health-facts-request.v1",
        "request_id": "request",
        "now": NOW,
        "managed_installs": [],
        "hook_verification": null,
        "daemon": {
            "registration_status": null,
            "last_heartbeat_at": NOW,
            "containment_health": evidence(),
        },
        "remembered_rules": null,
        "runtime_protection": null,
        "decision_stream": {"active_error_count": 0, "activity_count": 1},
    });
    for (key, value) in overrides.as_object().expect("overrides are an object") {
        base[key] = value.clone();
    }
    serde_json::from_value(base).expect("facts deserialize")
}

fn trusted() -> Value {
    json!({"remembered_rules": "enforced", "runtime_protection": "protected"})
}

fn merged(left: Value, right: Value) -> Value {
    let mut out = left;
    for (key, value) in right.as_object().expect("object") {
        out[key] = value.clone();
    }
    out
}

pub(crate) fn collect(overrides: Value) -> FactSignals {
    signals_from_facts(&facts(overrides)).expect("now parses")
}

pub(crate) fn row(signals: &FactSignals, check_id: &str) -> (String, String) {
    harness_row(&signals.signals, check_id)
}

fn harness_row(
    map: &BTreeMap<String, crate::protection_health::ProtectionSignal>,
    key: &str,
) -> (String, String) {
    let signal = &map[key];
    (
        format!("{:?}", signal.status()).to_lowercase(),
        signal.reason_code().to_owned(),
    )
}

pub(crate) fn pair(status: &str, reason: &str) -> (String, String) {
    (status.to_owned(), reason.to_owned())
}

fn all_pass(signals: &FactSignals) -> bool {
    signals
        .signals
        .values()
        .all(|signal| signal.status() == crate::protection_health::ProtectionCheckStatus::Pass)
}

#[test]
fn every_check_the_report_needs_is_produced() {
    let signals = collect(json!({"managed_installs": [{"harness": "codex", "active": true}]}));
    let ids: Vec<&str> = signals.signals.keys().map(String::as_str).collect();
    let mut expected = PROTECTION_CHECK_IDS.to_vec();
    expected.sort_unstable();
    assert_eq!(ids, expected);
    evaluate_protection_health(&signals.signals, &signals.harness_signals)
        .expect("the produced signals are a report the grammar accepts");
}

#[test]
fn missing_positive_proofs_never_produce_an_all_passing_signal_set() {
    for active in [false, true] {
        for protection in ["protected", "degraded", "unknown"] {
            for rules in ["enforced", "disabled_degraded", "unknown"] {
                for active_errors in [0, 1] {
                    let signals = collect(json!({
                        "managed_installs": [{"harness": "codex", "active": active}],
                        "runtime_protection": protection,
                        "remembered_rules": rules,
                        "decision_stream": {"active_error_count": active_errors, "activity_count": 1},
                    }));
                    assert!(!all_pass(&signals));
                }
            }
        }
    }
}

#[test]
fn repaired_live_state_is_healthy_and_a_fresh_store_is_ready() {
    let verified = json!({
        "managed_installs": [{"harness": "codex", "active": true}],
        "hook_verification": {"codex": true},
    });
    let repaired = collect(merged(
        merged(verified.clone(), trusted()),
        json!({"decision_stream": {"active_error_count": 0, "activity_count": 38_102}}),
    ));
    assert_eq!(
        row(&repaired, "decision_stream"),
        pair("pass", "decision_stream_healthy")
    );
    assert_eq!(
        row(&repaired, "rule_packs"),
        pair("pass", "rule_packs_enforced")
    );
    assert_eq!(
        row(&repaired, "tamper_checks"),
        pair("pass", "runtime_protection_trusted")
    );
    assert!(all_pass(&repaired));

    let fresh = collect(merged(
        merged(verified, trusted()),
        json!({"decision_stream": {"active_error_count": 0, "activity_count": 0}}),
    ));
    assert_eq!(
        row(&fresh, "decision_stream"),
        pair("pass", "decision_stream_ready")
    );
    assert!(all_pass(&fresh));
}

#[test]
fn signals_distinguish_failed_and_unproven_facts() {
    let active = collect(merged(
        json!({"managed_installs": [{"harness": "codex", "active": true}]}),
        trusted(),
    ));
    assert_eq!(row(&active, "daemon"), pair("pass", "daemon_healthy"));
    assert_eq!(
        row(&active, "harness_hooks"),
        pair("unknown", "hook_attestation_unavailable")
    );
    assert_eq!(
        row(&active, "decision_plane_compatibility"),
        pair("pass", "decision_plane_compatible")
    );
    assert_eq!(
        row(&active, "sandbox"),
        pair("pass", "containment_backend_enforced")
    );

    let degraded = collect(json!({
        "managed_installs": [{"harness": "codex", "active": false}],
        "runtime_protection": "degraded",
        "remembered_rules": "disabled_degraded",
        "decision_stream": {"active_error_count": 1, "activity_count": 1},
    }));
    assert_eq!(
        row(&degraded, "harness_hooks"),
        pair("fail", "no_managed_harness")
    );
    assert_eq!(
        row(&degraded, "tamper_checks"),
        pair("fail", "tamper_checks_failed")
    );
    assert_eq!(
        row(&degraded, "rule_packs"),
        pair("fail", "rule_packs_disabled")
    );
    assert_eq!(
        row(&degraded, "decision_stream"),
        pair("fail", "decision_stream_degraded")
    );

    let unproven = collect(json!({
        "runtime_protection": "unknown",
        "remembered_rules": 7,
        "decision_stream": null,
    }));
    assert_eq!(
        row(&unproven, "tamper_checks"),
        pair("unknown", "tamper_proof_unavailable")
    );
    assert_eq!(
        row(&unproven, "rule_packs"),
        pair("unknown", "rule_pack_runtime_proof_unavailable")
    );
    assert_eq!(
        row(&unproven, "decision_stream"),
        pair("fail", "decision_stream_health_unavailable")
    );
}

#[test]
fn a_failed_verification_fails_its_harness_and_every_hook() {
    let signals = collect(json!({
        "managed_installs": [
            {"harness": "codex", "active": true},
            {"harness": "cursor", "active": true},
            {"harness": "codex", "active": true},
        ],
        "hook_verification": {"codex": false, "cursor": true},
    }));
    assert_eq!(
        harness_row(&signals.harness_signals, "codex"),
        pair("fail", "hooks_inactive")
    );
    assert_eq!(
        harness_row(&signals.harness_signals, "cursor"),
        pair("pass", "hooks_verified")
    );
    assert_eq!(
        row(&signals, "harness_hooks"),
        pair("fail", "one_or_more_hooks_inactive")
    );

    // A verification that is not a boolean proves nothing either way.
    let signals = collect(json!({
        "managed_installs": [{"harness": "codex", "active": true}],
        "hook_verification": {"codex": "yes"},
    }));
    assert_eq!(
        harness_row(&signals.harness_signals, "codex"),
        pair("unknown", "hook_attestation_unavailable")
    );
}

#[test]
fn inactive_duplicate_rows_do_not_override_an_active_install() {
    for installs in [
        json!([{"harness": "codex", "active": false}, {"harness": "codex", "active": true}]),
        json!([{"harness": "codex", "active": true}, {"harness": "codex", "active": false}]),
    ] {
        let signals = collect(json!({"managed_installs": installs}));
        assert_eq!(
            signals.harness_signals.keys().collect::<Vec<_>>(),
            ["codex"]
        );
        assert_eq!(
            harness_row(&signals.harness_signals, "codex"),
            pair("unknown", "hook_attestation_unavailable")
        );
    }
}

#[test]
fn inactive_historical_rows_do_not_degrade_verified_active_hooks() {
    let signals = collect(merged(
        json!({
            "managed_installs": [
                {"harness": "pi", "active": false},
                {"harness": "cursor", "active": true},
                {"harness": "codex", "active": 1},
            ],
            "hook_verification": {"cursor": true},
        }),
        trusted(),
    ));
    assert_eq!(
        signals.harness_signals.keys().collect::<Vec<_>>(),
        ["cursor"]
    );
    assert_eq!(
        harness_row(&signals.harness_signals, "cursor"),
        pair("pass", "hooks_verified")
    );
    assert!(all_pass(&signals));
}

#[test]
fn stale_future_or_invalid_runtime_rows_never_prove_daemon_health() {
    let cases = [
        (
            "2026-07-19T14:59:29+00:00",
            pair("fail", "daemon_heartbeat_stale"),
        ),
        (
            "2026-07-19T15:00:06+00:00",
            pair("unknown", "daemon_heartbeat_future"),
        ),
        ("not-a-time", pair("unknown", "daemon_heartbeat_invalid")),
        (
            "2026-07-19T15:00:00",
            pair("unknown", "daemon_heartbeat_invalid"),
        ),
        (
            " 2026-07-19T15:00:00+00:00",
            pair("unknown", "daemon_heartbeat_invalid"),
        ),
        (
            "2026-07-19T15:00:00z",
            pair("unknown", "daemon_heartbeat_invalid"),
        ),
    ];
    for (heartbeat, expected) in cases {
        let signals = collect(json!({"daemon": {
            "registration_status": null,
            "last_heartbeat_at": heartbeat,
            "containment_health": null,
        }}));
        assert_eq!(row(&signals, "daemon"), expected, "{heartbeat}");
    }
    // Thirty seconds old and five seconds early are both still fresh.
    for heartbeat in ["2026-07-19T14:59:30+00:00", "2026-07-19T15:00:05Z"] {
        let signals = collect(json!({"daemon": {
            "registration_status": null,
            "last_heartbeat_at": heartbeat,
            "containment_health": null,
        }}));
        assert_eq!(
            row(&signals, "daemon"),
            pair("pass", "daemon_healthy"),
            "{heartbeat}"
        );
    }
}

#[test]
fn absent_or_unregistered_daemons_never_prove_health() {
    let absent = collect(json!({"daemon": null}));
    assert_eq!(
        row(&absent, "daemon"),
        pair("fail", "daemon_runtime_unavailable")
    );
    for check_id in CONTAINMENT_CHECK_IDS {
        assert_eq!(
            row(&absent, check_id),
            pair("fail", "containment_health_invalid")
        );
    }

    let missing = collect(json!({"daemon": {
        "registration_status": "missing",
        "last_heartbeat_at": NOW,
        "containment_health": evidence(),
    }}));
    assert_eq!(
        row(&missing, "daemon"),
        pair("unknown", "daemon_registration_missing")
    );

    let silent = collect(json!({"daemon": {
        "registration_status": "registered",
        "last_heartbeat_at": 17,
        "containment_health": evidence(),
    }}));
    assert_eq!(
        row(&silent, "daemon"),
        pair("unknown", "daemon_heartbeat_unavailable")
    );
}

#[test]
fn harness_signals_carry_only_a_stable_identity() {
    let mut installs: Vec<Value> = (0..120)
        .map(|index| json!({"harness": format!("app-{index}"), "active": true}))
        .collect();
    installs.push(json!({"harness": "../../private", "active": true}));
    installs.push(json!({"harness": "a".repeat(65), "active": true}));
    installs.push(json!({"harness": 7, "active": true}));
    let signals = collect(json!({"managed_installs": installs}));
    assert!(!signals.harness_signals.contains_key("../../private"));
    assert_eq!(signals.harness_signals.len(), 120);
    let report = evaluate_protection_health(&signals.signals, &signals.harness_signals)
        .expect("stable identities are reportable");
    assert_eq!(report.apps.len(), 100);
}

#[test]
fn facts_need_an_aware_instant() {
    for now in [
        "",
        "2026-07-19T15:00:00",
        "yesterday",
        "2026-07-19T15:00:00+00:00 ",
        "2026-07-19T15:00:00z",
    ] {
        let error = signals_from_facts(&facts(json!({"now": now}))).expect_err(now);
        assert_eq!(
            error.message(),
            "protection facts must be read at an aware instant"
        );
    }
}
