use super::super::super::tests::{input, write, Fixture};
use super::super::{claim_refreshed_review, persist_prepared_review};
use super::*;
use guard_policy_snapshot::business_source_anchor::{
    sign_business_source_anchor, BusinessSourcePhase,
};
use guard_policy_snapshot::business_source_authority::{
    sign_business_source, verify_business_source,
};
use guard_policy_snapshot::{integrity_mac, policy_digest};
use serde_json::json;
use std::cell::Cell;

fn claimed(f: &Fixture) -> ClaimedBusinessReview<PreparedBusinessInputV1> {
    let prepared = super::super::super::prepare(input(b"private-owned-send", &[])).unwrap();
    let binding = prepared.binding().to_owned();
    persist_prepared_review(&f.store, "business-test", &prepared, || true).unwrap();
    let decision = super::super::super::tests::owned_input_tests::owned_decision(f);
    claim_refreshed_review(
        &f.store,
        "business-test",
        &canonical_json_bytes(&decision).unwrap(),
        &binding,
        prepared,
        |_| true,
        PreparedBusinessInputV1::binding,
    )
    .unwrap()
}

fn status(f: &Fixture) -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(
            f.root
                .join("workspace-review-business-attempts/business-test.json"),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn owned_send_starts_durable_attempt_before_exactly_one_call_and_retains_ack() {
    let f = Fixture::new("business-dispatch-owned");
    let c = claimed(&f);
    let time = c.lease.claimed_at_ms;
    let count = Cell::new(0);
    let result = c
        .dispatch_with(
            &f.store,
            |_| true,
            |input, owned| {
                assert_eq!(input.binding(), owned.binding());
                assert_eq!(owned.primary_bytes(), b"private-owned-send");
                assert_eq!(status(&f)["status"], "attempt_started");
                count.set(count.get() + 1);
                Ok(GoogleSendAttempt::ApiAccepted {
                    message_binding: "e".repeat(64),
                })
            },
            || Ok(time),
        )
        .unwrap();
    assert_eq!(count.get(), 1);
    assert!(result.journal_recorded);
    let receipt = serde_json::to_value(result.receipt().unwrap()).unwrap();
    assert_eq!(receipt["attempt"], "api_accepted");
    assert_eq!(receipt["journal"], "recorded");
    assert_eq!(receipt["provider_effect"], "not_checked");
    assert_eq!(receipt["retry_authority"], "none");
    assert_eq!(receipt["acknowledgement_binding"], "e".repeat(64));
    assert!(!receipt.to_string().contains("private-owned-send"));
    assert!(matches!(
        result.attempt,
        GoogleSendAttempt::ApiAccepted { .. }
    ));
    assert_eq!(status(&f)["status"], "api_accepted");
    assert_eq!(status(&f)["acknowledgement_binding"], "e".repeat(64));
}

#[test]
fn expiry_and_clock_rollback_after_journal_start_never_call_transport() {
    for rollback in [false, true] {
        let f = Fixture::new(if rollback {
            "business-dispatch-rollback"
        } else {
            "business-dispatch-expiry"
        });
        let c = claimed(&f);
        let first = c.lease.claimed_at_ms;
        let last = if rollback {
            first - 1
        } else {
            c.lease.expires_at_ms
        };
        let mut times = [first, last].into_iter();
        let count = Cell::new(0);
        assert!(c
            .dispatch_with(
                &f.store,
                |_| true,
                |_, _| {
                    count.set(count.get() + 1);
                    Ok(GoogleSendAttempt::Unconfirmed)
                },
                || Ok(times.next().unwrap())
            )
            .is_err());
        assert_eq!(count.get(), 0);
        assert_eq!(status(&f)["status"], "not_attempted");
    }
}

#[test]
fn resolution_expiring_after_attempt_start_records_no_transport_attempt() {
    let f = Fixture::new("business-dispatch-resolution-after-start");
    let c = claimed(&f);
    let time = c.lease.claimed_at_ms;
    let checks = Cell::new(0);
    let sends = Cell::new(0);
    let error = c
        .dispatch_with(
            &f.store,
            |_| {
                checks.set(checks.get() + 1);
                checks.get() == 1
            },
            |_, _| {
                sends.set(sends.get() + 1);
                Ok(GoogleSendAttempt::Unconfirmed)
            },
            || Ok(time),
        )
        .err()
        .unwrap();
    assert_eq!(error, "native_business_dispatch_resolution_expired");
    assert_eq!(checks.get(), 2);
    assert_eq!(sends.get(), 0);
    assert_eq!(status(&f)["status"], "not_attempted");
}

#[test]
fn changed_policy_after_claim_refuses_before_attempt_or_transport() {
    let f = Fixture::new("business-dispatch-policy-change");
    let c = claimed(&f);
    let time = c.lease.claimed_at_ms;
    let mut snapshot = f.store.current_snapshot().unwrap();
    snapshot.generation += 1;
    let mut document = f.source_document.as_ref().unwrap().clone();
    document["metadata"]["revision"] = json!(snapshot.generation);
    document["spec"]["rules"][0]["effect"] = json!("block");
    let record = sign_business_source(&document, snapshot.generation, &f.key).unwrap();
    let source = verify_business_source(&record, &f.key).unwrap();
    snapshot.business_policy = Some(source.compiled().binding().clone());
    let marker =
        sign_business_source_anchor(&source, BusinessSourcePhase::Committed, &f.key).unwrap();
    write(
        &f.root,
        &f.root.join("business-source-anchor.v1.json"),
        &serde_json::from_slice(&marker).unwrap(),
    );
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &f.key).unwrap();
    f.store
        .push(&json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot}))
        .unwrap();
    let count = Cell::new(0);
    assert!(c
        .dispatch_with(
            &f.store,
            |_| true,
            |_, _| {
                count.set(count.get() + 1);
                Ok(GoogleSendAttempt::Unconfirmed)
            },
            || Ok(time)
        )
        .is_err());
    assert_eq!(count.get(), 0);
    assert_eq!(status(&f)["status"], "claimed");
}

#[test]
fn expired_resolution_and_changed_journal_do_not_call_transport() {
    for changed in [false, true] {
        let f = Fixture::new(if changed {
            "business-dispatch-journal-change"
        } else {
            "business-dispatch-resolution-expiry"
        });
        let c = claimed(&f);
        let time = c.lease.claimed_at_ms;
        if changed {
            std::fs::remove_file(
                f.root
                    .join("workspace-review-business-attempts/business-test.json"),
            )
            .unwrap();
        }
        let count = Cell::new(0);
        assert!(c
            .dispatch_with(
                &f.store,
                |_| changed,
                |_, _| {
                    count.set(count.get() + 1);
                    Ok(GoogleSendAttempt::Unconfirmed)
                },
                || Ok(time)
            )
            .is_err());
        assert_eq!(count.get(), 0);
    }
}

#[test]
fn unknown_outcome_and_sdk_error_never_retry() {
    for rejected in [false, true] {
        let f = Fixture::new(if rejected {
            "business-dispatch-sdk-error"
        } else {
            "business-dispatch-unknown"
        });
        let c = claimed(&f);
        let time = c.lease.claimed_at_ms;
        let count = Cell::new(0);
        let result = c.dispatch_with(
            &f.store,
            |_| true,
            |_, _| {
                count.set(count.get() + 1);
                if rejected {
                    Err(GoogleDispatchError::InputChanged)
                } else {
                    Ok(GoogleSendAttempt::Unconfirmed)
                }
            },
            || Ok(time),
        );
        assert_eq!(count.get(), 1);
        assert_eq!(result.is_err(), rejected);
        if let Ok(outcome) = result {
            let receipt = outcome.receipt().unwrap();
            assert_eq!(receipt.attempt, BusinessDispatchAttemptV1::OutcomeUnknown);
            assert_eq!(
                receipt.provider_effect,
                BusinessProviderEffectV1::NotChecked
            );
            assert_eq!(
                receipt.retry_authority,
                BusinessDispatchRetryAuthorityV1::None
            );
            assert_eq!(receipt.acknowledgement_binding, None);
        }
        assert_eq!(
            status(&f)["status"],
            if rejected {
                "not_attempted"
            } else {
                "unconfirmed"
            }
        );
    }
}

#[test]
fn outcome_persistence_failure_is_reported_without_a_second_send() {
    let f = Fixture::new("business-dispatch-outcome-write-failure");
    let c = claimed(&f);
    let time = c.lease.claimed_at_ms;
    let count = Cell::new(0);
    let result = c
        .dispatch_with(
            &f.store,
            |_| true,
            |_, _| {
                count.set(count.get() + 1);
                std::fs::remove_file(
                    f.root
                        .join("workspace-review-business-attempts/business-test.json"),
                )
                .unwrap();
                Ok(GoogleSendAttempt::Unconfirmed)
            },
            || Ok(time),
        )
        .unwrap();
    assert_eq!(count.get(), 1);
    assert!(!result.journal_recorded);
    let receipt = result.receipt().unwrap();
    assert_eq!(receipt.attempt, BusinessDispatchAttemptV1::OutcomeUnknown);
    assert_eq!(receipt.journal, BusinessDispatchJournalV1::Unconfirmed);
    assert_eq!(
        receipt.retry_authority,
        BusinessDispatchRetryAuthorityV1::None
    );
    assert_eq!(result.attempt, GoogleSendAttempt::Unconfirmed);
}

#[test]
fn mismatched_native_verifier_result_does_not_call_transport() {
    for changed in 0..3 {
        let f = Fixture::new("business-dispatch-verifier-mismatch");
        let mut c = claimed(&f);
        let time = c.lease.claimed_at_ms;
        match changed {
            0 => c.lease.envelope_digest = "f".repeat(64),
            1 => c.verified.decision = "review".into(),
            _ => c.verified.replayed = true,
        }
        let count = Cell::new(0);
        assert!(c
            .dispatch_with(
                &f.store,
                |_| true,
                |_, _| {
                    count.set(count.get() + 1);
                    Ok(GoogleSendAttempt::Unconfirmed)
                },
                || Ok(time)
            )
            .is_err());
        assert_eq!(count.get(), 0);
        assert_eq!(status(&f)["status"], "claimed");
    }
}

#[test]
fn missing_installed_authority_after_claim_does_not_call_transport() {
    let f = Fixture::new("business-dispatch-authority-missing");
    let c = claimed(&f);
    let time = c.lease.claimed_at_ms;
    std::fs::remove_file(f.root.join(workspace_review_authority::AUTHORITY_FILE_NAME)).unwrap();
    let count = Cell::new(0);
    assert!(c
        .dispatch_with(
            &f.store,
            |_| true,
            |_, _| {
                count.set(count.get() + 1);
                Ok(GoogleSendAttempt::Unconfirmed)
            },
            || Ok(time)
        )
        .is_err());
    assert_eq!(count.get(), 0);
}

#[test]
fn sdk_refusal_with_failed_journal_write_reports_both_without_retry() {
    let f = Fixture::new("business-dispatch-sdk-and-journal-failure");
    let c = claimed(&f);
    let time = c.lease.claimed_at_ms;
    let count = Cell::new(0);
    let error = c
        .dispatch_with(
            &f.store,
            |_| true,
            |_, _| {
                count.set(count.get() + 1);
                std::fs::remove_file(
                    f.root
                        .join("workspace-review-business-attempts/business-test.json"),
                )
                .unwrap();
                Err(GoogleDispatchError::WrongPurpose)
            },
            || Ok(time),
        )
        .err()
        .unwrap();
    assert_eq!(count.get(), 1);
    assert_eq!(
        error,
        "native_business_dispatch_spent_input_and_journal_unavailable"
    );
}

#[test]
fn policy_push_cannot_replace_snapshot_during_the_owned_call() {
    let f = Fixture::new("business-dispatch-policy-push-fence");
    let c = claimed(&f);
    let time = c.lease.claimed_at_ms;
    let generation = f.store.current_snapshot().unwrap().generation;
    let mut snapshot = f.store.current_snapshot().unwrap();
    snapshot.generation += 1;
    snapshot.policy_digest = policy_digest(&snapshot).unwrap();
    snapshot.integrity.mac = integrity_mac(&snapshot, &f.key).unwrap();
    let push = json!({"schema":"guard-policy-snapshot-push.v1","snapshot":snapshot});
    let result = c
        .dispatch_with(
            &f.store,
            |_| true,
            |_, _| {
                assert_eq!(
                    f.store.push(&push).err().unwrap(),
                    "native_approval_authority_busy"
                );
                assert_eq!(f.store.current_snapshot().unwrap().generation, generation);
                Ok(GoogleSendAttempt::Unconfirmed)
            },
            || Ok(time),
        )
        .unwrap();
    assert!(result.journal_recorded);
    f.store.push(&push).unwrap();
    assert_eq!(
        f.store.current_snapshot().unwrap().generation,
        generation + 1
    );
}
