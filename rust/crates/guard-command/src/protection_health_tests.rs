use std::collections::BTreeMap;

use super::protection_health::{
    evaluate_protection_health, ProtectionCheckStatus, ProtectionSignal, ProtectionState,
    PROTECTION_CHECK_IDS,
};

fn proven() -> ProtectionSignal {
    ProtectionSignal::new(ProtectionCheckStatus::Pass, "verified").expect("a stable reason code")
}

fn every_check_proven() -> BTreeMap<String, ProtectionSignal> {
    PROTECTION_CHECK_IDS
        .iter()
        .map(|check_id| ((*check_id).to_owned(), proven()))
        .collect()
}

#[test]
fn a_reason_code_must_be_a_stable_identifier() {
    for reason_code in [
        "Proof Unavailable",
        "",
        "_leading",
        "trailing_",
        "has space",
    ] {
        let error = ProtectionSignal::new(ProtectionCheckStatus::Unknown, reason_code)
            .expect_err("a free-form reason is refused");
        assert_eq!(
            error.message(),
            "protection signal reason_code must be a stable identifier"
        );
    }
    assert!(ProtectionSignal::new(ProtectionCheckStatus::Unknown, "proof_unavailable").is_ok());
}

#[test]
fn only_the_first_hundred_harnesses_are_reported_and_only_those_are_checked() {
    // Python slices before it validates, so a harness past the hundredth never
    // reaches the identity check. `zz-not-a-stable-id!` sorts last and so is
    // cut, and the report is built as if it had not been offered at all.
    let mut harnesses: BTreeMap<String, ProtectionSignal> = (0..100)
        .map(|index| (format!("h{index:03}"), proven()))
        .collect();
    harnesses.insert("zz-not-a-stable-id!".to_owned(), proven());

    let report = evaluate_protection_health(&every_check_proven(), &harnesses)
        .expect("the hundred-and-first harness is cut, not refused");
    assert_eq!(report.apps.len(), 100);
    assert_eq!(report.apps[0].harness, "h000");
    assert_eq!(report.apps[99].harness, "h099");
    assert_eq!(report.state, ProtectionState::Protected);

    // Offer the same bad name inside the first hundred and it is refused.
    let mut few: BTreeMap<String, ProtectionSignal> = BTreeMap::new();
    few.insert("zz-not-a-stable-id!".to_owned(), proven());
    let error = evaluate_protection_health(&every_check_proven(), &few)
        .expect_err("a reported harness must be named truthfully");
    assert_eq!(
        error.message(),
        "harness protection identity must be a stable identifier"
    );
}

#[test]
fn a_harness_name_is_measured_in_characters() {
    // Sixty-four is the longest name the report will carry.
    let longest = format!("h{}", "0".repeat(63));
    assert_eq!(longest.chars().count(), 64);
    let mut harnesses = BTreeMap::new();
    harnesses.insert(longest.clone(), proven());
    assert!(evaluate_protection_health(&every_check_proven(), &harnesses).is_ok());

    let mut harnesses = BTreeMap::new();
    harnesses.insert(format!("{longest}0"), proven());
    let error = evaluate_protection_health(&every_check_proven(), &harnesses)
        .expect_err("sixty-five is one too many");
    assert_eq!(
        error.message(),
        "harness protection identity must be a stable identifier"
    );
}

#[test]
fn an_unproven_check_is_never_read_as_a_pass() {
    let mut signals = every_check_proven();
    signals.remove("tamper_checks");
    let report = evaluate_protection_health(&signals, &BTreeMap::new()).expect("a report");
    assert_eq!(report.state, ProtectionState::Degraded);
    assert!(report.evidence_gap);
    let tamper = report
        .checks
        .iter()
        .find(|check| check.check_id == "tamper_checks")
        .expect("the check is still reported");
    assert_eq!(tamper.status, ProtectionCheckStatus::Unknown);
    assert_eq!(tamper.reason_code, "proof_unavailable");
}

#[test]
fn the_checks_keep_their_declared_order() {
    let report =
        evaluate_protection_health(&every_check_proven(), &BTreeMap::new()).expect("a report");
    let reported: Vec<&str> = report
        .checks
        .iter()
        .map(|check| check.check_id.as_str())
        .collect();
    assert_eq!(reported, PROTECTION_CHECK_IDS.to_vec());
}
