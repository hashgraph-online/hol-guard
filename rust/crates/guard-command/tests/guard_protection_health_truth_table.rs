//! Every combination of check statuses, and the bound on how many harnesses a
//! report may name.
//!
//! The exhaustive table is the coverage Python's
//! `test_exhaustive_check_truth_table_is_monotonic` carried before the verdict
//! moved here: a machine is protected only when every core check has proof, a
//! missing decision stream is the one gap that leaves it partial, and anything
//! else is degraded.

use std::collections::BTreeMap;

use guard_command::protection_health::{
    evaluate_protection_health, ProtectionCheckStatus, ProtectionSignal, ProtectionState,
    PROTECTION_CHECK_IDS,
};

const STATUSES: [ProtectionCheckStatus; 3] = [
    ProtectionCheckStatus::Pass,
    ProtectionCheckStatus::Unknown,
    ProtectionCheckStatus::Fail,
];

fn word(status: ProtectionCheckStatus) -> &'static str {
    match status {
        ProtectionCheckStatus::Pass => "pass",
        ProtectionCheckStatus::Unknown => "unknown",
        ProtectionCheckStatus::Fail => "fail",
    }
}

/// A reason code that names the status, so no row can plead an unsupported
/// platform and every row stays a stable identifier.
fn signal(check_id: &str, status: ProtectionCheckStatus) -> ProtectionSignal {
    ProtectionSignal::new(status, &format!("{check_id}_{}", word(status)))
        .expect("the reason code is a stable identifier")
}

#[test]
fn every_combination_of_check_statuses_lands_where_the_grammar_says() {
    let evidence_index = PROTECTION_CHECK_IDS
        .iter()
        .position(|check_id| *check_id == "decision_stream")
        .expect("the evidence check is named");

    let mut combination = [ProtectionCheckStatus::Pass; 9];
    let total = 3usize.pow(9);
    for ordinal in 0..total {
        let mut remainder = ordinal;
        for slot in combination.iter_mut() {
            *slot = STATUSES[remainder % 3];
            remainder /= 3;
        }

        let signals: BTreeMap<String, ProtectionSignal> = PROTECTION_CHECK_IDS
            .iter()
            .zip(combination.iter())
            .map(|(check_id, status)| ((*check_id).to_owned(), signal(check_id, *status)))
            .collect();

        let core_all_pass = combination.iter().enumerate().all(|(index, status)| {
            index == evidence_index || *status == ProtectionCheckStatus::Pass
        });
        let expected = if core_all_pass {
            match combination[evidence_index] {
                ProtectionCheckStatus::Pass => ProtectionState::Protected,
                ProtectionCheckStatus::Unknown => ProtectionState::Partial,
                ProtectionCheckStatus::Fail => ProtectionState::Degraded,
            }
        } else {
            ProtectionState::Degraded
        };

        let report = evaluate_protection_health(&signals, &BTreeMap::new())
            .expect("every check is named and every reason code is stable");
        assert_eq!(
            report.state, expected,
            "combination {combination:?} reports the wrong state"
        );
        assert_eq!(
            report.evidence_gap,
            combination.contains(&ProtectionCheckStatus::Unknown),
            "combination {combination:?} disagrees with its own evidence gap"
        );
    }
}

#[test]
fn a_report_names_at_most_a_hundred_harnesses() {
    let signals: BTreeMap<String, ProtectionSignal> = PROTECTION_CHECK_IDS
        .iter()
        .map(|check_id| {
            (
                (*check_id).to_owned(),
                signal(check_id, ProtectionCheckStatus::Pass),
            )
        })
        .collect();
    let harness_signals: BTreeMap<String, ProtectionSignal> = (0..120)
        .map(|index| {
            (
                format!("app-{index:03}"),
                signal("harness_hooks", ProtectionCheckStatus::Pass),
            )
        })
        .collect();

    let report = evaluate_protection_health(&signals, &harness_signals)
        .expect("a hundred and twenty well-named harnesses are not a refusal");
    assert_eq!(report.apps.len(), 100, "the harness bound moved");
    assert_eq!(
        report.apps[0].harness, "app-000",
        "the kept hundred are the first in order"
    );
}
