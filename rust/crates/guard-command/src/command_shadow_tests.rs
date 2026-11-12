use std::collections::{BTreeMap, BTreeSet};

use super::command_shadow::{
    command_shadow_comparison, disposition_matches, load_command_shadow_control, sample_bucket,
    CommandShadowCohort, CommandShadowComparison, COMMAND_SHADOW_CONTROL_SCHEMA_VERSION,
    COMMAND_SHADOW_DISABLED_COHORTS_ENV, COMMAND_SHADOW_ENABLED_ENV,
    COMMAND_SHADOW_KILL_SWITCH_ENV, COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV,
};
use super::effect_decision::{FinalDisposition, GuardAction};

fn control(pairs: &[(&str, &str)]) -> super::command_shadow::CommandShadowControl {
    let environment: BTreeMap<String, String> = pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    load_command_shadow_control(|key| environment.get(key).cloned())
}

fn cohorts(values: &[CommandShadowCohort]) -> BTreeSet<CommandShadowCohort> {
    values.iter().copied().collect()
}

#[test]
fn an_empty_environment_records_the_baseline_at_full_rate() {
    let control = control(&[]);
    assert!(control.enabled);
    assert!(!control.kill_switch);
    assert_eq!(control.sample_basis_points, 10_000);
    assert_eq!(
        control.release_cohorts,
        cohorts(&[CommandShadowCohort::Baseline])
    );
    assert!(control.disabled_cohorts.is_empty());
    assert_eq!(control.generation, 1);
    assert_eq!(
        control.schema_version,
        COMMAND_SHADOW_CONTROL_SCHEMA_VERSION
    );
}

#[test]
fn a_flag_it_cannot_read_fails_towards_recording_nothing() {
    // Enabling is the permissive direction, so anything unreadable is off.
    assert!(!control(&[(COMMAND_SHADOW_ENABLED_ENV, "true")]).enabled);
    assert!(!control(&[(COMMAND_SHADOW_ENABLED_ENV, "")]).enabled);
    // The kill switch is the restrictive direction, so anything unreadable trips it.
    assert!(control(&[(COMMAND_SHADOW_KILL_SWITCH_ENV, "yes")]).kill_switch);
    assert!(control(&[(COMMAND_SHADOW_KILL_SWITCH_ENV, "")]).kill_switch);
    assert!(!control(&[(COMMAND_SHADOW_KILL_SWITCH_ENV, "0")]).kill_switch);
}

#[test]
fn a_cohort_list_it_cannot_read_disables_every_cohort() {
    assert_eq!(
        control(&[(COMMAND_SHADOW_DISABLED_COHORTS_ENV, "nonsense")]).disabled_cohorts,
        super::command_shadow::ALL_COMMAND_SHADOW_COHORTS
            .into_iter()
            .collect()
    );
    // A trailing comma leaves an empty name, which is not a cohort either.
    assert_eq!(
        control(&[(COMMAND_SHADOW_DISABLED_COHORTS_ENV, "baseline,")]).disabled_cohorts,
        super::command_shadow::ALL_COMMAND_SHADOW_COHORTS
            .into_iter()
            .collect()
    );
    // The names are matched exactly; the enum has no case-insensitive lookup.
    assert_eq!(
        control(&[(COMMAND_SHADOW_DISABLED_COHORTS_ENV, "BASELINE")]).disabled_cohorts,
        super::command_shadow::ALL_COMMAND_SHADOW_COHORTS
            .into_iter()
            .collect()
    );
    // An empty list names no cohorts at all.
    assert!(control(&[(COMMAND_SHADOW_DISABLED_COHORTS_ENV, "")])
        .disabled_cohorts
        .is_empty());
}

#[test]
fn a_sampling_rate_outside_the_scale_stops_recording() {
    let rate =
        |raw: &str| control(&[(COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV, raw)]).sample_basis_points;
    assert_eq!(rate("0"), 0);
    assert_eq!(rate("10000"), 10_000);
    assert_eq!(rate("10001"), 0);
    assert_eq!(rate("-1"), 0);
    assert_eq!(rate("500.0"), 0);
    assert_eq!(rate("many"), 0);
    assert_eq!(rate(""), 0);
    assert_eq!(rate("0x10"), 0);
    // Python's `int()` reads these, so the Rust half must read them too.
    assert_eq!(rate("+500"), 500);
    assert_eq!(rate(" 500 "), 500);
    assert_eq!(rate("5_000"), 5_000);
}

#[test]
fn an_activity_id_that_is_not_opaque_is_refused() {
    for activity_id in ["", "-leading", ".leading", "has space", "has/slash", "café"] {
        let error = sample_bucket(CommandShadowCohort::Baseline, activity_id)
            .err()
            .unwrap_or_else(|| panic!("{activity_id:?} should be refused"));
        assert_eq!(error.message(), "activity_id must be an opaque identifier");
    }
    // 256 characters is the longest the pattern admits; 257 is one too many.
    assert!(sample_bucket(CommandShadowCohort::Baseline, &"a".repeat(256)).is_ok());
    assert!(sample_bucket(CommandShadowCohort::Baseline, &"a".repeat(257)).is_err());
}

#[test]
fn the_bucket_is_framed_so_no_two_pairs_can_collide_by_concatenation() {
    // "baseline" + "1x" and a cohort named "baseline1" + "x" would hash the
    // same without the lengths in front of each part.
    let first = sample_bucket(CommandShadowCohort::Baseline, "1x").expect("accepted");
    let second = sample_bucket(CommandShadowCohort::Baseline, "1").expect("accepted");
    assert_ne!(first, second);
    assert!(first < 10_000 && second < 10_000);
}

#[test]
fn nothing_is_selected_once_recording_is_off() {
    let proposal = cohorts(&[CommandShadowCohort::Baseline]);
    for pairs in [
        vec![(COMMAND_SHADOW_ENABLED_ENV, "0")],
        vec![(COMMAND_SHADOW_KILL_SWITCH_ENV, "1")],
        vec![(COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV, "0")],
    ] {
        assert!(control(&pairs)
            .selected_cohorts(&proposal, "activity-1")
            .expect("accepted")
            .is_empty());
    }
}

#[test]
fn only_cohorts_this_release_carries_and_the_rate_admits_are_selected() {
    let proposal = cohorts(&[
        CommandShadowCohort::Baseline,
        CommandShadowCohort::VerifiedReads,
    ]);
    // "activity-1" sits in bucket 3131 for the baseline cohort.
    let selected = control(&[(COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV, "3132")])
        .selected_cohorts(&proposal, "activity-1")
        .expect("accepted");
    assert_eq!(selected, vec![CommandShadowCohort::Baseline]);
    // One basis point lower and the same activity falls outside the sample.
    assert!(control(&[(COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV, "3131")])
        .selected_cohorts(&proposal, "activity-1")
        .expect("accepted")
        .is_empty());
    // A cohort an operator switched off is never selected.
    assert!(
        control(&[(COMMAND_SHADOW_DISABLED_COHORTS_ENV, "baseline")])
            .selected_cohorts(&proposal, "activity-1")
            .expect("accepted")
            .is_empty()
    );
}

#[test]
fn a_selection_refuses_an_activity_id_rather_than_bucketing_it() {
    let error = control(&[])
        .selected_cohorts(&cohorts(&[CommandShadowCohort::Baseline]), "has space")
        .expect_err("a malformed id is refused");
    assert_eq!(error.message(), "activity_id must be an opaque identifier");
}

#[test]
fn the_comparison_reads_off_the_severity_lattice() {
    assert_eq!(
        command_shadow_comparison(GuardAction::Review, GuardAction::Allow),
        CommandShadowComparison::Lowered
    );
    assert_eq!(
        command_shadow_comparison(GuardAction::Review, GuardAction::Review),
        CommandShadowComparison::Unchanged
    );
    assert_eq!(
        command_shadow_comparison(GuardAction::Review, GuardAction::Block),
        CommandShadowComparison::Strengthened
    );
    assert_eq!(CommandShadowComparison::Lowered.as_str(), "lowered");
    assert_eq!(CommandShadowComparison::Unchanged.as_str(), "unchanged");
    assert_eq!(
        CommandShadowComparison::Strengthened.as_str(),
        "strengthened"
    );
}

#[test]
fn allow_carries_the_three_silent_routes_and_nothing_else() {
    for disposition in [
        FinalDisposition::SilentVerified,
        FinalDisposition::SilentContained,
        FinalDisposition::WorkflowAuthorized,
    ] {
        assert!(disposition_matches(GuardAction::Allow, disposition));
    }
    assert!(!disposition_matches(
        GuardAction::Allow,
        FinalDisposition::Review
    ));
    assert!(disposition_matches(
        GuardAction::Review,
        FinalDisposition::Review
    ));
    assert!(!disposition_matches(
        GuardAction::Review,
        FinalDisposition::SilentVerified
    ));
    assert!(!disposition_matches(
        GuardAction::Block,
        FinalDisposition::Warn
    ));
}

#[test]
fn every_cohort_round_trips_through_its_wire_name() {
    for cohort in super::command_shadow::ALL_COMMAND_SHADOW_COHORTS {
        assert_eq!(
            CommandShadowCohort::from_value(cohort.as_str()),
            Some(cohort)
        );
    }
    assert_eq!(CommandShadowCohort::from_value("cdx-067"), None);
    // The wire names sort the way the variants are ordered, which is what lets
    // a `BTreeSet` stand in for Python's `sorted(..., key=attrgetter("value"))`.
    let mut names: Vec<&str> = super::command_shadow::ALL_COMMAND_SHADOW_COHORTS
        .iter()
        .map(|cohort| cohort.as_str())
        .collect();
    let declared = names.clone();
    names.sort_unstable();
    assert_eq!(names, declared);
}
