//! Replay the shadow rollout decisions Python recorded.
//!
//! Every row in the fixture came out of `command_shadow_evaluation`, so a
//! disagreement here is a real divergence between the two halves rather than a
//! difference of opinion about what the controls ought to mean.

use std::collections::{BTreeMap, BTreeSet};

use guard_command::command_shadow::{
    command_shadow_comparison, disposition_matches, load_command_shadow_control, sample_bucket,
    CommandShadowCohort, COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV,
};
use guard_command::effect_decision::{FinalDisposition, GuardAction};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../../tests/fixtures/guard-command-shadow.v1.json");

fn text<'a>(row: &'a Value, field: &str) -> &'a str {
    row.get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("row is missing {field}"))
}

fn cohort(value: &str) -> CommandShadowCohort {
    CommandShadowCohort::from_value(value).unwrap_or_else(|| panic!("unknown cohort {value}"))
}

fn action(value: &str) -> GuardAction {
    serde_json::from_value(Value::String(value.to_owned()))
        .unwrap_or_else(|_| panic!("unknown action {value}"))
}

fn disposition(value: &str) -> FinalDisposition {
    serde_json::from_value(Value::String(value.to_owned()))
        .unwrap_or_else(|_| panic!("unknown disposition {value}"))
}

fn names(values: &Value, field: &str) -> Vec<String> {
    values
        .get(field)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("row is missing {field}"))
        .iter()
        .map(|value| value.as_str().expect("cohort name").to_owned())
        .collect()
}

/// The recorded environment, as the loader's lookup.
fn environment(row: &Value) -> BTreeMap<String, String> {
    row.get("env")
        .and_then(Value::as_object)
        .expect("row is missing env")
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                value.as_str().expect("env values are text").to_owned(),
            )
        })
        .collect()
}

fn rows<'a>(document: &'a Value, field: &str) -> &'a Vec<Value> {
    document[field]
        .as_array()
        .unwrap_or_else(|| panic!("fixture is missing {field}"))
}

fn fixture() -> Value {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    assert_eq!(
        document["schema"], "guard-command-shadow-parity.v1",
        "fixture schema moved"
    );
    document
}

#[test]
fn recorded_sample_buckets_replay() {
    let document = fixture();
    let buckets = rows(&document, "buckets");
    assert!(!buckets.is_empty(), "fixture records no buckets");
    for row in buckets {
        let activity_id = text(row, "activity_id");
        let name = text(row, "cohort");
        let expected = row["bucket"].as_u64().expect("bucket") as u32;
        assert_eq!(
            sample_bucket(cohort(name), activity_id).expect("recorded ids are accepted"),
            expected,
            "bucket for {name} / {activity_id} disagrees with Python"
        );
    }
}

#[test]
fn recorded_activity_id_rejections_replay() {
    let document = fixture();
    let rejected = rows(&document, "rejected_activity_ids");
    assert!(!rejected.is_empty(), "fixture records no rejections");
    for row in rejected {
        let activity_id = text(row, "activity_id");
        let error = sample_bucket(CommandShadowCohort::Baseline, activity_id)
            .err()
            .unwrap_or_else(|| panic!("{activity_id:?} should be refused"));
        assert_eq!(error.message(), text(row, "error"));
    }
}

#[test]
fn recorded_controls_replay() {
    let document = fixture();
    let controls = rows(&document, "controls");
    assert!(!controls.is_empty(), "fixture records no controls");
    for row in controls {
        let environ = environment(row);
        let control = load_command_shadow_control(|key| environ.get(key).cloned());
        assert_eq!(
            control.enabled,
            row["enabled"].as_bool().expect("enabled"),
            "enabled disagrees for {environ:?}"
        );
        assert_eq!(
            control.kill_switch,
            row["kill_switch"].as_bool().expect("kill_switch"),
            "kill_switch disagrees for {environ:?}"
        );
        let release: Vec<String> = control
            .release_cohorts
            .iter()
            .map(|cohort| cohort.as_str().to_owned())
            .collect();
        assert_eq!(release, names(row, "release_cohorts"));
        let disabled: Vec<String> = control
            .disabled_cohorts
            .iter()
            .map(|cohort| cohort.as_str().to_owned())
            .collect();
        assert_eq!(
            disabled,
            names(row, "disabled_cohorts"),
            "disabled cohorts disagree for {environ:?}"
        );
        assert_eq!(
            u64::from(control.sample_basis_points),
            row["sample_basis_points"].as_u64().expect("basis points"),
            "sampling rate disagrees for {environ:?}"
        );
        assert_eq!(
            u64::from(control.generation),
            row["generation"].as_u64().expect("generation")
        );
        assert_eq!(control.schema_version, text(row, "schema_version"));
    }
}

#[test]
fn recorded_cohort_selections_replay() {
    let document = fixture();
    let selections = rows(&document, "selections");
    assert!(!selections.is_empty(), "fixture records no selections");
    let mut recorded_any = false;
    for row in selections {
        let environ = environment(row);
        let control = load_command_shadow_control(|key| environ.get(key).cloned());
        let proposal: BTreeSet<CommandShadowCohort> = names(row, "proposal_cohorts")
            .iter()
            .map(|name| cohort(name.as_str()))
            .collect();
        let activity_id = text(row, "activity_id");
        let selected: Vec<String> = control
            .selected_cohorts(&proposal, activity_id)
            .expect("recorded ids are accepted")
            .into_iter()
            .map(|cohort| cohort.as_str().to_owned())
            .collect();
        let expected = names(row, "selected");
        recorded_any |= !expected.is_empty();
        assert_eq!(
            selected, expected,
            "selection disagrees for {environ:?} / {activity_id}"
        );
    }
    assert!(
        recorded_any,
        "the fixture must keep recording selections that sample in"
    );
}

#[test]
fn recorded_comparisons_replay() {
    let document = fixture();
    let comparisons = rows(&document, "comparisons");
    assert!(!comparisons.is_empty(), "fixture records no comparisons");
    for row in comparisons {
        let current = text(row, "current");
        let proposed = text(row, "proposed");
        assert_eq!(
            command_shadow_comparison(action(current), action(proposed)).as_str(),
            text(row, "comparison"),
            "comparison disagrees for {current} -> {proposed}"
        );
    }
}

#[test]
fn recorded_disposition_matches_replay() {
    let document = fixture();
    let dispositions = rows(&document, "dispositions");
    assert!(!dispositions.is_empty(), "fixture records no dispositions");
    for row in dispositions {
        let action_name = text(row, "action");
        let disposition_name = text(row, "disposition");
        assert_eq!(
            disposition_matches(action(action_name), disposition(disposition_name)),
            row["matches"].as_bool().expect("matches"),
            "disposition match disagrees for {action_name} / {disposition_name}"
        );
    }
}

#[test]
fn the_fixture_keeps_the_sampling_rates_the_two_halves_read_differently() {
    // Python's `int()` reads any Unicode decimal digit and this parser reads
    // ASCII, so a rate spelled in another script has to come to nothing on both
    // sides. Padding already agreed: the characters `str.strip()` removes and
    // `str::trim` leaves behind are the ones `int()` itself refuses.
    let document = fixture();
    let rates: BTreeMap<&str, u64> = rows(&document, "controls")
        .iter()
        .filter_map(|row| {
            let raw = row["env"]
                .get(COMMAND_SHADOW_SAMPLE_BASIS_POINTS_ENV)?
                .as_str()?;
            Some((
                raw,
                row["sample_basis_points"].as_u64().expect("basis points"),
            ))
        })
        .collect();
    for spelling in [
        "\u{ff15}\u{ff10}\u{ff10}",
        "\u{665}\u{660}\u{660}",
        "\u{665}00",
        "\u{1f}500",
    ] {
        assert_eq!(
            rates.get(spelling),
            Some(&0),
            "{spelling:?} should sample nothing"
        );
    }
    assert_eq!(rates.get("\u{a0}500\u{a0}"), Some(&500));
    assert_eq!(rates.get("1_000"), Some(&1000));
}
