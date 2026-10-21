//! How a configured risk action resolves, including the per-harness Extra
//! careful floor `harness_posture.py` applies after the explicit maps.

use std::collections::BTreeMap;

use crate::local_supply_chain::{resolve_risk_action, GuardConfig};

fn actions(rows: &[(&str, &str)]) -> BTreeMap<String, String> {
    rows.iter()
        .map(|(key, action)| ((*key).to_owned(), (*action).to_owned()))
        .collect()
}

fn config(postures: &[(&str, &str)]) -> GuardConfig {
    GuardConfig {
        security_level: "balanced".to_owned(),
        protection_posture: "balanced".to_owned(),
        risk_actions: Some(actions(&[("package_script", "warn")])),
        harness_postures: (!postures.is_empty()).then(|| actions(postures)),
        ..GuardConfig::default()
    }
}

#[test]
fn an_explicit_action_wins_when_no_harness_is_on_extra_careful() {
    let config = config(&[]);
    assert_eq!(
        resolve_risk_action(&config, Some("package_script"), Some("codex")),
        Some("warn".to_owned())
    );
}

#[test]
fn extra_careful_raises_an_explicit_action_below_the_floor() {
    let config = config(&[("codex", "extra_careful")]);
    assert_eq!(
        resolve_risk_action(&config, Some("package_script"), Some("codex")),
        Some("require-reapproval".to_owned()),
        "the floor only ever strengthens"
    );
    assert_eq!(
        resolve_risk_action(&config, Some("package_script"), None),
        Some("warn".to_owned()),
        "a resolution without a harness carries no override"
    );
}

#[test]
fn extra_careful_leaves_an_action_above_the_floor_alone() {
    let mut config = config(&[("codex", "extra_careful")]);
    config.risk_actions = Some(actions(&[("package_script", "block")]));
    assert_eq!(
        resolve_risk_action(&config, Some("package_script"), Some("codex")),
        Some("block".to_owned())
    );
}

#[test]
fn a_harness_on_watch_keeps_its_configured_action() {
    let config = config(&[("codex", "watch")]);
    assert_eq!(
        resolve_risk_action(&config, Some("package_script"), Some("codex")),
        Some("warn".to_owned()),
        "only Extra careful carries a floor"
    );
}

#[test]
fn the_override_is_found_through_an_install_alias() {
    let config = config(&[("pi", "extra_careful")]);
    assert_eq!(
        resolve_risk_action(&config, Some("package_script"), Some("pi-agent")),
        Some("require-reapproval".to_owned()),
        "a stored canonical id answers for the alias the runtime reports"
    );
    assert_eq!(
        resolve_risk_action(&config, Some("package_script"), Some("cursor")),
        Some("warn".to_owned()),
        "the override names another harness"
    );
}

#[test]
fn an_unregistered_harness_matches_its_own_normalized_name() {
    let config = config(&[("house-agent", "extra_careful")]);
    assert_eq!(
        resolve_risk_action(&config, Some("package_script"), Some("House_Agent")),
        Some("require-reapproval".to_owned()),
        "runtime_harness_key falls back to the normalized name"
    );
}

#[test]
fn an_unknown_risk_class_resolves_to_nothing_even_on_extra_careful() {
    let config = config(&[("codex", "extra_careful")]);
    assert_eq!(
        resolve_risk_action(&config, Some("not_a_risk_class"), Some("codex")),
        None
    );
    assert_eq!(resolve_risk_action(&config, None, Some("codex")), None);
}
