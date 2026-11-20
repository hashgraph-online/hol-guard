use super::configured_risk_action;
use guard_contracts::RiskActionConfigV1;

fn config() -> RiskActionConfigV1 {
    RiskActionConfigV1 {
        security_level: "balanced".to_owned(),
        protection_posture: "protected".to_owned(),
        protection_posture_explicit: false,
        ..Default::default()
    }
}

#[test]
fn an_explicit_risk_action_wins_over_the_defaults() {
    let mut facts = config();
    facts
        .risk_actions
        .insert("local_secret_read".to_owned(), "warn".to_owned());
    assert_eq!(
        configured_risk_action(&facts, "local_secret_read", None).as_deref(),
        Some("warn")
    );
}

#[test]
fn a_harness_risk_action_wins_over_the_global_one() {
    let mut facts = config();
    facts
        .risk_actions
        .insert("local_secret_read".to_owned(), "warn".to_owned());
    facts.harness_risk_actions.insert(
        "codex".to_owned(),
        [("local_secret_read".to_owned(), "block".to_owned())]
            .into_iter()
            .collect(),
    );
    assert_eq!(
        configured_risk_action(&facts, "local_secret_read", Some("codex")).as_deref(),
        Some("block")
    );
    assert_eq!(
        configured_risk_action(&facts, "local_secret_read", Some("cursor")).as_deref(),
        Some("warn")
    );
}

#[test]
fn an_extra_careful_harness_posture_only_strengthens() {
    let mut facts = config();
    facts
        .risk_actions
        .insert("local_secret_read".to_owned(), "warn".to_owned());
    facts
        .harness_postures
        .insert("codex".to_owned(), "extra_careful".to_owned());
    assert_eq!(
        configured_risk_action(&facts, "local_secret_read", Some("codex")).as_deref(),
        Some("require-reapproval")
    );
    assert_eq!(
        configured_risk_action(&facts, "local_secret_read", None).as_deref(),
        Some("warn")
    );
}

#[test]
fn a_locked_security_level_keeps_the_posture_defaults_out() {
    let mut explicit = config();
    explicit.security_level = "relaxed".to_owned();
    explicit.protection_posture_explicit = true;
    explicit.protection_posture = "extra_careful".to_owned();
    assert_eq!(
        configured_risk_action(&explicit, "local_secret_read", None).as_deref(),
        Some("require-reapproval")
    );

    let mut locked = explicit.clone();
    locked.managed_locked_settings = vec!["security_level".to_owned()];
    assert_eq!(
        configured_risk_action(&locked, "local_secret_read", None).as_deref(),
        Some("warn")
    );
}

#[test]
fn an_unknown_risk_class_resolves_to_nothing() {
    assert_eq!(
        configured_risk_action(&config(), "not_a_risk_class", None),
        None
    );
}
