use super::low_trust_floor;
use guard_contracts::{ConsumerLowTrustFloorQueryV1, RiskActionConfigV1};
use serde_json::{json, Value};

fn config() -> RiskActionConfigV1 {
    RiskActionConfigV1 {
        security_level: "balanced".to_owned(),
        protection_posture: "protected".to_owned(),
        protection_posture_explicit: false,
        ..Default::default()
    }
}

/// A fresh, unconfigured plugin: the one shape that reaches a lookup.
fn query(config: RiskActionConfigV1) -> ConsumerLowTrustFloorQueryV1 {
    ConsumerLowTrustFloorQueryV1 {
        risk_action_config: config,
        harness: json!("codex"),
        artifact_type: json!("plugin"),
        artifact_id: "codex:global:plugin:helper".to_owned(),
        artifact_name: "helper".to_owned(),
        configured_action: Value::Null,
        fresh_decision: true,
        trust_score: None,
    }
}

fn none() -> Value {
    json!({"score_required": false, "floor": null})
}

#[test]
fn a_fresh_unconfigured_plugin_asks_for_its_score() {
    assert_eq!(
        low_trust_floor(&query(config())),
        json!({"score_required": true, "floor": null})
    );
}

#[test]
fn a_configured_artifact_keeps_its_action_without_a_lookup() {
    let mut request = query(config());
    request.configured_action = json!("allow");
    assert_eq!(low_trust_floor(&request), none());
}

#[test]
fn an_unchanged_artifact_is_not_scored() {
    let mut request = query(config());
    request.fresh_decision = false;
    assert_eq!(low_trust_floor(&request), none());
}

#[test]
fn an_artifact_type_the_registry_cannot_score_is_not_looked_up() {
    for kind in [json!("command"), json!("hook"), json!(null), json!(7)] {
        let mut request = query(config());
        request.artifact_type = kind.clone();
        assert_eq!(low_trust_floor(&request), none(), "{kind}");
    }
}

#[test]
fn every_scored_artifact_type_reaches_a_lookup() {
    for kind in ["skill", "skill_file", "mcp_server", "plugin", "extension"] {
        let mut request = query(config());
        request.artifact_type = json!(kind);
        assert_eq!(
            low_trust_floor(&request),
            json!({"score_required": true, "floor": null}),
            "{kind}"
        );
    }
}

#[test]
fn an_allowed_risk_class_skips_the_lookup() {
    let mut facts = config();
    facts
        .risk_actions
        .insert("low_trust_artifact".to_owned(), "allow".to_owned());
    assert_eq!(low_trust_floor(&query(facts)), none());
}

#[test]
fn a_trusted_score_adds_no_floor() {
    for score in [80, 97, 100] {
        let mut request = query(config());
        request.trust_score = Some(score);
        assert_eq!(low_trust_floor(&request), none(), "{score}");
    }
}

#[test]
fn a_low_score_raises_the_configured_action() {
    let mut request = query(config());
    request.trust_score = Some(42);
    let answer = low_trust_floor(&request);
    assert_eq!(answer["score_required"], json!(false));
    let floor = &answer["floor"];
    assert_eq!(floor["action"], json!("require-reapproval"));
    assert_eq!(floor["score"], json!(42));
    assert_eq!(
        floor["signal"]["signal_id"],
        json!("low_trust_artifact:codex:global:plugin:helper")
    );
    assert_eq!(floor["signal"]["category"], json!("publisher"));
    assert_eq!(floor["signal"]["severity"], json!("medium"));
    assert_eq!(floor["signal"]["confidence"], json!("likely"));
    assert_eq!(floor["signal"]["detector"], json!("hol_registry_trust"));
    assert_eq!(
        floor["signal"]["title"],
        json!("Low HOL Registry trust score")
    );
    assert_eq!(
        floor["signal"]["plain_reason"],
        json!(
            "helper has a HOL Registry trust score of 42, below the 80 Guard asks you to review."
        )
    );
    assert_eq!(
        floor["signal"]["technical_detail"],
        json!("registry trust score 42 < 80")
    );
    assert_eq!(floor["signal"]["redaction_level"], json!("none"));
    assert_eq!(floor["signal"]["evidence_ref"], json!(null));
    assert_eq!(floor["signal"]["advisory_id"], json!(null));
}

#[test]
fn a_harness_risk_action_decides_the_floor() {
    let mut facts = config();
    facts.harness_risk_actions.insert(
        "codex".to_owned(),
        [("low_trust_artifact".to_owned(), "block".to_owned())]
            .into_iter()
            .collect(),
    );
    let mut request = query(facts);
    request.trust_score = Some(42);
    assert_eq!(low_trust_floor(&request)["floor"]["action"], json!("block"));

    let mut other = request.clone();
    other.harness = json!("cursor");
    assert_eq!(
        low_trust_floor(&other)["floor"]["action"],
        json!("require-reapproval")
    );
}

#[test]
fn an_extra_careful_harness_posture_strengthens_the_floor() {
    let mut facts = config();
    facts.security_level = "relaxed".to_owned();
    facts
        .harness_postures
        .insert("codex".to_owned(), "extra_careful".to_owned());
    let mut request = query(facts);
    request.trust_score = Some(42);
    assert_eq!(
        low_trust_floor(&request)["floor"]["action"],
        json!("require-reapproval")
    );

    let mut other = request.clone();
    other.harness = json!("cursor");
    assert_eq!(low_trust_floor(&other)["floor"]["action"], json!("warn"));
}

#[test]
fn an_unknown_harness_falls_back_to_the_global_action() {
    let mut request = query(config());
    request.harness = Value::Null;
    request.trust_score = Some(42);
    assert_eq!(
        low_trust_floor(&request)["floor"]["action"],
        json!("require-reapproval")
    );
}
