use super::*;
use crate::mcp_tool_policy_decision::Current;
use guard_command::effect_decision::GuardAction;
use serde_json::{json, Map};

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/mcp_relay/safe_alternative_block_vectors.json");

fn decision(action: GuardAction) -> Decision {
    Decision::plain(Current {
        action,
        source: "policy".to_owned(),
        signals: Vec::new(),
        summary: String::new(),
        risk_categories: Vec::new(),
    })
}

fn proxy(route: Value) -> Value {
    json!({
        "gate": {"disable": false},
        "route": {
            "need": null,
            "decision_override": null,
            "tool_policy_action": "review",
            "route": route,
        },
    })
}

#[test]
fn route_queues_a_decided_call_with_its_policy_action() {
    let review = decision(GuardAction::Review);
    let queued = proxy(json!({"kind": "queue", "policy_action": "review"}));
    assert_eq!(
        route(&queued, &review, None),
        Ok(Routed::Queue {
            policy_action: "review".to_owned(),
        })
    );
    let unnamed = proxy(json!({"kind": "queue"}));
    assert_eq!(route(&unnamed, &review, None), Err(ROUTE_UNSUPPORTED));
    let mut pending = decision(GuardAction::Review);
    pending.pending = Some(Map::new());
    assert_eq!(route(&queued, &pending, None), Err(ROUTE_UNSUPPORTED));
    // The `ask` mode names a prompt need, which the resident cannot answer.
    let mut prompted = queued;
    prompted["route"]["need"] = json!({"kind": "native_prompt"});
    assert_eq!(route(&prompted, &review, None), Err(ROUTE_UNSUPPORTED));
}

#[test]
fn only_a_bound_safe_alternative_mode_blocks_in_place() {
    let blocked = |mode: Option<&str>, level: Option<&str>| {
        safe_alternative(mode, level, "require-reapproval".to_owned())
    };
    assert_eq!(
        blocked(Some("safe-alternative"), Some("partial")),
        Ok(Routed::SafeAlternative {
            policy_action: "require-reapproval".to_owned(),
            redaction_level: "partial".to_owned(),
        })
    );
    assert_eq!(blocked(Some("ask"), Some("full")), Err(ROUTE_UNSUPPORTED));
    assert_eq!(blocked(None, Some("full")), Err(ROUTE_UNSUPPORTED));
    assert_eq!(
        blocked(Some("safe-alternative"), None),
        Err(ROUTE_UNSUPPORTED)
    );
}

#[test]
fn the_block_matches_the_proxy_vectors() {
    let fixture: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for vector in vectors {
        let signals: Vec<String> = vector["signals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|signal| signal.as_str().unwrap().to_owned())
            .collect();
        let (message, data) = safe_alternative_block(
            vector["tool"].as_str().unwrap(),
            vector["server"].as_str().unwrap(),
            &signals,
        );
        assert_eq!(message, vector["message"], "{}", vector["name"]);
        assert_eq!(data, fixture["data"], "{}", vector["name"]);
    }
}

#[test]
fn the_relay_gathers_the_inline_prompt_and_no_other_need() {
    let review = decision(GuardAction::Review);
    let mut asked = proxy(json!({}));
    asked["route"]["need"] = json!("inline_approval");
    assert_eq!(route(&asked, &review, None), Ok(Routed::Elicit));
    let mut held = asked;
    // Every other need is a fact only the Python proxy holds.
    held["route"]["need"] = json!("package_policy");
    assert_eq!(route(&held, &review, None), Err(ROUTE_UNSUPPORTED));
}

#[test]
fn a_refused_prompt_blocks_with_its_own_reason() {
    let review = decision(GuardAction::Review);
    let denied = proxy(json!({"kind": "inline_denied"}));
    assert_eq!(
        route(&denied, &review, Some(inline::Reply::Denied)),
        Ok(Routed::InlineDenied {
            source: inline::DENIED_SOURCE,
        })
    );
    assert_eq!(
        route(&denied, &review, Some(inline::Reply::Invalid)),
        Ok(Routed::InlineDenied {
            source: inline::INVALID_SOURCE,
        })
    );
    // The block names the reply the relay classified, so a route without one,
    // or with a reply that refused nothing, is not a block the proxy writes.
    assert_eq!(route(&denied, &review, None), Err(ROUTE_UNSUPPORTED));
    assert_eq!(
        route(&denied, &review, Some(inline::Reply::Allow)),
        Err(ROUTE_UNSUPPORTED)
    );
    let mut pending = decision(GuardAction::Review);
    pending.pending = Some(Map::new());
    assert_eq!(
        route(&denied, &pending, Some(inline::Reply::Denied)),
        Err(ROUTE_UNSUPPORTED)
    );
}

#[test]
fn only_an_approved_prompt_saves_the_allow_it_forwards() {
    let review = decision(GuardAction::Review);
    let forward = |source: &str, remember: Value| {
        let mut route = json!({
            "kind": "allow_and_forward",
            "decision_source": source,
            "policy_action": "allow",
        });
        if !remember.is_null() {
            route["remember"] = remember;
        }
        proxy(route)
    };
    assert_eq!(
        route(
            &forward(INLINE_APPROVED_SOURCE, json!(true)),
            &review,
            Some(inline::Reply::Allow)
        ),
        Ok(Routed::Forward {
            source: INLINE_APPROVED_SOURCE.to_owned(),
            policy_action: "allow".to_owned(),
            remember: true,
        })
    );
    assert_eq!(
        route(&forward("policy", json!(false)), &review, None),
        Ok(Routed::Forward {
            source: "policy".to_owned(),
            policy_action: "allow".to_owned(),
            remember: false,
        })
    );
    // `remember=True` belongs to the inline prompt alone, and a forward that
    // says nothing either way is a route the resident has not seen.
    assert_eq!(
        route(&forward("policy", json!(true)), &review, None),
        Err(ROUTE_UNSUPPORTED)
    );
    assert_eq!(
        route(&forward(INLINE_APPROVED_SOURCE, Value::Null), &review, None),
        Err(ROUTE_UNSUPPORTED)
    );
}
