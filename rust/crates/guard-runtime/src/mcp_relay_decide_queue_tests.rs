use super::*;
use crate::mcp_tool_policy_decision::Current;
use guard_command::effect_decision::GuardAction;
use serde_json::Map;

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
        route(&queued, &review),
        Ok(Routed::Queue {
            policy_action: "review".to_owned(),
        })
    );
    let unnamed = proxy(json!({"kind": "queue"}));
    assert_eq!(route(&unnamed, &review), Err(ROUTE_UNSUPPORTED));
    let mut pending = decision(GuardAction::Review);
    pending.pending = Some(Map::new());
    assert_eq!(route(&queued, &pending), Err(ROUTE_UNSUPPORTED));
    // The `ask` mode names a prompt need, which the resident cannot answer.
    let mut prompted = queued;
    prompted["route"]["need"] = json!({"kind": "native_prompt"});
    assert_eq!(route(&prompted, &review), Err(ROUTE_UNSUPPORTED));
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
