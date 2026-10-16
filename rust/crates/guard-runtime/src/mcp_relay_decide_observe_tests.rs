use super::super::route;
use super::*;
use crate::mcp_tool_policy_decision::Current;
use guard_command::effect_decision::GuardAction;
use serde_json::Map;

fn decision(action: GuardAction) -> Decision {
    Decision::plain(Current {
        action,
        source: "policy".to_owned(),
        signals: Vec::new(),
        summary: String::new(),
        risk_categories: Vec::new(),
    })
}

/// A decision that would claim a pending saved approval, over a current
/// policy recommendation of `current`.
fn pending(current: GuardAction) -> Decision {
    let mut pending = decision(GuardAction::Allow);
    pending.source = "approval-reuse".to_owned();
    pending.current_action = Some(current);
    pending.saved_action = Some(GuardAction::Allow);
    pending.pending = Some(Map::new());
    pending
}

fn proxy(route: Value, decision_override: Value) -> Value {
    json!({
        "gate": {"disable": false},
        "route": {
            "need": null,
            "decision_override": decision_override,
            "tool_policy_action": "review",
            "route": route,
        },
    })
}

fn observe_route() -> Value {
    json!({"kind": "observe_forward"})
}

#[test]
fn no_override_leaves_the_decision_and_payload_alone() {
    let payload = proxy(observe_route(), Value::Null);
    let (taken, downgraded) =
        downgrade(payload.clone(), "observe", &decision(GuardAction::Review)).unwrap();
    assert_eq!(taken, payload);
    assert!(downgraded.is_none());
}

#[test]
fn the_observe_downgrade_presents_the_current_policy() {
    let overridden = json!({"action": "review", "source": "observe-current-policy"});
    let payload = proxy(observe_route(), overridden);
    let (taken, downgraded) = downgrade(payload, "observe", &pending(GuardAction::Review)).unwrap();
    assert!(taken["route"]["decision_override"].is_null());
    let downgraded = downgraded.unwrap();
    assert_eq!(downgraded.action, GuardAction::Review);
    assert_eq!(downgraded.source, "observe-current-policy");
    assert!(downgraded.pending.is_none());
    assert!(downgraded.claim_disposition.is_none());
    // `replace()` keeps every other field of the decision.
    assert_eq!(downgraded.current_action, Some(GuardAction::Review));
    assert_eq!(downgraded.saved_action, Some(GuardAction::Allow));
    // The taken payload routes the downgraded decision.
    assert_eq!(route(&taken, &downgraded, None), Ok(Routed::ObserveForward));
}

#[test]
fn any_other_override_defers() {
    let exact = json!({"action": "review", "source": "observe-current-policy"});
    let defers = |payload: Value, mode: &str, decision: &Decision| {
        downgrade(payload, mode, decision).map(|(_, downgraded)| downgraded.is_some())
    };
    let review = pending(GuardAction::Review);
    assert_eq!(
        defers(proxy(observe_route(), exact.clone()), "enforce", &review),
        Err(ROUTE_UNSUPPORTED)
    );
    let mismatched = json!({"action": "block", "source": "observe-current-policy"});
    assert_eq!(
        defers(proxy(observe_route(), mismatched), "observe", &review),
        Err(ROUTE_UNSUPPORTED)
    );
    let unsourced = json!({"action": "review", "source": "policy"});
    assert_eq!(
        defers(proxy(observe_route(), unsourced), "observe", &review),
        Err(ROUTE_UNSUPPORTED)
    );
    let mut settled = review.clone();
    settled.pending = None;
    assert_eq!(
        defers(proxy(observe_route(), exact.clone()), "observe", &settled),
        Err(ROUTE_UNSUPPORTED)
    );
    let mut unknown = review;
    unknown.current_action = None;
    assert_eq!(
        defers(proxy(observe_route(), exact), "observe", &unknown),
        Err(ROUTE_UNSUPPORTED)
    );
}

#[test]
fn route_takes_observe_forward_only_without_a_pending_approval() {
    let payload = proxy(observe_route(), Value::Null);
    assert_eq!(
        route(&payload, &decision(GuardAction::Review), None),
        Ok(Routed::ObserveForward)
    );
    assert_eq!(
        route(&payload, &pending(GuardAction::Review), None),
        Err(ROUTE_UNSUPPORTED)
    );
    // An override left in the payload is never routed past.
    let overridden = proxy(
        observe_route(),
        json!({"action": "review", "source": "observe-current-policy"}),
    );
    assert_eq!(
        route(&overridden, &decision(GuardAction::Review), None),
        Err(ROUTE_UNSUPPORTED)
    );
}

#[test]
fn an_observed_review_forwards_as_allow_with_the_observe_mode_item() {
    let (routed, append) =
        forward(Some("safe-alternative"), &decision(GuardAction::Review)).unwrap();
    assert_eq!(
        routed,
        Routed::Forward {
            source: "policy-observe".to_owned(),
            policy_action: "allow".to_owned(),
            remember: false,
        }
    );
    assert_eq!(
        append,
        Some(vec![json!({
            "source": "observe_mode",
            "observed_policy_action": "review",
            "authoritative_action": "allow",
        })])
    );
}

#[test]
fn the_observed_action_is_the_current_policy_before_the_decision() {
    // `fresh.current_action or fresh.action`.
    let mut decided = decision(GuardAction::Allow);
    decided.current_action = Some(GuardAction::RequireReapproval);
    let (_, append) = forward(Some("safe-alternative"), &decided).unwrap();
    assert_eq!(
        append.unwrap()[0]["observed_policy_action"],
        json!("require-reapproval")
    );
}

#[test]
fn a_permitted_observed_action_forwards_as_itself_with_no_evidence() {
    let (routed, append) = forward(Some("safe-alternative"), &decision(GuardAction::Warn)).unwrap();
    assert_eq!(
        routed,
        Routed::Forward {
            source: "policy-observe".to_owned(),
            policy_action: "warn".to_owned(),
            remember: false,
        }
    );
    assert_eq!(append, None);
}

#[test]
fn an_observed_call_under_any_other_blocked_request_mode_defers() {
    let review = decision(GuardAction::Review);
    assert_eq!(forward(Some("ask"), &review), Err(ROUTE_UNSUPPORTED));
    assert_eq!(forward(None, &review), Err(ROUTE_UNSUPPORTED));
}
