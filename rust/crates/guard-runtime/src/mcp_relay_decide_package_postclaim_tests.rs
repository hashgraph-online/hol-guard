//! The route a claimed package call takes, against `_render_package_postclaim`.

use std::cell::Cell;

use super::*;
use crate::mcp_tool_policy_decision::Current;
use guard_command::effect_decision::GuardAction as EffectAction;
use guard_contracts::McpPackageFactsV1;
use serde_json::json;

/// The tool call's own re-read decision. `Decision::plain` composes no saved
/// authority, which is the allow the proxy re-resolves to when nothing about
/// the call changed.
fn tool(action: EffectAction) -> Decision {
    Decision::plain(Current {
        action,
        source: "policy".to_owned(),
        signals: Vec::new(),
        summary: "installs a package".to_owned(),
        risk_categories: Vec::new(),
    })
}

/// The boundary the claimed approval was taken at, re-read unchanged.
fn context() -> McpToolContextV1 {
    McpToolContextV1 {
        artifact_id: "codex:project:install_package".to_owned(),
        expected_artifact_id: "codex:project:install_package".to_owned(),
        artifact_hash: "guard-approval-context:v1:tool".to_owned(),
        expected_artifact_hash: "guard-approval-context:v1:tool".to_owned(),
    }
}

/// The freshly resolved package policy, at an unchanged boundary.
fn package(action: &str) -> McpPackagePostclaimFactsV1 {
    McpPackagePostclaimFactsV1 {
        facts: McpPackageFactsV1 {
            saved_policy_blocks: false,
            current_action: Some(action.to_owned()),
            policy_action: action.to_owned(),
            has_pending: false,
        },
        artifact_id: "package-request:npm:left-pad".to_owned(),
        expected_artifact_id: "package-request:npm:left-pad".to_owned(),
        digest: "guard-approval-context:v1:package".to_owned(),
        expected_digest: "guard-approval-context:v1:package".to_owned(),
        tool_claim_authorizes_review: true,
        package_claim_authorizes_review: true,
    }
}

/// A supply that records whether the resident ever asked for it.
struct Supply {
    asked: Cell<bool>,
    facts: McpPackagePostclaimFactsV1,
}

impl Supply {
    fn new(facts: McpPackagePostclaimFactsV1) -> Self {
        Self {
            asked: Cell::new(false),
            facts,
        }
    }

    fn take(&self) -> Result<McpPackagePostclaimFactsV1, &'static str> {
        self.asked.set(true);
        Ok(self.facts.clone())
    }
}

#[test]
fn an_unchanged_boundary_forwards_under_the_authoritative_action() {
    let supply = Supply::new(package("review"));
    let routed = postclaim(&tool(EffectAction::Review), context(), true, || {
        supply.take()
    })
    .expect("the claimed authority still covers the request");

    // `executed(action)`: a review both claims authorize is the allow the call
    // runs under, which is the action the forward is recorded with.
    assert_eq!(
        routed.decided,
        Decided::Package(PackageRoute::Forward {
            policy_action: "allow".to_owned()
        })
    );
    assert_eq!(routed.append, Vec::<Value>::new());
}

#[test]
fn a_stored_tool_block_stops_the_call_before_the_package_is_resolved() {
    let supply = Supply::new(package("allow"));
    let mut decision = tool(EffectAction::Allow);
    decision.saved_action = Some(EffectAction::Block);
    let routed =
        postclaim(&decision, context(), true, || supply.take()).expect("the stored block answers");

    assert_eq!(routed.decided, Decided::Tool(ToolLeg::StoredBlock));
    // The proxy's supply re-resolves the package policy with the external
    // archive network authorized. A call the tool half stops pays for none of
    // that fresh supply-chain evaluation.
    assert!(!supply.asked.get());
}

#[test]
fn a_terminal_tool_action_stops_the_call_before_the_package_is_resolved() {
    let supply = Supply::new(package("allow"));
    let routed = postclaim(&tool(EffectAction::Block), context(), true, || {
        supply.take()
    })
    .expect("the terminal tool action answers");

    assert_eq!(
        routed.decided,
        Decided::Tool(ToolLeg::Terminal {
            policy_action: "block".to_owned()
        })
    );
    assert!(!supply.asked.get());
}

#[test]
fn a_call_whose_package_request_no_longer_resolves_queues_the_tool_leg() {
    let supply = Supply::new(package("allow"));
    let routed = postclaim(&tool(EffectAction::Allow), context(), false, || {
        supply.take()
    })
    .expect("the unresolved package request queues");

    // `_queue_approval_center_response(policy_action="require-reapproval")`:
    // the action is the proxy's own literal, not one read off the answer.
    assert_eq!(
        routed.decided,
        Decided::Tool(ToolLeg::Queue {
            policy_action: "require-reapproval".to_owned()
        })
    );
    assert!(!supply.asked.get());
}

#[test]
fn a_tool_boundary_that_moved_queues_the_tool_leg_with_its_own_evidence() {
    let supply = Supply::new(package("allow"));
    let mut context = context();
    context.artifact_hash = "guard-approval-context:v1:moved".to_owned();
    let routed = postclaim(&tool(EffectAction::Allow), context, true, || supply.take())
        .expect("the moved boundary queues");

    assert_eq!(
        routed.decided,
        Decided::Tool(ToolLeg::Queue {
            policy_action: "require-reapproval".to_owned()
        })
    );
    // The tool half's queue is reached only after the package facts are
    // supplied, and its evidence is the tool half's, not the package's.
    assert!(supply.asked.get());
    assert_eq!(
        routed.append,
        vec![json!({
            "source": "approval_reuse",
            "status": "rejected",
            "reason_code": "approval_reuse_context_changed_after_claim",
            "context_matches": false,
            "current_action": "allow",
            "effective_action": "allow",
        })]
    );
}

#[test]
fn a_review_no_claim_authorizes_queues_the_half_the_claim_no_longer_covers() {
    let mut facts = package("review");
    facts.package_claim_authorizes_review = false;
    let supply = Supply::new(facts);
    let routed = postclaim(&tool(EffectAction::Allow), context(), true, || {
        supply.take()
    })
    .expect("the package half queues");

    assert_eq!(
        routed.decided,
        Decided::Package(PackageRoute::QueuePackage {
            policy_action: "require-reapproval".to_owned()
        })
    );
    assert_eq!(
        routed.append,
        vec![json!({
            "source": "approval_reuse",
            "status": "rejected",
            "reason_code": "approval_reuse_context_changed_after_claim",
            "context_matches": true,
            "claimed_authority_matches": false,
            "current_action": "review",
            "effective_action": "require-reapproval",
        })]
    );
}

#[test]
fn a_package_policy_that_now_blocks_stops_the_call_on_the_package_half() {
    let supply = Supply::new(package("block"));
    let routed = postclaim(&tool(EffectAction::Allow), context(), true, || {
        supply.take()
    })
    .expect("the terminal package action answers");

    assert_eq!(
        routed.decided,
        Decided::Package(PackageRoute::TerminalPackage {
            policy_action: "block".to_owned()
        })
    );
}

#[test]
fn a_saved_package_block_stops_the_call_on_its_own_row() {
    let mut facts = package("allow");
    facts.facts.saved_policy_blocks = true;
    let supply = Supply::new(facts);
    let routed = postclaim(&tool(EffectAction::Allow), context(), true, || {
        supply.take()
    })
    .expect("the stored package block answers");

    assert_eq!(
        routed.decided,
        Decided::Package(PackageRoute::StoredPackageBlock)
    );
}

#[test]
fn a_package_policy_the_resolve_could_not_supply_defers_the_call() {
    let routed = postclaim(&tool(EffectAction::Allow), context(), true, || {
        Err("mcp_relay_package_resolve_failed")
    });

    // The supply's own failure is the reason the call defers, not this port's.
    assert_eq!(routed, Err("mcp_relay_package_resolve_failed"));
}

#[test]
fn an_action_the_answer_cannot_name_defers_the_call() {
    let mut facts = package("allow");
    facts.facts.policy_action = "escalate".to_owned();
    let supply = Supply::new(facts);
    let routed = postclaim(&tool(EffectAction::Allow), context(), true, || {
        supply.take()
    });

    // `norm(policy_action, Block)`: an action the lattice does not recognize
    // is read as a block, which stops the call rather than forwarding it.
    assert_eq!(
        routed
            .expect("the unknown action is read as a block")
            .decided,
        Decided::Package(PackageRoute::TerminalPackage {
            policy_action: "block".to_owned()
        })
    );
}
