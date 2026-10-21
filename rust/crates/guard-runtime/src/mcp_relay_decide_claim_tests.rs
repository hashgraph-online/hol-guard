use super::*;
use crate::mcp_tool_policy_decision::{Current, Decision};
use guard_command::effect_decision::GuardAction;
use guard_contracts::{McpToolCallArtifactV1, McpToolCallIdentityPayloadV1};
use serde_json::Map;
use std::io::Write;

const ARTIFACT: &str = "codex:project:files:read";
const HASH: &str = "guard-approval-context:v1:relay";

fn claimed(disposition: Disposition) -> Claimed {
    Claimed {
        artifact_id: ARTIFACT.to_owned(),
        artifact_hash: HASH.to_owned(),
        pending: Map::new(),
        disposition: Some(disposition),
        source: "policy".to_owned(),
        policy_action: "allow".to_owned(),
    }
}

fn fresh(action: GuardAction, artifact_hash: &str) -> Resolved {
    let decision = Decision::plain(Current {
        action,
        source: "policy".to_owned(),
        signals: Vec::new(),
        summary: String::new(),
        risk_categories: Vec::new(),
    });
    Resolved {
        identity: McpToolCallIdentityPayloadV1 {
            artifact: McpToolCallArtifactV1 {
                artifact_id: ARTIFACT.to_owned(),
                name: "files:read".to_owned(),
                harness: "codex".to_owned(),
                source_scope: "project".to_owned(),
                config_path: "/work/.codex/config.toml".to_owned(),
                command: None,
                transport: Some("stdio".to_owned()),
                publisher: None,
                metadata: Map::new(),
            },
            runtime_private_metadata: Map::new(),
            artifact_hash: Some(artifact_hash.to_owned()),
            risk_categories: Vec::new(),
        },
        decision,
        mode: "enforce".to_owned(),
        redaction_level: None,
    }
}

#[test]
fn a_covered_claim_forwards_as_the_decision_routed() {
    let (routed, append) = postclaim(
        &claimed(Disposition::Consumed),
        &fresh(GuardAction::Allow, HASH),
    )
    .unwrap();
    assert_eq!(
        routed,
        Routed::Forward {
            source: "policy".to_owned(),
            policy_action: "allow".to_owned(),
            remember: false,
        }
    );
    assert!(append.is_empty());
}

#[test]
fn a_fresh_block_after_the_claim_is_the_proxy_terminal() {
    let (routed, _) = postclaim(
        &claimed(Disposition::Consumed),
        &fresh(GuardAction::Block, HASH),
    )
    .unwrap();
    assert_eq!(
        routed,
        Routed::Terminal {
            policy_action: "block".to_owned(),
        }
    );
    let mut stored = fresh(GuardAction::Block, HASH);
    stored.decision.saved_action = Some(GuardAction::Block);
    let (routed, _) = postclaim(&claimed(Disposition::Consumed), &stored).unwrap();
    assert_eq!(
        routed,
        Routed::StoredBlock {
            package_request: false,
        }
    );
}

#[test]
fn a_post_claim_reapproval_queues_the_fresh_call() {
    // The proxy spends the claim and queues a re-approval request for the
    // fresh identity (`runtime_mcp.py` 2674-2684).
    let queued = || Routed::Queue {
        policy_action: "require-reapproval".to_owned(),
    };
    let moved = fresh(GuardAction::Allow, "guard-approval-context:v1:moved");
    let (routed, append) = postclaim(&claimed(Disposition::Consumed), &moved).unwrap();
    assert_eq!(routed, queued());
    // The context change is the evidence the queued row and receipt append.
    assert!(!append.is_empty());
    // A retained claim does not authorize a fresh review.
    let review = fresh(GuardAction::Review, HASH);
    let (routed, _) = postclaim(&claimed(Disposition::Retained), &review).unwrap();
    assert_eq!(routed, queued());
    // A fresh require-reapproval asks whether the claim still covers it; an
    // empty claimed row never does.
    let reapproval = fresh(GuardAction::RequireReapproval, HASH);
    let (routed, _) = postclaim(&claimed(Disposition::Consumed), &reapproval).unwrap();
    assert_eq!(routed, queued());
}

#[test]
fn only_the_very_admission_a_decision_saw_is_unchanged() {
    let (snapshot, binding) = (Arc::new(1u8), Arc::new(2u8));
    let held = ("/work", &snapshot, &binding);
    assert!(unchanged(held, ("/work", &snapshot, &binding)));
    // A republish with equal content is still a different publication.
    let republished = Arc::new(1u8);
    assert!(!unchanged(held, ("/work", &republished, &binding)));
    let rebound = Arc::new(2u8);
    assert!(!unchanged(held, ("/work", &snapshot, &rebound)));
    assert!(!unchanged(held, ("/other", &snapshot, &binding)));
}

#[test]
fn an_unknown_or_spent_ticket_defers() {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("guard-relay-claim-{}-{suffix}", std::process::id()));
    let root = crate::resident_state::ensure_private_directory(&root, true).unwrap();
    let mut key =
        crate::resident_state::private_file(&root.join("policy-verifier.key"), false, &root)
            .unwrap();
    key.write_all(&[23u8; 32]).unwrap();
    drop(key);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let request = McpRelayClaimRequestV1 {
        guard_home: root.to_string_lossy().into_owned(),
        ticket: "claim-0-0-0:1".to_owned(),
        package_evaluation: None,
    };
    let answer: Value = serde_json::from_slice(&claim(&request, &store).unwrap()).unwrap();
    assert_eq!(answer["outcome"], "defer");
    assert_eq!(answer["reason"], CLAIM_UNKNOWN);
    std::fs::remove_dir_all(root).unwrap();
}
