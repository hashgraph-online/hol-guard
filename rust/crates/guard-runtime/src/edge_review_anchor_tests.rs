use super::*;
use guard_policy_snapshot::business_policy::{
    BusinessPolicyBindingV1, BUSINESS_POLICY_BINDING_SCHEMA,
};
use guard_policy_snapshot::{
    EffectiveNativePolicyV3, PolicySnapshotV3, ScopeContractV3, SnapshotIntegrityV3,
    POLICY_SNAPSHOT_INTEGRITY_ALGORITHM, POLICY_SNAPSHOT_SCHEMA,
};
use std::collections::BTreeMap;

fn effective_policy() -> EffectiveNativePolicyV3 {
    EffectiveNativePolicyV3 {
        protection_posture: "protected".into(),
        security_level: "balanced".into(),
        default_action: "review".into(),
        unknown_publisher_action: "review".into(),
        changed_hash_action: "require-reapproval".into(),
        new_network_domain_action: "allow".into(),
        subprocess_action: "allow".into(),
        risk_actions: BTreeMap::new(),
        harness_risk_actions: BTreeMap::new(),
        harness_actions: BTreeMap::new(),
        publisher_actions: BTreeMap::new(),
        artifact_actions: BTreeMap::new(),
        mcp_tool_actions: BTreeMap::new(),
        mcp_provider_actions: BTreeMap::new(),
        mcp_provider_catalog_hash: None,
        sandbox_analysis: "off".into(),
        receipt_redaction_level: "full".into(),
    }
}

fn snapshot() -> PolicySnapshotV3 {
    PolicySnapshotV3 {
        schema: POLICY_SNAPSHOT_SCHEMA.into(),
        version: 3,
        generation: 7,
        policy_digest: "a".repeat(64),
        config_digest: "b".repeat(64),
        rule_digest: "c".repeat(64),
        runtime_identity: "d".repeat(64),
        protocol_version: 1,
        mode: "enforce".into(),
        scope_contract: ScopeContractV3 {
            schema: "guard-native-scope.v1".into(),
            kind: "guard-home".into(),
            scope_digest: "e".repeat(64),
            workspace_binding: "request-source".into(),
        },
        effective_policy: effective_policy(),
        command_extensions: None,
        business_policy: None,
        issued_at_ms: 1,
        expires_at_ms: 2,
        integrity: SnapshotIntegrityV3 {
            algorithm: POLICY_SNAPSHOT_INTEGRITY_ALGORITHM.into(),
            key_id: "f".repeat(64),
            mac: "0".repeat(64),
        },
    }
}

/// `envelope` writes a generation file under a fresh guard home; the anchor
/// never reads it, so the fixture only has to clean it up again.
struct ReviewRequest(GuardHookEnvelopeV2);

impl std::ops::Deref for ReviewRequest {
    type Target = GuardHookEnvelopeV2;

    fn deref(&self) -> &GuardHookEnvelopeV2 {
        &self.0
    }
}

impl Drop for ReviewRequest {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0.source.guard_home);
    }
}

fn review_envelope() -> ReviewRequest {
    ReviewRequest(envelope(
        "PreToolUse",
        serde_json::json!({"tool_name": "bash", "tool_input": {"command": "rm -rf ./build"}}),
    ))
}

fn anchor(request: &GuardHookEnvelopeV2, snapshot: &PolicySnapshotV3) -> String {
    review_anchor_digest(request, Some(snapshot)).expect("anchor the reviewed action")
}

/// The whole point of the anchor: the publisher republishes on its own, and an
/// identical retry must still match the approval the user already gave.
#[test]
fn anchor_survives_a_republish_that_decided_nothing() {
    let request = review_envelope();
    let published = snapshot();
    let mut republished = published.clone();
    republished.generation = 31;
    republished.policy_digest = "1".repeat(64);
    republished.config_digest = "2".repeat(64);
    republished.issued_at_ms = 900;
    republished.expires_at_ms = 1_800;
    republished.integrity.mac = "3".repeat(64);
    assert_eq!(anchor(&request, &published), anchor(&request, &republished));
}

/// Observed MCP state accumulates as the agent works. The publisher merges it
/// stricter-wins, so it can only tighten, and a tightening that matters is
/// already applied by the fresh evaluation that runs before any approval is
/// looked up.
#[test]
fn anchor_survives_newly_observed_mcp_state() {
    let request = review_envelope();
    let published = snapshot();
    let mut observed = published.clone();
    observed
        .effective_policy
        .mcp_tool_actions
        .insert("server__fetch".into(), "review".into());
    observed
        .effective_policy
        .mcp_provider_actions
        .insert("server".into(), "review".into());
    observed.effective_policy.mcp_provider_catalog_hash = Some("4".repeat(64));
    assert_eq!(anchor(&request, &published), anchor(&request, &observed));
}

#[test]
fn anchor_changes_when_the_configured_policy_changes() {
    let request = review_envelope();
    let published = snapshot();
    let baseline = anchor(&request, &published);
    let mut denied = published.clone();
    denied.effective_policy.default_action = "block".into();
    assert_ne!(anchor(&request, &denied), baseline);
    let mut harness_denied = published.clone();
    harness_denied
        .effective_policy
        .harness_actions
        .insert("claude-code".into(), "block".into());
    assert_ne!(anchor(&request, &harness_denied), baseline);
    let mut risk_denied = published.clone();
    risk_denied
        .effective_policy
        .risk_actions
        .insert("destructive".into(), "block".into());
    assert_ne!(anchor(&request, &risk_denied), baseline);
    let mut posture = published.clone();
    posture.effective_policy.security_level = "strict".into();
    assert_ne!(anchor(&request, &posture), baseline);
}

#[test]
fn anchor_changes_with_the_runtime_and_scope_it_was_approved_under() {
    let request = review_envelope();
    let published = snapshot();
    let baseline = anchor(&request, &published);
    let mut rules = published.clone();
    rules.rule_digest = "5".repeat(64);
    assert_ne!(anchor(&request, &rules), baseline);
    let mut runtime = published.clone();
    runtime.runtime_identity = "6".repeat(64);
    assert_ne!(anchor(&request, &runtime), baseline);
    let mut mode = published.clone();
    mode.mode = "observe".into();
    assert_ne!(anchor(&request, &mode), baseline);
    let mut scope = published.clone();
    scope.scope_contract.scope_digest = "7".repeat(64);
    assert_ne!(anchor(&request, &scope), baseline);
    let mut business = published.clone();
    business.business_policy = Some(BusinessPolicyBindingV1 {
        schema: BUSINESS_POLICY_BINDING_SCHEMA.into(),
        version: 1,
        default_action: "block".into(),
        rules: Vec::new(),
        source_document_digest: None,
        budgets: None,
    });
    assert_ne!(anchor(&request, &business), baseline);
}

/// `execution_intent_digest` omits these three, so anchoring to it alone would
/// let an approval be consumed under a different guard home or with the
/// external source-ref flag flipped.
#[test]
fn anchor_binds_every_source_field_of_the_approved_request() {
    let published = snapshot();
    let request = review_envelope();
    let baseline = anchor(&request, &published);
    let mut elsewhere = request.clone();
    elsewhere.source.guard_home = format!("{}-other", request.source.guard_home);
    assert_ne!(anchor(&elsewhere, &published), baseline);
    let mut other_home = request.clone();
    other_home.source.home_dir = "/home/other".into();
    assert_ne!(anchor(&other_home, &published), baseline);
    let mut external = request.clone();
    external.source.source_ref_external_allowed = true;
    assert_ne!(anchor(&external, &published), baseline);
    let mut moved = request.clone();
    moved.source.cwd = Some("/workspace/other".into());
    assert_ne!(anchor(&moved, &published), baseline);
    let mut environment = request.clone();
    environment.source.execution_environment = Some(guard_contracts::GuardExecutionEnvironmentV1 {
        path: "/usr/bin:/bin".into(),
        environment_names: vec!["PATH".into()],
        environment_digest: "8".repeat(64),
        home: None,
        git_pager_disabled: false,
        pager_disabled: false,
        xdg_config_home: None,
        git_config_no_system: false,
        library_search_paths: Default::default(),
    });
    assert_ne!(anchor(&environment, &published), baseline);
}

#[test]
fn anchor_binds_the_action_it_was_approved_for() {
    let published = snapshot();
    let request = review_envelope();
    let baseline = anchor(&request, &published);
    let mut other_command = request.clone();
    other_command.raw_payload["tool_input"]["command"] = serde_json::json!("rm -rf /");
    assert_ne!(anchor(&other_command, &published), baseline);
    let mut other_event = request.clone();
    other_event.event = "PostToolUse".into();
    assert_ne!(anchor(&other_event, &published), baseline);
    let mut other_harness = request.clone();
    other_harness.harness = "codex".into();
    assert_ne!(anchor(&other_harness, &published), baseline);
}

/// The model emits a new tool-use block for its retry, so Claude Code stamps
/// the retry with a new `tool_use_id`. The approval the user gave for the
/// command has to reach it, and only it: another command or another session
/// is another action.
#[test]
fn anchor_reaches_a_retry_under_a_new_tool_use_id() {
    let published = snapshot();
    let mut request = review_envelope();
    request.0.raw_payload["session_id"] = serde_json::json!("session-one");
    request.0.raw_payload["tool_use_id"] = serde_json::json!("toolu_first");
    let baseline = anchor(&request, &published);
    let mut retry = request.0.clone();
    retry.raw_payload["tool_use_id"] = serde_json::json!("toolu_retry");
    assert_eq!(anchor(&retry, &published), baseline);
    let mut other_session = retry.clone();
    other_session.raw_payload["session_id"] = serde_json::json!("session-two");
    assert_ne!(anchor(&other_session, &published), baseline);
    let mut other_command = retry.clone();
    other_command.raw_payload["tool_input"]["command"] = serde_json::json!("rm -rf /");
    assert_ne!(anchor(&other_command, &published), baseline);
    // Without a session the call ID is all that ties a retry to its request.
    let mut sessionless = request.0.clone();
    sessionless.raw_payload["session_id"] = serde_json::json!("");
    let mut sessionless_retry = sessionless.clone();
    sessionless_retry.raw_payload["tool_use_id"] = serde_json::json!("toolu_retry");
    assert_ne!(
        anchor(&sessionless_retry, &published),
        anchor(&sessionless, &published)
    );
}

/// Without an authenticated snapshot there is nothing narrower to trust, so
/// the anchor keeps the whole claimed identity rather than widen what a retry
/// may be matched against.
#[test]
fn anchor_without_a_snapshot_keeps_the_claimed_policy_identity() {
    let request = review_envelope();
    let baseline = review_anchor_digest(&request, None).expect("anchor without a snapshot");
    let mut claimed = request.clone();
    claimed.policy_snapshot["policy_digest"] = serde_json::json!("9".repeat(64));
    assert_ne!(
        review_anchor_digest(&claimed, None).expect("anchor without a snapshot"),
        baseline
    );
    assert_ne!(baseline, anchor(&request, &snapshot()));
}
