use guard_contracts::{
    PolicyDocumentDecisionRequestV1, PolicyDocumentEventV1, PolicyDocumentRowV1,
    POLICY_DOCUMENT_DECISION_REQUEST_SCHEMA, POLICY_DOCUMENT_MATCH_LIMIT,
};
use serde_json::Value;

use super::evaluate;

const NOW: &str = "2026-10-17T12:00:00Z";

fn row(rule_id: &str, scope: &str, action: &str) -> PolicyDocumentRowV1 {
    PolicyDocumentRowV1 {
        rule_id: rule_id.to_owned(),
        harness: "codex".to_owned(),
        scope: scope.to_owned(),
        action: action.to_owned(),
        ..PolicyDocumentRowV1::default()
    }
}

fn event() -> PolicyDocumentEventV1 {
    PolicyDocumentEventV1 {
        harness: "codex".to_owned(),
        ..PolicyDocumentEventV1::default()
    }
}

fn decide(rows: Vec<PolicyDocumentRowV1>, event: PolicyDocumentEventV1) -> Value {
    evaluate(&PolicyDocumentDecisionRequestV1 {
        schema: POLICY_DOCUMENT_DECISION_REQUEST_SCHEMA.to_owned(),
        request_id: "policy-document-decision-test".to_owned(),
        rows,
        event,
        now: NOW.to_owned(),
    })
    .expect("decision")
}

fn candidate(decision: &Value, index: usize) -> &Value {
    &decision["candidates"][index]
}

#[test]
fn block_beats_allow_at_the_same_scope() {
    let decision = decide(
        vec![
            row("allow-all", "global", "allow"),
            row("block-all", "global", "block"),
        ],
        event(),
    );
    assert_eq!(decision["effect"], "block");
    assert_eq!(decision["ruleId"], "block-all");
    assert_eq!(candidate(&decision, 0)["state"], "outranked");
    assert_eq!(candidate(&decision, 0)["reason"], "block_wins");
    assert_eq!(candidate(&decision, 1)["state"], "selected");
    assert_eq!(decision["ambiguous"], false);
}

#[test]
fn the_more_specific_rule_wins_at_equal_severity() {
    let mut narrow = row("workspace-allow", "workspace", "allow");
    narrow.workspace = Some("/srv/app".to_owned());
    let decision = decide(
        vec![row("global-allow", "global", "allow"), narrow],
        PolicyDocumentEventV1 {
            harness: "codex".to_owned(),
            workspace: Some("/srv/app".to_owned()),
            ..PolicyDocumentEventV1::default()
        },
    );
    assert_eq!(decision["ruleId"], "workspace-allow");
    assert_eq!(candidate(&decision, 0)["reason"], "more_specific_rule");
}

#[test]
fn two_rules_of_equal_specificity_tie() {
    let decision = decide(
        vec![
            row("first", "global", "allow"),
            row("second", "global", "allow"),
        ],
        event(),
    );
    assert_eq!(decision["ruleId"], "first");
    assert_eq!(decision["ambiguous"], true);
    assert_eq!(decision["tiedRuleIds"], serde_json::json!(["second"]));
    assert_eq!(candidate(&decision, 1)["reason"], "tie");
}

#[test]
fn an_expired_rule_decides_nothing() {
    let mut expired = row("stale", "global", "block");
    expired.expires_at = Some("2026-10-17T11:59:59Z".to_owned());
    let decision = decide(vec![expired], event());
    assert_eq!(decision["effect"], "default");
    assert_eq!(decision["ruleId"], Value::Null);
    assert_eq!(candidate(&decision, 0)["state"], "expired");
}

#[test]
fn an_unreadable_expiry_expires_the_rule() {
    let mut expired = row("stale", "global", "allow");
    expired.expires_at = Some("not-a-timestamp".to_owned());
    let decision = decide(vec![expired], event());
    assert_eq!(candidate(&decision, 0)["state"], "expired");
}

#[test]
fn another_harness_never_matches() {
    let mut other = row("other", "global", "block");
    other.harness = "claude".to_owned();
    let decision = decide(vec![other], event());
    assert_eq!(candidate(&decision, 0)["state"], "unmatched");
    assert_eq!(candidate(&decision, 0)["reason"], "harness");
}

#[test]
fn a_wildcard_harness_matches_every_harness() {
    let mut any = row("any", "global", "block");
    any.harness = "*".to_owned();
    let decision = decide(vec![any], event());
    assert_eq!(decision["effect"], "block");
}

#[test]
fn a_broad_rule_over_an_exact_only_family_is_not_enforced_without_its_key() {
    let mut broad = row("broad-shell", "harness", "allow");
    broad.artifact_id = Some("family:tool-action".to_owned());
    broad.artifact_hash = Some("runtime-exact:0000".to_owned());
    let decision = decide(
        vec![broad],
        PolicyDocumentEventV1 {
            harness: "codex".to_owned(),
            tool: Some("shell".to_owned()),
            ..PolicyDocumentEventV1::default()
        },
    );
    assert_eq!(candidate(&decision, 0)["state"], "not_enforced");
    assert_eq!(candidate(&decision, 0)["reason"], "exact_only_family");
    assert_eq!(decision["effect"], "default");
}

#[test]
fn a_tool_event_probes_its_family_artifact() {
    let mut family = row("mcp-block", "global", "block");
    family.artifact_id = Some("family:mcp".to_owned());
    let decision = decide(
        vec![family],
        PolicyDocumentEventV1 {
            harness: "codex".to_owned(),
            tool: Some("MCP".to_owned()),
            ..PolicyDocumentEventV1::default()
        },
    );
    assert_eq!(decision["effect"], "block");
    assert_eq!(decision["lookup"]["artifactId"], "family:mcp");
    assert_eq!(decision["lookup"]["familyKey"], "family:mcp");
    assert_eq!(decision["lookup"]["at"], NOW);
}

#[test]
fn an_artifact_scope_rule_needs_the_same_artifact_and_no_hash() {
    let mut exact = row("exact", "artifact", "block");
    exact.artifact_id = Some("codex:tool:mcp:fetch".to_owned());
    let decision = decide(
        vec![exact.clone()],
        PolicyDocumentEventV1 {
            harness: "codex".to_owned(),
            artifact: Some("codex:tool:mcp:fetch".to_owned()),
            ..PolicyDocumentEventV1::default()
        },
    );
    assert_eq!(decision["effect"], "block");

    let mut bound = exact;
    bound.artifact_hash = Some("guard-approval-context:v1:abc".to_owned());
    let decision = decide(
        vec![bound],
        PolicyDocumentEventV1 {
            harness: "codex".to_owned(),
            artifact: Some("codex:tool:mcp:fetch".to_owned()),
            ..PolicyDocumentEventV1::default()
        },
    );
    assert_eq!(candidate(&decision, 0)["state"], "unmatched");
    assert_eq!(candidate(&decision, 0)["reason"], "artifact");
}

#[test]
fn a_workspace_rule_matches_the_hashed_workspace_key() {
    let mut scoped = row("ws", "workspace", "block");
    scoped.workspace = Some("/srv/app/".to_owned());
    let decision = decide(
        vec![scoped],
        PolicyDocumentEventV1 {
            harness: "codex".to_owned(),
            workspace: Some("/srv/app".to_owned()),
            ..PolicyDocumentEventV1::default()
        },
    );
    assert_eq!(decision["effect"], "block");
}

#[test]
fn a_workspace_rule_skips_another_workspace() {
    let mut scoped = row("ws", "workspace", "block");
    scoped.workspace = Some("/srv/other".to_owned());
    let decision = decide(
        vec![scoped],
        PolicyDocumentEventV1 {
            harness: "codex".to_owned(),
            workspace: Some("/srv/app".to_owned()),
            ..PolicyDocumentEventV1::default()
        },
    );
    assert_eq!(candidate(&decision, 0)["reason"], "workspace");
}

#[test]
fn a_publisher_rule_needs_the_events_publisher() {
    let mut scoped = row("pub", "publisher", "block");
    scoped.publisher = Some("acme".to_owned());
    let decision = decide(vec![scoped.clone()], event());
    assert_eq!(candidate(&decision, 0)["reason"], "publisher");

    let decision = decide(
        vec![scoped],
        PolicyDocumentEventV1 {
            harness: "codex".to_owned(),
            publisher: Some("acme".to_owned()),
            ..PolicyDocumentEventV1::default()
        },
    );
    assert_eq!(decision["effect"], "block");
}

#[test]
fn the_event_time_overrides_now() {
    let mut expiring = row("window", "global", "allow");
    expiring.expires_at = Some("2026-10-17T13:00:00Z".to_owned());
    let decision = decide(
        vec![expiring],
        PolicyDocumentEventV1 {
            harness: "codex".to_owned(),
            at: Some("2026-10-17T14:00:00Z".to_owned()),
            ..PolicyDocumentEventV1::default()
        },
    );
    assert_eq!(candidate(&decision, 0)["state"], "expired");
    assert_eq!(decision["lookup"]["at"], "2026-10-17T14:00:00Z");
}

#[test]
fn passing_the_probe_limit_blocks_without_a_rule() {
    let rows: Vec<PolicyDocumentRowV1> = (0..=POLICY_DOCUMENT_MATCH_LIMIT)
        .map(|index| row(&format!("rule-{index}"), "global", "allow"))
        .collect();
    let decision = decide(rows, event());
    assert_eq!(decision["effect"], "block");
    assert_eq!(decision["ruleId"], Value::Null);
    assert_eq!(decision["matchLimitExceeded"], true);
    assert_eq!(decision["tiedRuleIds"], serde_json::json!([]));
}

#[test]
fn an_unknown_scope_is_refused_rather_than_ranked() {
    let error = evaluate(&PolicyDocumentDecisionRequestV1 {
        schema: POLICY_DOCUMENT_DECISION_REQUEST_SCHEMA.to_owned(),
        request_id: "policy-document-decision-test".to_owned(),
        rows: vec![row("odd", "organisation", "allow")],
        event: event(),
        now: NOW.to_owned(),
    })
    .expect_err("unknown scope");
    assert_eq!(error, "native_policy_document_decision_row_scope_unknown");
}

#[test]
fn an_unknown_action_is_refused_rather_than_ranked() {
    let error = evaluate(&PolicyDocumentDecisionRequestV1 {
        schema: POLICY_DOCUMENT_DECISION_REQUEST_SCHEMA.to_owned(),
        request_id: "policy-document-decision-test".to_owned(),
        rows: vec![row("odd", "global", "warn")],
        event: event(),
        now: NOW.to_owned(),
    })
    .expect_err("unknown action");
    assert_eq!(error, "native_policy_document_decision_row_action_unknown");
}

#[test]
fn an_unreadable_evaluation_time_is_refused() {
    let error = evaluate(&PolicyDocumentDecisionRequestV1 {
        schema: POLICY_DOCUMENT_DECISION_REQUEST_SCHEMA.to_owned(),
        request_id: "policy-document-decision-test".to_owned(),
        rows: Vec::new(),
        event: event(),
        now: "2026-10-17 12:00:00".to_owned(),
    })
    .expect_err("bad time");
    assert_eq!(error, "native_policy_document_decision_time_invalid");
}

#[test]
fn a_request_naming_another_schema_decides_nothing() {
    let error = evaluate(&PolicyDocumentDecisionRequestV1 {
        schema: "guard-policy-decision-lookup-request.v1".to_owned(),
        request_id: "policy-document-decision-test".to_owned(),
        rows: vec![row("allow-all", "global", "allow")],
        event: event(),
        now: NOW.to_owned(),
    })
    .expect_err("schema mismatch");
    assert_eq!(error, "native_policy_document_decision_schema_mismatch");
}
