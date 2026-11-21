//! What a claimed package call spends, holds its revalidation to, and answers.

use guard_command::effect_decision::GuardAction;
use guard_command::package_execution_context::PackageExecutionContext;
use guard_contracts::{McpToolCallArtifactV1, McpToolCallIdentityPayloadV1};
use serde_json::json;

use super::super::package_receipt;
use super::package_lane::PackageOutcome;
use super::package_route::PackageRoute;
use super::*;
use crate::mcp_tool_policy_decision::Current;

const TOOL: &str = "install_package";
const SERVER: &str = "registry";

/// One saved `allow` the resolution reported without consuming.
fn row(approval_id: &str) -> Map<String, Value> {
    json!({
        "approval_id": approval_id,
        "decision_id": 7,
        "action": "allow",
        "scope": "once",
        "harness": "codex",
        "workspace": "/work",
    })
    .as_object()
    .expect("the row is an object")
    .clone()
}

/// A claim both policies left a row for, taken at an unmoved boundary.
fn claimed() -> PackageClaimed {
    PackageClaimed {
        tool: Some(row("approval-tool")),
        tool_disposition: Some(Disposition::Consumed),
        package: Some(row("approval-package")),
        package_disposition: Some(Disposition::Consumed),
        tool_artifact_id: "codex:project:install_package".to_owned(),
        tool_artifact_hash: "guard-approval-context:v1:tool".to_owned(),
        package_artifact_id: "package-request:npm:left-pad".to_owned(),
        package_digest: "guard-approval-context:v1:package".to_owned(),
    }
}

/// The tool authority as the claim transaction re-reads it.
fn resolved(artifact_hash: Option<&str>) -> Resolved {
    Resolved {
        identity: McpToolCallIdentityPayloadV1 {
            artifact: McpToolCallArtifactV1 {
                artifact_id: "codex:project:install_package".to_owned(),
                name: TOOL.to_owned(),
                harness: "codex".to_owned(),
                source_scope: "project".to_owned(),
                config_path: "/work/.codex/config.toml".to_owned(),
                command: Some("npm".to_owned()),
                transport: None,
                publisher: None,
                metadata: Map::new(),
            },
            runtime_private_metadata: Map::new(),
            artifact_hash: artifact_hash.map(str::to_owned),
            risk_categories: Vec::new(),
        },
        decision: tool(GuardAction::Allow),
        mode: "enforce".to_owned(),
        redaction_level: Some("full".to_owned()),
    }
}

/// The tool call's own re-read decision.
fn tool(action: GuardAction) -> Decision {
    Decision::plain(Current {
        action,
        source: "policy".to_owned(),
        signals: Vec::new(),
        summary: "installs a package".to_owned(),
        risk_categories: Vec::new(),
    })
}

/// The package request's artifact, rebuilt after the claim.
fn artifact() -> GuardArtifact {
    GuardArtifact {
        artifact_id: "package-request:npm:left-pad".to_owned(),
        name: "left-pad".to_owned(),
        harness: "codex".to_owned(),
        artifact_type: "package_request".to_owned(),
        source_scope: "project".to_owned(),
        config_path: "/work/.codex/config.toml".to_owned(),
        command: Some("npm".to_owned()),
        args: vec!["install".to_owned(), "left-pad".to_owned()],
        url: None,
        transport: None,
        publisher: None,
        metadata: json!({}),
        runtime_private_metadata: Value::Null,
    }
}

/// The freshly resolved package policy, as the claim transaction composes it.
fn policy(policy_action: &str) -> PackagePolicy {
    let mut evaluation = Map::new();
    evaluation.insert("policy_action".to_owned(), json!(policy_action));
    evaluation.insert("decision".to_owned(), json!(policy_action));
    evaluation.insert("reasons".to_owned(), json!([]));
    evaluation.insert("packages".to_owned(), json!([]));
    evaluation.insert(
        "risk_summary".to_owned(),
        json!("left-pad was published yesterday"),
    );
    evaluation.insert(
        "user_copy".to_owned(),
        json!({"title": "Package request needs review", "dashboard_url": "https://hol.org/guard"}),
    );
    PackagePolicy {
        evaluation,
        current_action: GuardAction::Review,
        artifact_hash: "guard-approval-context:v1:package".to_owned(),
        policy_workspace: Some("package-request-workspace:v2:abc".to_owned()),
        execution_context: PackageExecutionContext {
            digest: "ctx".to_owned(),
            portable: true,
            components: Vec::new(),
            non_portable_reason: None,
        },
        reused_decision: None,
        claim_disposition: None,
    }
}

/// The blocked-request mode a queued request is answered under.
fn bound() -> QueueBinding<'static> {
    QueueBinding {
        blocked_request_mode: Some("safe-alternative"),
        redaction_level: Some("full"),
    }
}

/// The evidence the revalidation appends to the half it stopped.
fn append() -> Vec<Value> {
    vec![json!({
        "source": "approval_reuse",
        "status": "rejected",
        "reason_code": "approval_reuse_context_changed_after_claim",
    })]
}

#[test]
fn a_claim_spends_the_rows_the_two_policies_left_in_the_proxys_own_order() {
    let both = claimed();
    assert_eq!(
        rows(&both),
        vec![&row("approval-tool"), &row("approval-package")]
    );

    let mut package_only = claimed();
    package_only.tool = None;
    assert_eq!(rows(&package_only), vec![&row("approval-package")]);

    let mut tool_only = claimed();
    tool_only.package = None;
    assert_eq!(rows(&tool_only), vec![&row("approval-tool")]);

    let mut neither = claimed();
    neither.tool = None;
    neither.package = None;
    assert!(rows(&neither).is_empty());
}

#[test]
fn the_tool_context_states_where_the_claim_was_taken_and_where_it_stands_now() {
    let context = tool_context(
        &claimed(),
        &resolved(Some("guard-approval-context:v1:moved")),
    )
    .expect("the re-read identity carries an approval context");

    assert_eq!(context.artifact_id, "codex:project:install_package");
    assert_eq!(
        context.expected_artifact_id,
        "codex:project:install_package"
    );
    // The boundary the claim is held to is the decision's, and the one it is
    // compared with is the re-read authority's.
    assert_eq!(context.artifact_hash, "guard-approval-context:v1:moved");
    assert_eq!(
        context.expected_artifact_hash,
        "guard-approval-context:v1:tool"
    );
}

#[test]
fn a_re_read_authority_without_an_approval_context_defers_the_claim() {
    assert_eq!(
        tool_context(&claimed(), &resolved(None)),
        Err(IDENTITY_FAILED)
    );
}

#[test]
fn the_package_facts_hold_the_fresh_resolution_to_the_claims_own_boundary() {
    let mut resolution = policy("review");
    resolution.artifact_hash = "guard-approval-context:v1:moved".to_owned();
    let facts = package_facts(
        &claimed(),
        &artifact(),
        &resolution,
        &tool(GuardAction::Allow),
    )
    .expect("the resolved policy composes its facts");

    assert_eq!(facts.artifact_id, "package-request:npm:left-pad");
    assert_eq!(facts.expected_artifact_id, "package-request:npm:left-pad");
    assert_eq!(facts.digest, "guard-approval-context:v1:moved");
    assert_eq!(facts.expected_digest, "guard-approval-context:v1:package");
    assert_eq!(facts.facts.policy_action, "review");
    // A resolution that reported no saved row has none left to reuse.
    assert!(!facts.facts.has_pending);
}

#[test]
fn a_consumed_claim_authorizes_the_postclaim_review_on_its_own_half() {
    let facts = package_facts(
        &claimed(),
        &artifact(),
        &policy("review"),
        &tool(GuardAction::Allow),
    )
    .expect("the facts compose");

    assert!(facts.tool_claim_authorizes_review);
    assert!(facts.package_claim_authorizes_review);
}

#[test]
fn a_retained_claim_authorizes_the_review_only_while_its_own_row_is_selected() {
    let mut retained = claimed();
    retained.tool_disposition = Some(Disposition::Retained);
    retained.package_disposition = Some(Disposition::Retained);

    let mut selected = policy("review");
    selected.reused_decision = Some(Value::Object(row("approval-package")));
    let mut fresh_tool = tool(GuardAction::Allow);
    fresh_tool.pending = Some(row("approval-tool"));
    let facts =
        package_facts(&retained, &artifact(), &selected, &fresh_tool).expect("the facts compose");
    assert!(facts.tool_claim_authorizes_review);
    assert!(facts.package_claim_authorizes_review);

    // The same rows are no longer the ones the fresh resolutions selected.
    let mut moved = policy("review");
    moved.reused_decision = Some(Value::Object(row("approval-other")));
    let mut moved_tool = tool(GuardAction::Allow);
    moved_tool.pending = Some(row("approval-other"));
    let facts =
        package_facts(&retained, &artifact(), &moved, &moved_tool).expect("the facts compose");
    assert!(!facts.tool_claim_authorizes_review);
    assert!(!facts.package_claim_authorizes_review);
}

#[test]
fn a_half_that_left_no_claim_authorizes_no_postclaim_review() {
    let mut unclaimed = claimed();
    unclaimed.tool = None;
    unclaimed.tool_disposition = None;
    unclaimed.package_disposition = None;
    let facts = package_facts(
        &unclaimed,
        &artifact(),
        &policy("review"),
        &tool(GuardAction::Allow),
    )
    .expect("the facts compose");

    assert!(!facts.tool_claim_authorizes_review);
    assert!(!facts.package_claim_authorizes_review);
}

#[test]
fn a_tool_leg_carries_its_evidence_on_the_tool_calls_own_receipt() {
    let settled = settled(
        Postclaimed {
            decided: Decided::Tool(ToolLeg::Queue {
                policy_action: "require-reapproval".to_owned(),
            }),
            append: append(),
        },
        TOOL,
        SERVER,
        &policy("allow"),
        artifact(),
        "/work",
        bound(),
    )
    .expect("the tool leg settles");

    let Settled::Tool {
        leg,
        append: carried,
    } = settled
    else {
        panic!("a leg the tool policy decided is answered by the tool lane");
    };
    assert_eq!(
        leg,
        ToolLeg::Queue {
            policy_action: "require-reapproval".to_owned(),
        }
    );
    // The package request's own artifact records nothing here: the evidence
    // rides the tool call's receipt.
    assert_eq!(carried, append());
}

#[test]
fn a_package_route_appends_its_evidence_after_the_requests_own() {
    let resolution = policy("allow");
    let settled = settled(
        Postclaimed {
            decided: Decided::Package(PackageRoute::Forward {
                policy_action: "allow".to_owned(),
            }),
            append: append(),
        },
        TOOL,
        SERVER,
        &resolution,
        artifact(),
        "/work",
        bound(),
    )
    .expect("the forward settles");

    let Settled::Package(packaged) = settled else {
        panic!("a package route settles on the package request's own artifact");
    };
    assert_eq!(packaged.artifact.artifact_id, artifact().artifact_id);
    assert_eq!(packaged.workspace, "/work");
    let PackageOutcome::Answered(answer) = packaged.outcome else {
        panic!("an unqueued forward is answered outright");
    };
    // The forward is recorded against the post-claim resolution, and the
    // revalidation's own evidence follows the receipt's.
    assert_eq!(answer.block, None);
    assert_eq!(answer.policy_action, "allow");
    assert_eq!(answer.artifact_hash, resolution.artifact_hash);
    assert_eq!(answer.evaluation, resolution.evaluation);
    let own = package_receipt::evidence(&resolution);
    assert_eq!(answer.evidence.len(), own.len() + 1);
    assert_eq!(&answer.evidence[..own.len()], &own[..]);
    assert_eq!(answer.evidence.last(), append().last());
}

#[test]
fn a_postclaim_forward_the_relay_cannot_bind_to_its_archives_is_blocked_instead() {
    let mut demanding = policy("allow");
    demanding.evaluation.insert(
        "external_archive_source_hashes".to_owned(),
        json!(["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]),
    );
    let settled = settled(
        Postclaimed {
            decided: Decided::Package(PackageRoute::Forward {
                policy_action: "allow".to_owned(),
            }),
            append: append(),
        },
        TOOL,
        SERVER,
        &demanding,
        artifact(),
        "/work",
        bound(),
    )
    .expect("the refused binding answers the call");

    let Settled::Package(packaged) = settled else {
        panic!("the refusal is the package half's");
    };
    let PackageOutcome::Answered(answer) = packaged.outcome else {
        panic!("the block is answered outright");
    };
    // `_bound_external_archive_mcp_request` runs on the post-claim resolution
    // too: a claimed forward the relay retains no archive for still blocks.
    assert!(answer.block.is_some());
    assert_eq!(answer.policy_action, "block");
    assert_eq!(answer.evidence.last(), append().last());
}
