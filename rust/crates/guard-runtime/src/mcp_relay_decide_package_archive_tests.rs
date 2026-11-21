//! Which evaluations demand an external-archive binding, and the block the
//! relay answers a binding it cannot make with.

use guard_command::effect_decision::GuardAction;
use guard_command::package_execution_context::PackageExecutionContext;
use serde_json::json;

use super::*;

const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn evaluation(fields: Value) -> Map<String, Value> {
    let mut evaluation = Map::new();
    evaluation.insert("policy_action".to_owned(), json!("allow"));
    evaluation.insert("decision".to_owned(), json!("allow"));
    evaluation.insert("reasons".to_owned(), json!([]));
    evaluation.insert("packages".to_owned(), json!([]));
    evaluation.insert("risk_summary".to_owned(), json!("installs left-pad"));
    for (key, value) in fields.as_object().expect("an object") {
        evaluation.insert(key.clone(), value.clone());
    }
    evaluation
}

fn policy(evaluation: Map<String, Value>) -> PackagePolicy {
    PackagePolicy {
        evaluation,
        current_action: GuardAction::Allow,
        artifact_hash: "guard-approval-context:v1:abc".to_owned(),
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

#[test]
fn an_inspected_archive_digest_demands_the_binding() {
    assert!(requires_binding(&evaluation(
        json!({"external_archive_source_hashes": [SHA]})
    )));
}

#[test]
fn a_hash_that_is_not_one_demands_nothing() {
    // `len(item) == 64`: a truncated digest is not one the binding can match.
    assert!(!requires_binding(&evaluation(
        json!({"external_archive_source_hashes": [&SHA[..63], 64]})
    )));
    assert!(!requires_binding(&evaluation(json!({}))));
}

#[test]
fn either_reason_list_the_external_tarball_is_reported_on_demands_it() {
    assert!(requires_binding(&evaluation(json!({
        "reasons": [{"code": "external_tarball_source", "message": "from a tarball"}],
    }))));
    assert!(requires_binding(&evaluation(json!({
        "packages": [{"name": "left-pad", "reasons": [{"code": "external_tarball_source"}]}],
    }))));
    // Any other reason is one the forward carries as it is.
    assert!(!requires_binding(&evaluation(json!({
        "reasons": [{"code": "advisory", "message": "left-pad has an advisory"}],
        "packages": [{"name": "left-pad", "reasons": [{"code": "advisory"}]}],
    }))));
}

#[test]
fn the_refused_binding_blocks_the_request_the_proxys_override_blocks_it_with() {
    let refused = unbound(&policy(evaluation(json!({
        "external_archive_source_hashes": [SHA],
        "packages": [{"name": "left-pad", "decision": "allow"}],
    }))))
    .expect("the override is composed");
    assert_eq!(refused.evaluation["decision"], json!("block"));
    assert_eq!(refused.evaluation["policy_action"], json!("block"));
    assert_eq!(
        refused.evaluation["reasons"][0]["code"],
        json!("external_archive_digest_mismatch")
    );
    assert_eq!(
        refused.evaluation["user_copy"]["title"],
        json!("External archive blocked")
    );
    // Every package the request named is blocked with it.
    assert_eq!(
        refused.evaluation["packages"][0]["decision"],
        json!("block")
    );
}

#[test]
fn the_refused_binding_answers_as_the_same_request() {
    let policy = policy(evaluation(json!({"external_archive_source_hashes": [SHA]})));
    let refused = unbound(&policy).expect("the override is composed");
    // The receipt is written against the request that was refused, under the
    // workspace its lookup was valid for.
    assert_eq!(refused.artifact_hash, policy.artifact_hash);
    assert_eq!(refused.policy_workspace, policy.policy_workspace);
    assert_eq!(
        refused.execution_context.digest,
        policy.execution_context.digest
    );
    // The fields the rewrite does not compose are the evaluation's own, and
    // the digest the binding was demanded by is still stated.
    assert_eq!(
        refused.evaluation["external_archive_source_hashes"],
        json!([SHA])
    );
}
