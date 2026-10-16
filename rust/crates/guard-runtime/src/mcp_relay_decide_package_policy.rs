//! The stored package policy a relayed package call is decided under.
//!
//! Port of the proxy's package-policy leg (`runtime_mcp.py:1405-1428`), in its
//! own order: the execution context the digest binds
//! (`build_package_execution_context`), the composed current action and the
//! approval-context token (`package_current_action_and_hash`), the one
//! workspace identity a package lookup is valid for
//! (`package_request_runtime_workspace_scope`), and the stored override the
//! resident resolves over the hydrated store facts
//! (`_resolve_stored_package_policy_override`, `native_package_policy_resolve.py`).
//!
//! The proxy hydrates those facts from a read-write store and a daemon policy
//! authority. The relay has neither: it reads the saved rows on the
//! integrity-verified read-only snapshot the rest of the decide path reads
//! (`mcp_relay_decide_store.rs`, `mcp_relay_decide_saved.rs`), and it has no
//! daemon authority at all. So a lookup that ignored a saved row for a local
//! integrity failure and found no decision — the one leg where Python asks the
//! daemon — defers the call rather than answering `require-reapproval` on the
//! authority's behalf.
//!
//! Every other fact is read here rather than asked of the proxy: the policy
//! view from the bound harness view (`mcp_relay_decide_package_config.rs`), the
//! advisory feed snapshot hash and the approval-request row with narrow
//! read-only SQL on the same snapshot, and the extension-control digest from
//! the binding the direct lane admitted. The signed-store verifier key
//! `native_package_approval_hash.py:167` provisions is not needed: the advisory
//! read the token binds opens the store read-only on its own.
//!
//! A fact this cannot read is never defaulted. The evaluation views are read
//! strictly — every field the proxy sends must be present — and the claim is
//! never asked for, because a relayed call resolves read-only: `claim_saved_approval`
//! is false, so a saved approval is reported, never consumed.

// The decide path reads this with the rest of the native package lane; until it
// does, only the tests below resolve a stored policy.
#![allow(dead_code)]

use super::package_snapshot::{approval_request, feed_snapshot_hash};
use super::store::{Probe, Saved};
use super::view::HarnessView;
use crate::package_approval_hash_op::package_current_action_and_hash;
use crate::package_context_build_op::build_execution_context;
use crate::package_policy_resolve_op::resolve_unclaimed_resolution;
use guard_command::effect_decision::GuardAction;
use guard_command::local_supply_chain::package_request_runtime_workspace_scope;
use guard_command::package_execution_context::{
    PackageExecutionContext, PackageExecutionContextComponent, PACKAGE_EXECUTION_CONTEXT_VERSION,
};
use guard_command::package_intent_common::GuardArtifact;
use guard_contracts::{
    PackageApprovalHashRequestV1, PackageContextBuildMetadataV1, PackageContextBuildRequestV1,
    PackagePolicyResolveRequestV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA,
    PACKAGE_CONTEXT_BUILD_REQUEST_SCHEMA,
};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// An evaluation whose fields the policy composition reads are not the ones
/// the proxy sends.
const EVALUATION_INVALID: &str = "mcp_relay_package_evaluation_invalid";
/// The execution context the digest binds could not be built here.
const CONTEXT_UNBUILDABLE: &str = "mcp_relay_package_context_unbuildable";
/// The composed action or the approval-context token could not be derived.
const HASH_FAILED: &str = "mcp_relay_package_hash_failed";
/// The resident refused the stored-policy resolution.
pub(super) const RESOLVE_FAILED: &str = "mcp_relay_package_policy_failed";
/// A saved row was ignored for a local integrity failure and no decision was
/// found, which only a daemon policy authority can resolve.
const DAEMON_AUTHORITY: &str = "mcp_relay_package_policy_daemon_authority";

/// The request id the in-process resolution carries. The byte path's id
/// correlates a response with its request; nothing correlates here, but the op
/// rejects an empty one, so the lane names itself.
const REQUEST_ID: &str = "mcp-relay-package-policy";

/// `_EVALUATION_FIELDS` (`native_package_approval_hash.py:28`): the fields the
/// approval identity and the composed action read.
const HASH_EVALUATION_FIELDS: [&str; 10] = [
    "bundle_version",
    "decision",
    "enforcement",
    "entitlement_state",
    "exception_id",
    "matched_rule_id",
    "packages",
    "policy_action",
    "policy_version",
    "reasons",
];

/// The fields the stored-override rewrites read.
const RESOLVE_EVALUATION_FIELDS: [&str; 3] = ["policy_action", "reasons", "packages"];

/// The process facts the execution context is built from, which the proxy read
/// from its own interpreter. They are the relaying process's, not the
/// resident's: the digest describes where the package command would run, so
/// reading the resident's own environment here would bind the wrong process.
pub(super) struct ProcessFacts<'a> {
    /// `os.environ` of the process the proxy ran in.
    pub(super) environment: &'a BTreeMap<String, String>,
    /// `os.getcwd()`.
    pub(super) cwd: &'a str,
    /// `str(Path.home())`.
    pub(super) home: &'a str,
}

/// What the stored policy settles for a relayed package call.
pub(super) struct PackagePolicy {
    /// The caller's evaluation with the override's rewrite applied.
    pub(super) evaluation: Map<String, Value>,
    /// The composed action the approval identity was bound to.
    pub(super) current_action: GuardAction,
    /// The approval-context token the saved row is matched against.
    pub(super) artifact_hash: String,
    /// The only workspace identity a package-policy lookup is valid for.
    pub(super) policy_workspace: Option<String>,
    pub(super) execution_context: PackageExecutionContext,
    /// The saved row the resolution accepted, when it reused one.
    pub(super) reused_decision: Option<Value>,
    pub(super) claim_disposition: Option<String>,
}

/// The stored package policy override for one relayed call.
pub(super) fn package_policy(
    saved: &Saved<'_>,
    view: &HarnessView,
    artifact: &GuardArtifact,
    evaluation: &Map<String, Value>,
    control_digest: &str,
    workspace_dir: &str,
    process: &ProcessFacts<'_>,
) -> Result<PackagePolicy, &'static str> {
    let execution_context = execution_context(saved, artifact, workspace_dir, process)?;
    let (current_action, artifact_hash) = current_action_and_hash(
        saved,
        view,
        artifact,
        evaluation,
        control_digest,
        workspace_dir,
        &execution_context,
    )?;
    let policy_workspace = package_request_runtime_workspace_scope(
        Some(&artifact.artifact_id),
        Some(&artifact_hash),
        Some(&artifact.artifact_type),
        &execution_context,
    );
    let facts = hydrate(
        saved,
        artifact,
        &artifact_hash,
        policy_workspace.as_deref(),
        process.cwd,
    )?;
    let request = PackagePolicyResolveRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: REQUEST_ID.to_owned(),
        guard_home: saved.guard_home.clone(),
        evaluation: Value::Object(view_of(evaluation, &RESOLVE_EVALUATION_FIELDS)?),
        current_action: Some(json!(current_action.as_str())),
        harness: artifact.harness.clone(),
        artifact_id: artifact.artifact_id.clone(),
        artifact_hash: artifact_hash.clone(),
        workspace_dir: workspace_dir.to_owned(),
        decision: facts.decision,
        approval_request: facts.approval_request,
        ignored_integrity: facts.ignored_integrity,
        // No daemon policy authority is reachable from the relay; the one leg
        // that needs one deferred in `hydrate`.
        daemon_authority: false,
        diagnosed_reason: facts.diagnosed_reason,
        diagnosed_stored_hash: facts.diagnosed_stored_hash,
        // `_bundle_rules` only reports rules for a `policy-bundle` row of the
        // package-request family. Such a row either comes with the
        // `policy_bundle` sync payload, and then this call already deferred
        // with `mcp_relay_saved_remote_policy`, or comes without one, and then
        // `validated_synced_policy_bundle` yields no rules either. Both ways
        // the staleness check reads the same absent rules.
        bundle_rules: None,
        // A relayed call resolves read-only.
        claim_saved_approval: false,
        claim_succeeded: None,
    };
    let resolution = resolve_unclaimed_resolution(&request).map_err(|_| RESOLVE_FAILED)?;
    let reused_decision = match resolution.reused {
        // `reused` without the row it reused is not a resolution this records.
        true => Some(request.decision.clone().ok_or(RESOLVE_FAILED)?),
        false => None,
    };
    let mut merged = evaluation.clone();
    merged.extend(resolution.output);
    Ok(PackagePolicy {
        evaluation: merged,
        current_action,
        artifact_hash,
        policy_workspace,
        execution_context,
        reused_decision,
        claim_disposition: resolution.claim_disposition,
    })
}

/// The saved-policy facts `_hydrate` procures, minus the daemon leg.
struct Facts {
    decision: Option<Value>,
    /// The approval request row the decision names, when it names a readable
    /// one.
    approval_request: Option<Value>,
    ignored_integrity: bool,
    diagnosed_reason: Option<String>,
    diagnosed_stored_hash: Option<String>,
}

/// The lookup identity the package policy probes a workspace with.
fn probe<'a>(artifact: &'a GuardArtifact, artifact_hash: &'a str, workspace: &'a str) -> Probe<'a> {
    Probe {
        harness: &artifact.harness,
        artifact_id: &artifact.artifact_id,
        artifact_hash: Some(artifact_hash),
        workspace: Some(workspace),
        publisher: artifact.publisher.as_deref(),
        // The package lookup selects on the saved row, not on an exact command
        // match, so it binds no exact-match context.
        exact_match_context: None,
    }
}

/// `_hydrate` (`native_package_policy_resolve.py:70`) over the relay's own
/// snapshot: the lookup, then either the approval-request row the decision
/// names or the diagnostic that explains the miss.
fn hydrate(
    saved: &Saved<'_>,
    artifact: &GuardArtifact,
    artifact_hash: &str,
    policy_workspace: Option<&str>,
    process_cwd: &str,
) -> Result<Facts, &'static str> {
    let mut decision: Option<Value> = None;
    let mut ignored_integrity = false;
    // `policy_workspaces` is the one runtime identity or none at all.
    if let Some(workspace) = policy_workspace {
        let lookup =
            saved.package_candidate(&probe(artifact, artifact_hash, workspace), process_cwd)?;
        let found = lookup.get("decision").cloned().unwrap_or(Value::Null);
        ignored_integrity = lookup
            .get("ignored_local_integrity")
            .is_some_and(|ignored| !ignored.is_null());
        if found.is_object() {
            decision = Some(found);
        }
    }
    if decision.is_none() && ignored_integrity {
        // Python asks the daemon's policy authority to resolve the row it
        // ignored. The relay has no such authority, and answering
        // `require-reapproval` in its place would decide a call the authority
        // may hold an allow for.
        return Err(DAEMON_AUTHORITY);
    }
    let mut facts = Facts {
        approval_request: match decision.as_ref() {
            Some(decision) => approval_request(saved, decision)?,
            None => None,
        },
        decision,
        ignored_integrity,
        diagnosed_reason: None,
        diagnosed_stored_hash: None,
    };
    // The miss is explained over the same one identity the lookup read.
    let diagnose = facts
        .decision
        .is_none()
        .then_some(policy_workspace)
        .flatten();
    if let Some(workspace) = diagnose {
        let (reason, stored) = saved.diagnosed(&probe(artifact, artifact_hash, workspace))?;
        if let Some(reason) = reason.as_str() {
            facts.diagnosed_reason = Some(reason.to_owned());
            facts.diagnosed_stored_hash = stored.as_str().map(str::to_owned);
        }
    }
    Ok(facts)
}

/// `package_current_action_and_hash` for a relayed call: the facts the proxy
/// hydrates for the approval-hash op, read from the bound view and the
/// snapshot instead.
fn current_action_and_hash(
    saved: &Saved<'_>,
    view: &HarnessView,
    artifact: &GuardArtifact,
    evaluation: &Map<String, Value>,
    control_digest: &str,
    workspace_dir: &str,
    execution_context: &PackageExecutionContext,
) -> Result<(GuardAction, String), &'static str> {
    let request = PackageApprovalHashRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: REQUEST_ID.to_owned(),
        guard_home: saved.guard_home.clone(),
        kind: "artifact_hash".to_owned(),
        artifact: artifact.to_dict(),
        evaluation: Value::Object(view_of(evaluation, &HASH_EVALUATION_FIELDS)?),
        config_policy: super::package_config::config_policy(view, artifact)?,
        sandbox_analysis: Some(super::package_config::sandbox_analysis(view)?),
        store_path: Some(saved.store_path.clone()),
        workspace_dir: Some(workspace_dir.to_owned()),
        execution_context: Some(json!({
            "digest": execution_context.digest,
            "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
            "components": execution_context
                .components
                .iter()
                .map(|component| json!({"name": component.name, "digest": component.digest}))
                .collect::<Vec<_>>(),
        })),
        extension_control_digest: Some(control_digest.to_owned()),
        feed_snapshot_hash: feed_snapshot_hash(saved)?,
        // A relayed `tools/call` carries no launcher identity, no second
        // current action and no extra policy context; the proxy omits all
        // three on this path.
        launch_identity: None,
        additional_current_action: None,
        additional_policy_context: None,
    };
    package_current_action_and_hash(&request).map_err(|_| HASH_FAILED)
}

/// `build_package_execution_context(workspace_dir=, artifact=)`: the build the
/// proxy runs in the resident, run here in process.
fn execution_context(
    saved: &Saved<'_>,
    artifact: &GuardArtifact,
    workspace_dir: &str,
    process: &ProcessFacts<'_>,
) -> Result<PackageExecutionContext, &'static str> {
    let request = PackageContextBuildRequestV1 {
        schema: PACKAGE_CONTEXT_BUILD_REQUEST_SCHEMA.to_owned(),
        request_id: REQUEST_ID.to_owned(),
        guard_home: saved.guard_home.clone(),
        workspace_dir: workspace_dir.to_owned(),
        metadata: metadata_facts(&artifact.metadata),
        // The proxy names no executable for a package request: the build
        // resolves the manager from the metadata and the ambient `PATH`.
        executable: None,
        executable_args: Vec::new(),
        environment: process.environment.clone(),
        process_cwd: process.cwd.to_owned(),
        process_home: process.home.to_owned(),
        process_home_env: process.environment.get("HOME").cloned(),
        process_path: process.environment.get("PATH").cloned(),
    };
    let built = build_execution_context(&request).map_err(|_| CONTEXT_UNBUILDABLE)?;
    Ok(PackageExecutionContext {
        digest: built.digest,
        portable: built.portable,
        components: built
            .components
            .into_iter()
            .map(|component| PackageExecutionContextComponent {
                name: component.name,
                digest: component.digest,
            })
            .collect(),
        non_portable_reason: built.non_portable_reason,
    })
}

/// `_metadata_facts`: the typed keys the build reads, every one present, so
/// the context depends on the metadata rather than on its shape.
fn metadata_facts(metadata: &Value) -> PackageContextBuildMetadataV1 {
    let text = |key: &str| metadata.get(key).and_then(Value::as_str).map(str::to_owned);
    let strings = |key: &str| {
        metadata
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };
    PackageContextBuildMetadataV1 {
        package_manager: text("package_manager"),
        package_executable: text("package_executable"),
        flags: strings("flags"),
        manifest_paths: strings("manifest_paths"),
        lockfile_paths: strings("lockfile_paths"),
    }
}

/// `_evaluation_view`: the named fields of the settled evaluation. Python
/// reads them off the dataclass, where every one exists; an evaluation missing
/// one is not the payload this was written against, so the call defers rather
/// than composing an action over an absent field.
fn view_of(
    evaluation: &Map<String, Value>,
    fields: &[&str],
) -> Result<Map<String, Value>, &'static str> {
    fields
        .iter()
        .map(|field| {
            evaluation
                .get(*field)
                .map(|value| ((*field).to_owned(), value.clone()))
                .ok_or(EVALUATION_INVALID)
        })
        .collect()
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_policy_tests.rs"]
mod tests;
