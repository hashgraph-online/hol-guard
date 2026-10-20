//! The package leg of one relayed `tools/call`: the artifact, the stored
//! policy and the answer the lane settles, read on the decide path's own
//! snapshot.
//!
//! The proxy evaluates a package request before it resolves any policy for it
//! (`runtime_mcp.py:1365`), and that evaluation is a conversation: the
//! resident asks for archive and registry rounds the caller performs. A
//! `tools/call` decide cannot hold one, so the first decide of a package call
//! answers `evaluate` and the relay sends the same call again with the
//! evaluation attached. This module is what the second decide runs: the
//! package request's artifact, rebuilt from the intent the gate parsed, the
//! stored policy resolved against it, and the lane's answer over both.
//!
//! Everything the evaluation and the execution context are bound to belongs to
//! the relaying process, not the resident: its environment, its working
//! directory and its home (`_resident_environment`). They travel with the
//! request, and a call that is missing any of them defers rather than binding
//! the resident's own.
//!
//! The workspace is the one the policy lookup is valid for, so a call without
//! one defers as well. The proxy would resolve the policy under its working
//! directory, but it parses the intent under its `--workspace` alone, and the
//! drain rebuilds the artifact from the workspace the receipt names. A
//! substituted directory would rebuild another artifact, and the receipt the
//! drain cannot match is dropped rather than recorded.

use guard_command::package_intent_common::{
    build_package_request_artifact, GuardArtifact, PackageIntent,
};
use guard_contracts::{McpToolCallIdentityPayloadV1, McpToolPolicySubjectV1};

use serde_json::{Map, Value};

use super::package_lane::{self, PackageOutcome, QueueBinding};
use super::package_policy::{self, PackagePolicy, ProcessFacts};
use super::store::Saved;
use super::view::HarnessView;
use super::{run_policy, McpRelayDecideRequestV1};

/// A package call sent without the evaluation the lane decides from.
pub(super) const EVALUATION_ABSENT: &str = "mcp_relay_package_evaluation_absent";
/// A package call without the relaying process's own facts: the workspace the
/// policy lookup is valid for, its working directory or its environment.
const FACTS_ABSENT: &str = "mcp_relay_package_facts_absent";
/// No store to resolve the saved package policy against.
const STORE_ABSENT: &str = "mcp_relay_package_store_absent";

/// One decided package call, and what its receipt is written against.
pub(super) struct Packaged {
    /// The package request's own artifact, which the receipt names by id.
    pub(super) artifact: GuardArtifact,
    /// The workspace the intent was parsed against, which the drain rebuilds
    /// the artifact from.
    pub(super) workspace: String,
    /// The lane's own answer, or the leg the tool policy decided and the tool
    /// lane answers and records.
    pub(super) outcome: PackageOutcome,
}

/// Everything one package call's stored policy resolves from.
///
/// The lane resolves it twice — once to decide the route, once more for the
/// route that needs the fresh supply-chain answer — and a claimed call
/// resolves it again on the claimed store, from the evaluation the relay
/// re-read the request with. Holding the inputs keeps those resolutions the
/// same resolution.
pub(super) struct PackageInputs<'a, 'c> {
    /// The package request's own artifact, which the receipt names by id.
    pub(super) artifact: GuardArtifact,
    /// The workspace the intent was parsed against.
    pub(super) workspace: &'a str,
    saved: &'a Saved<'c>,
    view: &'a HarnessView,
    evaluation: &'a Map<String, Value>,
    control_digest: &'a str,
    process: ProcessFacts<'a>,
}

impl PackageInputs<'_, '_> {
    /// The stored package policy, resolved against the request's evaluation.
    pub(super) fn resolve(&self) -> Result<PackagePolicy, &'static str> {
        package_policy::package_policy(
            self.saved,
            self.view,
            &self.artifact,
            self.evaluation,
            self.control_digest,
            self.workspace,
            &self.process,
        )
    }
}

/// Gather what the package call's policy resolves from.
///
/// `evaluation` is the one the policy is resolved against: the decide path
/// passes the request's own, and a claimed call passes the one the relay
/// re-read the request with after the claim.
pub(super) fn package_inputs<'a, 'c>(
    request: &'a McpRelayDecideRequestV1,
    view: &'a HarnessView,
    saved: Option<&'a Saved<'c>>,
    control_digest: &'a str,
    identity: &McpToolCallIdentityPayloadV1,
    intent: &PackageIntent,
    evaluation: Option<&'a Map<String, Value>>,
) -> Result<PackageInputs<'a, 'c>, &'static str> {
    let evaluation = evaluation.ok_or(EVALUATION_ABSENT)?;
    let workspace = present(request.workspace.as_deref())?;
    let cwd = present(request.cwd.as_deref())?;
    if request.environment.is_empty() {
        return Err(FACTS_ABSENT);
    }
    // `package_policy` reads the saved rows the resolution is composed from,
    // so a call the store is unreadable for has no package policy at all.
    let saved = saved.ok_or(STORE_ABSENT)?;
    // The package request's artifact carries the tool call's own scope and
    // config path, as `_package_request_artifact` builds it.
    let artifact = build_package_request_artifact(
        &identity.artifact.harness,
        intent,
        &identity.artifact.config_path,
        &identity.artifact.source_scope,
    );
    Ok(PackageInputs {
        artifact,
        workspace,
        saved,
        view,
        evaluation,
        control_digest,
        process: ProcessFacts {
            environment: &request.environment,
            cwd,
            home: &request.launcher_home,
        },
    })
}

/// Decide the package call the gate found an intent in, from the inputs its
/// own evaluation resolves (`package_inputs`).
pub(super) fn decide_package_leg(
    request: &McpRelayDecideRequestV1,
    inputs: PackageInputs<'_, '_>,
    subject: &McpToolPolicySubjectV1,
    catalog: &crate::contributed_mcp_decision_op::Catalog<'_>,
    binding: QueueBinding<'_>,
) -> Result<Packaged, &'static str> {
    let resolved = inputs.resolve()?;
    let outcome = package_lane::decide_package(
        &inputs.view.mode,
        &request.build.tool_name,
        &request.build.server_name,
        &resolved,
        binding,
        // The proxy's second resolution, which reads the store the decide
        // path still holds open: the fresh tool authority, then the fresh
        // package policy.
        || {
            Ok((
                run_policy(
                    subject,
                    Some(inputs.saved),
                    Some(inputs.saved.connection),
                    catalog,
                )?,
                inputs.resolve()?,
            ))
        },
    )?;
    Ok(Packaged {
        artifact: inputs.artifact,
        workspace: inputs.workspace.to_owned(),
        outcome,
    })
}

/// One claimed package call's re-resolution, on the store the claim holds
/// open: the policy alone, and what the receipt it settles is written
/// against.
///
/// A claimed call takes no lane route. The route it takes is the post-claim
/// revalidation's, over this policy and the re-read tool authority together
/// (`mcp_relay_decide_package_claim.rs`), so the lane's own second resolution
/// — the one that would re-raise the pending claim this call is spending — is
/// not run at all.
pub(super) struct Reresolved {
    /// The package request's own artifact, rebuilt from the claimed call.
    pub(super) artifact: GuardArtifact,
    /// The workspace the intent was parsed against.
    pub(super) workspace: String,
    /// The package policy on the claimed store.
    pub(super) policy: PackagePolicy,
}

/// Re-resolve a claimed package call.
///
/// `evaluation` is the one the relay re-read the request with after the
/// claim, which is what the proxy resolves the post-claim package policy
/// from; everything else is the claimed call's own.
pub(super) fn reresolve_package_leg(
    request: &McpRelayDecideRequestV1,
    view: &HarnessView,
    saved: Option<&Saved<'_>>,
    control_digest: &str,
    identity: &McpToolCallIdentityPayloadV1,
    intent: &PackageIntent,
    evaluation: &Map<String, Value>,
) -> Result<Reresolved, &'static str> {
    let inputs = package_inputs(
        request,
        view,
        saved,
        control_digest,
        identity,
        intent,
        Some(evaluation),
    )?;
    let policy = inputs.resolve()?;
    Ok(Reresolved {
        artifact: inputs.artifact,
        workspace: inputs.workspace.to_owned(),
        policy,
    })
}

/// A request field the proxy sends for every package call, which a call
/// without it is not decided from.
fn present(field: Option<&str>) -> Result<&str, &'static str> {
    field.filter(|value| !value.is_empty()).ok_or(FACTS_ABSENT)
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_leg_tests.rs"]
mod tests;
