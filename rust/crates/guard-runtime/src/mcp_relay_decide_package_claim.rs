//! What a claimed package call's spend composes, short of the store write.
//!
//! The claim itself is one write transaction (`mcp_relay_decide_claim.rs`):
//! both saved approvals, the read-only re-resolution of the tool authority and
//! the package policy, the post-claim revalidation and the answer all commit
//! together. This module is everything that transaction composes which reads
//! no store: the rows the claim spends, the two boundaries the revalidation
//! holds the fresh resolutions to, and the answer the route it returns is
//! settled as.
//!
//! The proxy's own order is `_package_postclaim` (`runtime_mcp.py:1799`). It
//! claims `(pending_tool, pending_package)` — whichever of the two the
//! resolutions left — re-reads the tool authority and rebuilds the package
//! request's artifact, and asks the resident whether the claimed authority
//! still covers what would run now. The package half of that question is
//! lazy, so the freshly resolved package policy is composed only once the
//! resident asks for it.
//!
//! A package route is answered against that post-claim resolution, not the one
//! the decision was made on, exactly as `_render_package_postclaim` renders it:
//! the artifact, the digest and the evaluation are the fresh ones, and the
//! post-claim evidence is appended to the package request's own receipt. A
//! tool leg instead carries that evidence on the tool call's receipt, which the
//! tool lane's settle records.

use guard_command::package_intent_common::GuardArtifact;
use guard_contracts::{McpPackagePostclaimFactsV1, McpToolContextV1};
use serde_json::{Map, Value};

use super::package_lane::{self, QueueBinding};
use super::package_leg::Packaged;
use super::package_policy::PackagePolicy;
use super::package_postclaim::{Postclaimed, PACKAGE_POSTCLAIM_FAILED};
use super::package_route::{self, Decided, ToolLeg};
use super::{Resolved, IDENTITY_FAILED};
use crate::approval_proof_op::{postclaim_review_authorized, Disposition};
use crate::mcp_tool_policy_decision::Decision;

/// The saved approvals a package call's forward spends, and the boundary the
/// post-claim revalidation holds the fresh resolutions to.
///
/// Either policy may have left a row, and a forward that claims is one where
/// at least one did. The artifact identities are the decision's own: what the
/// claimed approval was taken against, which the revalidation compares the
/// re-read identities with.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct PackageClaimed {
    /// `fresh_tool_decision.pending_approval_reuse_decision`.
    pub(super) tool: Option<Map<String, Value>>,
    pub(super) tool_disposition: Option<Disposition>,
    /// `fresh_package_resolution.pending_approval_reuse_decision`.
    pub(super) package: Option<Map<String, Value>>,
    pub(super) package_disposition: Option<Disposition>,
    pub(super) tool_artifact_id: String,
    pub(super) tool_artifact_hash: String,
    pub(super) package_artifact_id: String,
    pub(super) package_digest: String,
}

/// The rows a forward would spend, as the lane reports them.
///
/// The lane sees both resolutions and nothing else; the artifact identities
/// the revalidation is held to belong to the decision the caller settles, so
/// it is the caller that completes this into a `PackageClaimed`.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct ClaimLeg {
    tool: Option<Map<String, Value>>,
    tool_disposition: Option<Disposition>,
    package: Option<Map<String, Value>>,
    package_disposition: Option<Disposition>,
    package_digest: String,
}

/// The rows the two resolutions of one forward left unspent.
pub(super) fn claim_leg(authority: &Decision, policy: &PackagePolicy) -> ClaimLeg {
    ClaimLeg {
        tool: authority.pending.clone(),
        tool_disposition: authority.claim_disposition,
        package: pending(policy).cloned(),
        package_disposition: Disposition::parse(policy.claim_disposition.as_deref()),
        package_digest: policy.artifact_hash.clone(),
    }
}

/// The leg held against the identities the decision was made under: the tool
/// call's artifact, and the package request's own.
pub(super) fn claimed(
    leg: &ClaimLeg,
    resolved: &Resolved,
    artifact: &GuardArtifact,
) -> Result<PackageClaimed, &'static str> {
    Ok(PackageClaimed {
        tool: leg.tool.clone(),
        tool_disposition: leg.tool_disposition,
        package: leg.package.clone(),
        package_disposition: leg.package_disposition,
        tool_artifact_id: resolved.identity.artifact.artifact_id.clone(),
        tool_artifact_hash: resolved
            .identity
            .artifact_hash
            .clone()
            .ok_or(IDENTITY_FAILED)?,
        package_artifact_id: artifact.artifact_id.clone(),
        package_digest: leg.package_digest.clone(),
    })
}

/// The pending rows one package claim spends, in the proxy's own order:
/// `tuple(claim for claim in (pending_tool, pending_package) if claim is not
/// None)` (`runtime_mcp.py:1679`).
pub(super) fn rows(claimed: &PackageClaimed) -> Vec<&Map<String, Value>> {
    [claimed.tool.as_ref(), claimed.package.as_ref()]
        .into_iter()
        .flatten()
        .collect()
}

/// `tool_context`: where the claimed tool approval was taken, and where the
/// re-read authority stands now.
pub(super) fn tool_context(
    claimed: &PackageClaimed,
    fresh: &Resolved,
) -> Result<McpToolContextV1, &'static str> {
    Ok(McpToolContextV1 {
        artifact_id: fresh.identity.artifact.artifact_id.clone(),
        expected_artifact_id: claimed.tool_artifact_id.clone(),
        artifact_hash: fresh
            .identity
            .artifact_hash
            .clone()
            .ok_or(IDENTITY_FAILED)?,
        expected_artifact_hash: claimed.tool_artifact_hash.clone(),
    })
}

/// `package_facts_need` (`runtime_mcp.py:1829`): the freshly resolved package
/// policy, the boundary it is held to, and whether either claimed approval
/// still authorizes a review the fresh resolution reports.
pub(super) fn package_facts(
    claimed: &PackageClaimed,
    artifact: &GuardArtifact,
    policy: &PackagePolicy,
    fresh_tool: &Decision,
) -> Result<McpPackagePostclaimFactsV1, &'static str> {
    Ok(McpPackagePostclaimFactsV1 {
        facts: package_route::package_facts(policy)?,
        artifact_id: artifact.artifact_id.clone(),
        expected_artifact_id: claimed.package_artifact_id.clone(),
        digest: policy.artifact_hash.clone(),
        expected_digest: claimed.package_digest.clone(),
        tool_claim_authorizes_review: postclaim_review_authorized(
            claimed.tool_disposition,
            claimed.tool.as_ref(),
            fresh_tool.pending.as_ref(),
        ),
        package_claim_authorizes_review: postclaim_review_authorized(
            claimed.package_disposition,
            claimed.package.as_ref(),
            pending(policy),
        ),
    })
}

/// The saved row a resolved package policy reported without consuming, which
/// is the row the claim check compares the claimed one with.
pub(super) fn pending(policy: &PackagePolicy) -> Option<&Map<String, Value>> {
    policy.reused_decision.as_ref().and_then(Value::as_object)
}

/// What one claimed package call is answered by.
pub(super) enum Settled {
    /// The package lane's own answer, whose receipt the package request's
    /// artifact names.
    Package(Box<Packaged>),
    /// The leg the tool policy decided, which the tool lane answers and
    /// records against the tool call's own artifact, with the post-claim
    /// evidence on that receipt.
    Tool { leg: ToolLeg, append: Vec<Value> },
}

/// Settle the route the post-claim revalidation returned.
///
/// `policy` and `artifact` are the post-claim resolution's, because that is
/// what the proxy renders every package leg of this answer from. The lane
/// answers the route as it answers any other: a forward still refuses a
/// binding to external archives the relay retains none of, and a queued
/// request still takes the bound blocked-request mode.
pub(super) fn settled(
    postclaimed: Postclaimed,
    tool: &str,
    server: &str,
    policy: &PackagePolicy,
    artifact: GuardArtifact,
    workspace: &str,
    binding: QueueBinding<'_>,
) -> Result<Settled, &'static str> {
    let Postclaimed { decided, append } = postclaimed;
    let route = match decided {
        Decided::Tool(leg) => return Ok(Settled::Tool { leg, append }),
        Decided::Package(route) => route,
        // The revalidation decides on the rows this claim already spent, so a
        // route that would claim again is one the proxy never answers with.
        Decided::ClaimPackage => return Err(PACKAGE_POSTCLAIM_FAILED),
    };
    let mut outcome = package_lane::answered(&route, tool, server, policy, binding)?;
    outcome
        .answer_mut()
        .ok_or(PACKAGE_POSTCLAIM_FAILED)?
        .evidence
        .extend(append);
    Ok(Settled::Package(Box::new(Packaged {
        artifact,
        workspace: workspace.to_owned(),
        outcome,
    })))
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_claim_tests.rs"]
mod tests;
