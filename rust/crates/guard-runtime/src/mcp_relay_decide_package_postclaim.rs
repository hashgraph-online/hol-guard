//! The route a claimed package call takes once its authority is re-read.
//!
//! Port of `_package_postclaim` and `_render_package_postclaim`
//! (`runtime_mcp.py:1799`, `:1902`). Once both saved approvals are claimed the
//! proxy re-resolves the tool authority, asks the resident's own
//! `package_postclaim` whether the claimed authority still covers what would
//! run now, and renders whichever half of the call the answer stops.
//!
//! The answer is lazy about the package half, and so is this port. The tool
//! half can stop the call on its own — a stored block, a terminal action, or
//! a call whose package request no longer resolves to an artifact — and the
//! resident says so before it asks for any package facts. Only when the tool
//! half neither stops nor short-circuits does it answer
//! `need = postclaim_package`, which is where the caller's supply runs. The
//! proxy's own supply re-resolves the package policy with the external archive
//! network authorized, which is a fresh supply-chain evaluation, so a call
//! stopped by the tool half pays for none of it.
//!
//! Each answered kind names the half whose receipt its evidence is appended
//! to: the tool legs carry `tool_evidence_append` against the tool call's own
//! artifact, and the package routes carry `package_evidence_append` against
//! the package request's. Exactly one of the two is ever present, so the route
//! the answer takes is also the receipt the evidence belongs on.
//!
//! A queued half is queued for re-approval, which the proxy passes as the
//! literal `require-reapproval` rather than reading it back off the answer.
//!
//! A kind neither half names is the proxy's `NativeMcpProxyDecisionError`;
//! here it defers, because a claimed call never guesses at a verdict.

use guard_contracts::{McpPackagePostclaimFactsV1, McpPackagePostclaimQueryV1, McpToolContextV1};
use serde_json::Value;

use super::package_route::{Decided, PackageRoute, ToolLeg};
use crate::mcp_proxy_actions::REQUIRE_REAPPROVAL;
use crate::mcp_tool_policy_decision::Decision;

/// The answer named a kind, or left out a field, this port cannot render.
pub(super) const PACKAGE_POSTCLAIM_FAILED: &str = "mcp_relay_package_postclaim_failed";

/// The facts the resident asks for once the tool half neither stops the call
/// nor short-circuits it.
const NEED_PACKAGE: &str = "postclaim_package";

/// The route a claimed package call takes, and the evidence its receipt
/// carries.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Postclaimed {
    pub(super) decided: Decided,
    /// `tool_evidence_append` for a tool leg, `package_evidence_append` for a
    /// package route: the half the route names is the half it belongs to.
    pub(super) append: Vec<Value>,
}

/// `package_postclaim` over the re-read tool authority, as a route.
///
/// `package` supplies the facts of a freshly resolved package policy, and runs
/// only if the resident asks for them.
pub(super) fn postclaim<F>(
    tool: &Decision,
    context: McpToolContextV1,
    package_artifact_present: bool,
    package: F,
) -> Result<Postclaimed, &'static str>
where
    F: FnOnce() -> Result<McpPackagePostclaimFactsV1, &'static str>,
{
    let mut query = McpPackagePostclaimQueryV1 {
        tool: crate::mcp_tool_policy_proxy::facts(tool),
        tool_context: context,
        package_artifact_present,
        package: None,
    };
    let mut reply = crate::mcp_proxy_postclaim::package_postclaim(&query);
    if reply["need"].as_str() == Some(NEED_PACKAGE) {
        query.package = Some(package()?);
        reply = crate::mcp_proxy_postclaim::package_postclaim(&query);
    }
    if !reply["need"].is_null() {
        return Err(PACKAGE_POSTCLAIM_FAILED);
    }
    let disposition = &reply["disposition"];
    let decided = match disposition["kind"].as_str() {
        Some("stored_tool_block") => Decided::Tool(ToolLeg::StoredBlock),
        Some("terminal_tool") => Decided::Tool(ToolLeg::Terminal {
            policy_action: action(disposition)?,
        }),
        Some("queue_tool") => Decided::Tool(ToolLeg::Queue {
            policy_action: REQUIRE_REAPPROVAL.to_owned(),
        }),
        Some("stored_package_block") => Decided::Package(PackageRoute::StoredPackageBlock),
        Some("terminal_package") => Decided::Package(PackageRoute::TerminalPackage {
            policy_action: action(disposition)?,
        }),
        Some("queue_package") => Decided::Package(PackageRoute::QueuePackage {
            policy_action: REQUIRE_REAPPROVAL.to_owned(),
        }),
        Some("forward") => Decided::Package(PackageRoute::Forward {
            policy_action: disposition["authoritative_action"]
                .as_str()
                .ok_or(PACKAGE_POSTCLAIM_FAILED)?
                .to_owned(),
        }),
        _ => return Err(PACKAGE_POSTCLAIM_FAILED),
    };
    let key = match decided {
        Decided::Tool(_) => "tool_evidence_append",
        Decided::Package(_) => "package_evidence_append",
        // The revalidation decides on the rows this claim already spent, so a
        // route that would claim them again is one it never answers with.
        Decided::ClaimPackage => return Err(PACKAGE_POSTCLAIM_FAILED),
    };
    let append = reply[key]
        .as_array()
        .cloned()
        .ok_or(PACKAGE_POSTCLAIM_FAILED)?;
    Ok(Postclaimed { decided, append })
}

/// The action a terminal half carries, which the proxy passes to the response
/// it renders.
fn action(disposition: &Value) -> Result<String, &'static str> {
    disposition["policy_action"]
        .as_str()
        .map(str::to_owned)
        .ok_or(PACKAGE_POSTCLAIM_FAILED)
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_postclaim_tests.rs"]
mod tests;
