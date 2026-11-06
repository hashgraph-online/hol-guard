//! The external-archive binding a forwarded package call must hold.
//!
//! Port of `_bound_external_archive_mcp_request` (`runtime_mcp.py:98`) for the
//! relay's forward leg (`:1747`). An evaluation that resolved a package from an
//! external tarball is only allowed through once the request names the verified
//! local blob the evaluation downloaded, rather than the source URL the child
//! would fetch again. The proxy binds the call to those blobs before it writes
//! it to the child, and answers a call it cannot bind with the terminal
//! `mcp_unbound` block.
//!
//! The relay never reaches the bound branch. It authorizes the external-archive
//! network only for the evaluation it runs after a claim, and both evaluations
//! ask for `retain_external_archive_blob: false` (`mcp_relay_package_eval.rs`),
//! so neither holds a verified blob to bind to. A post-claim evaluation that
//! retained one is refused on the relay's own lane
//! (`mcp_relay_resident.rs`), since this process has no path to the proxy's
//! binding. Python in that same state asks
//! `native_external_archive_bind` for the empty binding with
//! `requires_binding=True`, which answers `unbound`, and the forward becomes the
//! block. This module is that one reachable branch: which evaluations demand the
//! binding, and the override the refusal is answered with.

use serde_json::{Map, Value};

use super::package_policy::PackagePolicy;
use guard_command::local_supply_chain::{
    package_evaluation_requires_external_archive_binding, PackageRequestEvaluation,
};

/// `package_external_archive_override` (`local_supply_chain.py:984`) and the
/// variant the proxy names for a relayed call it could not bind.
const OVERRIDE_KIND: &str = "external_archive_override";
const UNBOUND_VARIANT: &str = "mcp_unbound";

/// The defer this lane raises when the override itself cannot be composed. Like
/// every package-lane defer it names the package prefix, so the server is handed
/// to the proxy rather than answered here.
const PACKAGE_ARCHIVE_OVERRIDE: &str = "mcp_relay_package_archive_override";

/// Whether this evaluation only permits a request bound to the external
/// archives it verified.
pub(super) fn requires_binding(evaluation: &Map<String, Value>) -> bool {
    package_evaluation_requires_external_archive_binding(&PackageRequestEvaluation::new(
        Value::Object(evaluation.clone()),
    ))
}

/// The resolution a refused binding answers with: the same policy, carrying the
/// evaluation the `mcp_unbound` override composed over it.
pub(super) fn unbound(policy: &PackagePolicy) -> Result<PackagePolicy, &'static str> {
    let evaluation = crate::package_policy_resolve_op::rewrite(
        &policy.evaluation,
        OVERRIDE_KIND,
        None,
        Some(UNBOUND_VARIANT),
        None,
        None,
    )
    .map_err(|_| PACKAGE_ARCHIVE_OVERRIDE)?;
    Ok(PackagePolicy {
        evaluation,
        ..(*policy).clone()
    })
}

#[cfg(test)]
#[path = "mcp_relay_decide_package_archive_tests.rs"]
mod tests;
