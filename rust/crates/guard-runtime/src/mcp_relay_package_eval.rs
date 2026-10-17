//! The package evaluation the relay runs for a tool call that installs or runs
//! a package.
//!
//! Port of `_package_request_artifact` plus `_resolve_package_policy`'s
//! evaluation step (`runtime_mcp.py:1365`, `:1382`) over the native pieces: the
//! artifact the proxy builds from a parsed intent
//! (`build_package_request_artifact`), the request `native_supply_chain_eval`
//! sends (`native_supply_chain_eval.py:190`), and the rounds the caller drives
//! (`supply_chain_eval_rounds`).
//!
//! Only the caller's half is here. The verdict is the resident's, and this
//! module never reads one: it assembles a request, performs the exchanges the
//! resident asks for under the machine's managed network policy, and hands back
//! the settled payload or the reason there is none. A caller with no verdict
//! fails the call closed; it never answers from a weaker one.
//!
//! Two things this caller still defers. A `saved_policy_probe_required` answer
//! needs the approval-identity hash and the signed approval store, which live
//! on the Python side, so an evaluation that asks for one settles as "not a
//! verdict" rather than hydrating the row. Archive download and inspection
//! reach production through the resident's own APIs, so an evaluation is run
//! here without retaining blobs.

use guard_command::egress_caller_policy::ManagedEgressPolicy;
use guard_command::package_intent_common::{build_package_request_artifact, PackageIntent};
use guard_contracts::{SupplyChainEvalRequestV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA};

use crate::managed_policy_load::ManagedPolicySource;
use crate::supply_chain_eval_caller::CallerEgressFulfilment;
use crate::supply_chain_eval_rounds::{
    evaluate_rounds, RoundsError, SettledEvaluation, SupplyChainEvalTransport,
};

/// `guard.db` under the home, which is the store every package evaluation
/// reads (`store.path`).
const STORE_FILE: &str = "guard.db";

/// The session facts a package evaluation is built from. The relay already
/// holds every one of them for the decision request it sends.
pub(crate) struct PackageEvalFacts<'a> {
    /// The resolved guard home the evaluation and the resident share.
    pub(crate) guard_home: &'a str,
    /// The workspace the request is bound to, when the relay has one. Without
    /// it the evaluation is not workspace-bound, exactly as the proxy's is not.
    pub(crate) workspace: Option<&'a str>,
    /// The harness, scope and config path the artifact's identity is built
    /// from, as the decision request carries them.
    pub(crate) harness: &'a str,
    pub(crate) source_scope: &'a str,
    pub(crate) config_path: &'a str,
}

/// `native_supply_chain_eval_payload`'s request for one parsed intent.
///
/// The round fields (`request_id`, `now`, `egress_supplied`,
/// `egress_spool_dir`, `saved_policy_probe`) belong to the rounds loop and are
/// left unset here. An absent optional field is omitted rather than sent as
/// null, because the resident digests its typed request.
pub(crate) fn package_eval_request(
    facts: &PackageEvalFacts<'_>,
    intent: &PackageIntent,
    external_archive_network_authorized: bool,
) -> SupplyChainEvalRequestV1 {
    let artifact = build_package_request_artifact(
        facts.harness,
        intent,
        facts.config_path,
        facts.source_scope,
    );
    let private_metadata = match &artifact.runtime_private_metadata {
        // `if private_metadata:` — an empty mapping is not sent.
        value if value.as_object().is_some_and(|map| !map.is_empty()) => Some(value.clone()),
        _ => None,
    };
    SupplyChainEvalRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        store_path: format!(
            "{}{}{STORE_FILE}",
            facts.guard_home,
            std::path::MAIN_SEPARATOR
        ),
        guard_home: facts.guard_home.to_owned(),
        artifact: artifact.to_dict(),
        workspace_dir: facts.workspace.map(str::to_owned),
        now: None,
        external_archive_network_authorized,
        // The relay keeps no blob: the evidence a retained archive carries is
        // the proxy's to persist, and the resident's answer is complete
        // without one.
        retain_external_archive_blob: false,
        runtime_private_metadata: private_metadata,
        sync_auth_context_override: None,
        package_entitlement_override: None,
        registry_metadata_override: None,
        saved_policy_probe: None,
        egress_supplied: None,
        egress_spool_dir: None,
    }
}

/// Evaluate one package request and return the resident's settled payload.
///
/// The exchanges the resident asks for are performed under the machine's
/// managed network policy. A policy this caller cannot honour refuses every
/// exchange, so an evaluation that needs the network does not settle, while one
/// answered from the cache still does.
pub(crate) fn evaluate_package_request(
    facts: &PackageEvalFacts<'_>,
    intent: &PackageIntent,
    external_archive_network_authorized: bool,
    managed: &ManagedPolicySource,
    transport: &mut dyn SupplyChainEvalTransport,
) -> Result<SettledEvaluation, RoundsError> {
    let request = package_eval_request(facts, intent, external_archive_network_authorized);
    let policy = CallerEgressFulfilment::resolve_policy(managed);
    match policy {
        Ok(policy) => evaluate_under(request, &policy, transport),
        Err(reason) => {
            let mut egress = CallerEgressFulfilment::refusing(reason);
            evaluate_rounds(request, transport, &mut egress, None)
        }
    }
}

/// Split out so the resolved policy outlives the egress that borrows it.
fn evaluate_under(
    request: SupplyChainEvalRequestV1,
    policy: &ManagedEgressPolicy,
    transport: &mut dyn SupplyChainEvalTransport,
) -> Result<SettledEvaluation, RoundsError> {
    let mut egress = CallerEgressFulfilment::new(policy);
    // No saved-policy reader: the hash that lookup keys on is not this
    // caller's to compute, and an answer asking for one is not a verdict.
    evaluate_rounds(request, transport, &mut egress, None)
}

#[cfg(test)]
#[path = "mcp_relay_package_eval_tests.rs"]
mod tests;
