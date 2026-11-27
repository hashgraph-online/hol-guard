//! `connect/preview` and the proof the connect route spends. The challenge is bound to what the
//! preview showed: the provider, the shared facts and the hosts.

use guard_command::provider_integration_compile::CompiledProviderIntegrationV1;
use guard_contracts::{ProviderConnectPreviewV1, ProviderShareableFactV1};
use serde_json::{json, Value};

use super::{
    digest_of, issue, ok, read_body, shares, unavailable, ProofAction, ProofLedger, RouteAnswer,
    RouteContext,
};

/// Spends a `connect/preview` challenge for the connect route, which stores the key only when this
/// is true. The challenge is bound to what the preview showed: the shared facts and hosts.
pub fn spend_connect_proof(
    ledger: &mut ProofLedger,
    proof: &str,
    provider: &CompiledProviderIntegrationV1,
    now_ms: u64,
) -> bool {
    ledger.spend(
        proof,
        &provider.id,
        ProofAction::Connect,
        connect_digest(provider),
        now_ms,
    )
}

fn connect_digest(provider: &CompiledProviderIntegrationV1) -> [u8; 32] {
    digest_of(&json!([provider.id, shares(provider), provider.hosts]).to_string())
}

pub(super) fn connect_preview(
    ledger: &mut ProofLedger,
    context: &RouteContext<'_>,
    provider: &CompiledProviderIntegrationV1,
    body: &[u8],
) -> Result<RouteAnswer, RouteAnswer> {
    let _: serde_json::Map<String, Value> = read_body(body)?;
    let shares = shares(provider);
    let opt_in_facts: Vec<ProviderShareableFactV1> = shares
        .iter()
        .copied()
        .filter(|fact| fact.opt_in_only())
        .collect();
    let (challenge, expires_at_ms) = issue(
        ledger,
        context,
        &provider.id,
        ProofAction::Connect,
        connect_digest(provider),
    )?;
    let preview = ProviderConnectPreviewV1 {
        provider_id: provider.id.clone(),
        shares: shares
            .into_iter()
            .filter(|fact| !fact.opt_in_only())
            .collect(),
        opt_in_facts,
        hosts: provider.hosts.clone(),
        challenge,
        expires_at_ms,
    };
    Ok(ok(serde_json::to_value(preview).map_err(|_| unavailable())?))
}
