//! `connect/preview` and `connect`. The preview's challenge is bound to what it showed: the
//! provider, the shared facts and the hosts.
//!
//! `connect` calls the provider to check the key, so it runs in three phases. `prepare_connect`
//! spends the proof and checks the request, `verify_connect` sends the manifest's `verify` request
//! with no store lock held, and `finish_connect` stores the key and the connection row.

use guard_command::provider_integration_compile::{
    CompiledProviderIntegrationV1, ProviderHttpMethodV1,
};
use guard_contracts::{
    ProviderConnectPreviewV1, ProviderConnectRequestV1, ProviderConnectionStateV1,
    ProviderIntegrationErrorV1, ProviderShareableFactV1,
};
use guard_provider_integrations::client::{
    ProviderLimits, ProviderMethod, ProviderRequest, ProviderTransport,
};
use guard_provider_integrations::ProviderClientError;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{
    digest_of, error, fact_rank, issue, ok, read_apply, read_body, route, shares, unavailable,
    Action, ProofAction, ProofLedger, Route, RouteAnswer, RouteContext, CONNECT_SUPERSEDED,
    INVALID_REQUEST, NOT_FOUND, PROOF_INVALID,
};
use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::provider_integration_secret::{
    check_key_format, delete_provider_key, load_provider_key, store_provider_key, ProviderKey,
};
use crate::provider_integration_store::{
    in_write_savepoint, provider_connection, put_connection, ProviderConnection,
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

/// Whether `method path` is the connect route, which the caller runs in phases.
pub fn is_connect(method: &str, path: &str) -> bool {
    method == "POST" && matches!(route(path), Some(Route::Post(_, Action::Connect)))
}

/// A connect request whose proof was spent and whose key and facts passed every local check.
pub struct PreparedConnect<'p> {
    provider: &'p CompiledProviderIntegrationV1,
    key: ProviderKey,
    opt_in_facts: Vec<ProviderShareableFactV1>,
    /// The provider's ledger epoch when the proof was spent.
    epoch: u64,
}

impl PreparedConnect<'_> {
    /// The provider being connected; its pinned hosts bound the verify call.
    pub fn provider(&self) -> &CompiledProviderIntegrationV1 {
        self.provider
    }
}

fn key_invalid() -> RouteAnswer {
    error(400, ProviderIntegrationErrorV1::ProviderKeyInvalid.code())
}

/// Phase one, under the proof ledger: spend the proof, then check the facts and the key format.
/// The proof stays spent whatever follows.
pub fn prepare_connect<'p>(
    ledger: &mut ProofLedger,
    enabled: bool,
    providers: &'p [CompiledProviderIntegrationV1],
    path: &str,
    body: &[u8],
    now_ms: u64,
) -> Result<PreparedConnect<'p>, RouteAnswer> {
    if !enabled {
        return Err(error(
            503,
            ProviderIntegrationErrorV1::ProviderCapabilityUnavailable.code(),
        ));
    }
    let Some(Route::Post(provider_id, Action::Connect)) = route(path) else {
        return Err(error(404, NOT_FOUND));
    };
    let provider = providers
        .iter()
        .find(|provider| provider.id == provider_id)
        .ok_or_else(|| error(404, NOT_FOUND))?;
    let mut request: ProviderConnectRequestV1 = read_apply(ledger, body)?;
    let key = ProviderKey::new(Zeroizing::new(std::mem::take(&mut request.key)));
    if !spend_connect_proof(ledger, &request.proof, provider, now_ms) {
        return Err(error(403, PROOF_INVALID));
    }
    let epoch = ledger.epoch(&provider.id);
    let offered = shares(provider);
    let mut opt_in_facts = request.enabled_opt_in_facts;
    if opt_in_facts
        .iter()
        .any(|fact| !fact.opt_in_only() || !offered.contains(fact))
    {
        return Err(error(400, INVALID_REQUEST));
    }
    opt_in_facts.sort_by_key(|fact| fact_rank(*fact));
    opt_in_facts.dedup();
    check_key_format(key.expose(), &provider.auth).map_err(|_| key_invalid())?;
    Ok(PreparedConnect {
        provider,
        key,
        opt_in_facts,
        epoch,
    })
}

/// Phase two, with no store lock held: send the manifest's `verify` request. `Ok(true)` when the
/// provider accepted the key, `Ok(false)` when the manifest declares no verify request.
pub fn verify_connect(
    prepared: &PreparedConnect<'_>,
    transport: &dyn ProviderTransport,
) -> Result<bool, RouteAnswer> {
    let provider = prepared.provider;
    let Some(verify) = &provider.verify else {
        return Ok(false);
    };
    let request = ProviderRequest {
        method: match verify.method {
            ProviderHttpMethodV1::Get => ProviderMethod::Get,
            ProviderHttpMethodV1::Post => ProviderMethod::Post,
        },
        host: verify.host.clone(),
        path: verify.path.clone(),
        header: provider.auth.header.clone(),
        key: Zeroizing::new(prepared.key.expose().to_owned()),
        body: None,
    };
    let limits = ProviderLimits {
        timeout_ms: provider.limits.timeout_ms,
        max_response_bytes: provider.limits.max_response_bytes,
    };
    let code = |code: ProviderIntegrationErrorV1, status| error(status, code.code());
    match transport.send(&request, limits) {
        Ok(response) if (200..300).contains(&response.status) => Ok(true),
        Ok(response) if matches!(response.status, 401 | 403) => Err(key_invalid()),
        Ok(response) if response.status == 429 => {
            Err(code(ProviderIntegrationErrorV1::ProviderRateLimited, 429))
        }
        Err(ProviderClientError::HostNotPinned | ProviderClientError::Blocked) => {
            Err(code(ProviderIntegrationErrorV1::ProviderHostRefused, 403))
        }
        Err(ProviderClientError::ResponseTooLarge) => Err(code(
            ProviderIntegrationErrorV1::ProviderResponseTooLarge,
            502,
        )),
        Err(ProviderClientError::CredentialInvalid) => Err(key_invalid()),
        _ => Err(code(
            ProviderIntegrationErrorV1::ProviderIntegrationUnavailable,
            502,
        )),
    }
}

/// Phase three, under the storage gate and the proof ledger: store the key, then the connection
/// row bound to the manifest digest. A disconnect, settings apply or other connect that finished
/// after this one's proof was spent refuses it with `409 provider_connect_superseded`, and nothing
/// is written. A row that fails to write puts back the key the provider had before, or removes the
/// new one when there was none.
pub fn finish_connect(
    ledger: &mut ProofLedger,
    context: &RouteContext<'_>,
    prepared: PreparedConnect<'_>,
    verified: bool,
) -> RouteAnswer {
    let provider = prepared.provider;
    if ledger.epoch(&provider.id) != prepared.epoch {
        return error(409, CONNECT_SUPERSEDED);
    }
    ledger.advance(&provider.id);
    let mut secrets = EncryptedFileSecretStore::new(context.guard_home);
    let previous = load_provider_key(&mut secrets, &provider.id);
    if store_provider_key(&mut secrets, &provider.id, &prepared.key, &provider.auth).is_err() {
        return unavailable();
    }
    let write = || {
        let connected_at_ms = provider_connection(context.connection, &provider.id)?
            .filter(|stored| stored.state != ProviderConnectionStateV1::NotConnected)
            .map_or(context.now_ms, |stored| stored.connected_at_ms);
        put_connection(
            context.connection,
            &ProviderConnection {
                provider_id: provider.id.clone(),
                manifest_digest: provider.manifest_digest.clone(),
                state: ProviderConnectionStateV1::Connected,
                opt_in_facts: prepared.opt_in_facts.clone(),
                connected_at_ms,
                updated_at_ms: context.now_ms,
                last_verified_at_ms: verified.then_some(context.now_ms),
            },
        )
    };
    if in_write_savepoint(context.connection, write).is_err() {
        let restored = previous.is_some_and(|key| {
            store_provider_key(&mut secrets, &provider.id, &key, &provider.auth).is_ok()
        });
        if !restored {
            let _ = delete_provider_key(&secrets, &provider.id);
        }
        return unavailable();
    }
    super::detail(context, &provider.id)
}
