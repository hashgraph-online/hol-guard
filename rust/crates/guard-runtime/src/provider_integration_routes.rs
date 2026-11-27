//! The provider integration routes (PRD 6.9, BP-T130) that need no provider call.
//!
//! The daemon edge authenticates the caller (header token or dashboard session; hosted dashboard
//! origins are refused because no `/v1/integrations` path is a hosted dashboard API) and hands the
//! request here. This module answers from the compiled provider set, the provider store, managed
//! policy and its own one-use proof ledger:
//!
//! list, detail, `connect/preview`, `connect`, `settings/preview`, `settings`, `disconnect/preview`
//! and `disconnect` (the table in PRD 6.9).
//!
//! `connect` calls the provider, so it runs in three phases (`prepare_connect`, `verify_connect`,
//! `finish_connect`) and the caller holds no store lock while the provider answers. `test` belongs
//! to the lookup side.
//!
//! A challenge is bound to the provider, the action and the exact previewed body. It is spent by
//! the first apply that presents it, whether that apply succeeds or not, and it expires after
//! [`PROOF_TTL_MS`]. Managed policy wins: a requested setting that managed policy would change is
//! refused rather than silently raised. Rollback: `HOL_GUARD_PROVIDER_INTEGRATIONS=off` answers
//! every route `provider_capability_unavailable`.

use std::path::Path;

use guard_command::provider_integration_compile::CompiledProviderIntegrationV1;
use guard_contracts::{
    ProviderCapabilitySettingsV1, ProviderConnectionStateV1, ProviderDisconnectRequestV1,
    ProviderIntegrationErrorV1, ProviderSettingsRequestV1, ProviderShareableFactV1,
};
use guard_provider_integrations::parse::parse_strict_bounded;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::provider_integration_managed::ManagedProviderSettings;
pub use crate::provider_integration_proof::{
    ProofAction, ProofLedger, MAX_PENDING_PROOFS, PROOF_TTL_MS,
};
use crate::provider_integration_secret::delete_provider_key;
use crate::provider_integration_store::{
    forget_provider, in_write_savepoint, provider_connection, put_capability_setting,
    put_connection, CapabilitySetting, ProviderConnection, ProviderStoreResult,
};

/// The rollback switch.
pub const PROVIDER_INTEGRATIONS_ENV: &str = "HOL_GUARD_PROVIDER_INTEGRATIONS";
/// Largest request body these routes read.
pub const MAX_ROUTE_BODY_BYTES: usize = 16 * 1024;

const PREFIX: &str = "/v1/integrations/providers";

pub const PROOF_INVALID: &str = "provider_proof_invalid";
pub const NOT_FOUND: &str = "provider_not_found";
pub const NOT_CONNECTED: &str = "provider_not_connected";
pub const SETTING_MANAGED: &str = "provider_setting_managed";
pub const INVALID_REQUEST: &str = "invalid_request";
pub const CONNECT_SUPERSEDED: &str = "provider_connect_superseded";

/// Whether the rollback switch leaves provider integrations on.
pub fn provider_integrations_enabled(value: Option<&str>) -> bool {
    !matches!(
        value
            .map(|text| text.trim().to_ascii_lowercase())
            .as_deref(),
        Some("0" | "off" | "false" | "disabled")
    )
}

/// The switch as the process environment sets it.
pub fn provider_integrations_enabled_now() -> bool {
    provider_integrations_enabled(std::env::var(PROVIDER_INTEGRATIONS_ENV).ok().as_deref())
}

/// Everything a route reads besides the request.
pub struct RouteContext<'a> {
    pub enabled: bool,
    pub providers: &'a [CompiledProviderIntegrationV1],
    pub connection: &'a Connection,
    pub managed: &'a ManagedProviderSettings,
    /// Guard's home, which holds the encrypted provider keys.
    pub guard_home: &'a Path,
    pub now_ms: u64,
}

impl<'a> RouteContext<'a> {
    fn provider(&self, provider_id: &str) -> Option<&'a CompiledProviderIntegrationV1> {
        self.providers
            .iter()
            .find(|provider| provider.id == provider_id)
    }
}

/// A route's status and JSON body.
#[derive(Debug, Clone, PartialEq)]
pub struct RouteAnswer {
    pub status: u16,
    pub body: Value,
}

fn ok(body: Value) -> RouteAnswer {
    RouteAnswer { status: 200, body }
}

fn error(status: u16, code: &str) -> RouteAnswer {
    RouteAnswer {
        status,
        body: json!({ "error": code }),
    }
}

fn unavailable() -> RouteAnswer {
    error(
        503,
        ProviderIntegrationErrorV1::ProviderIntegrationUnavailable.code(),
    )
}

/// Whether this module answers `method path`.
pub fn owns(method: &str, path: &str) -> bool {
    matches!(
        (method, route(path)),
        ("GET", Some(Route::List | Route::Detail(_))) | ("POST", Some(Route::Post(_, _)))
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    ConnectPreview,
    Connect,
    SettingsPreview,
    Settings,
    DisconnectPreview,
    Disconnect,
}

enum Route<'p> {
    List,
    Detail(&'p str),
    Post(&'p str, Action),
}

fn route(path: &str) -> Option<Route<'_>> {
    let rest = path.strip_prefix(PREFIX)?;
    if rest.is_empty() {
        return Some(Route::List);
    }
    let parts: Vec<&str> = rest.strip_prefix('/')?.split('/').collect();
    if parts[0].is_empty() {
        return None;
    }
    let action = match parts[1..] {
        [] => return Some(Route::Detail(parts[0])),
        ["connect", "preview"] => Action::ConnectPreview,
        ["connect"] => Action::Connect,
        ["settings", "preview"] => Action::SettingsPreview,
        ["settings"] => Action::Settings,
        ["disconnect", "preview"] => Action::DisconnectPreview,
        ["disconnect"] => Action::Disconnect,
        _ => return None,
    };
    Some(Route::Post(parts[0], action))
}

/// `POST .../settings/preview` body: the settings the person wants.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SettingsChange {
    settings: Vec<ProviderCapabilitySettingsV1>,
    enabled_opt_in_facts: Vec<ProviderShareableFactV1>,
}

impl SettingsChange {
    /// Sorted, so the same change previews and applies to the same digest.
    fn normalized(mut self) -> Self {
        self.settings
            .sort_by(|left, right| left.capability.cmp(&right.capability));
        for setting in &mut self.settings {
            setting.quieted_reason_codes.sort();
        }
        self.enabled_opt_in_facts
            .sort_by_key(|fact| fact_rank(*fact));
        self.enabled_opt_in_facts.dedup();
        self
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::digest(serde_json::to_vec(self).unwrap_or_default()).into()
    }
}

fn fact_rank(fact: ProviderShareableFactV1) -> usize {
    ProviderShareableFactV1::ALL
        .iter()
        .position(|known| *known == fact)
        .unwrap_or(usize::MAX)
}

fn read_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, RouteAnswer> {
    if body.len() > MAX_ROUTE_BODY_BYTES {
        return Err(error(400, INVALID_REQUEST));
    }
    let value = if body.iter().all(u8::is_ascii_whitespace) {
        json!({})
    } else {
        parse_strict_bounded(body, MAX_ROUTE_BODY_BYTES)
            .ok_or_else(|| error(400, INVALID_REQUEST))?
    };
    serde_json::from_value(value).map_err(|_| error(400, INVALID_REQUEST))
}

/// Reads an apply body. A body that is valid JSON and names a `proof` but fails the typed shape
/// still spends that proof, so a refused first apply always spends its challenge. A body too large
/// or too malformed to read names no proof.
fn read_apply<T: serde::de::DeserializeOwned>(
    ledger: &mut ProofLedger,
    body: &[u8],
) -> Result<T, RouteAnswer> {
    read_body(body).inspect_err(|_| {
        if let Ok(value) = read_body::<Value>(body) {
            if let Some(proof) = value.get("proof").and_then(Value::as_str) {
                ledger.discard(proof);
            }
        }
    })
}

fn digest_of(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

/// Answer one authenticated request. `None` when the path is not one of these routes.
pub fn answer(
    ledger: &mut ProofLedger,
    context: &RouteContext<'_>,
    method: &str,
    path: &str,
    body: &[u8],
) -> Option<RouteAnswer> {
    if !owns(method, path) {
        return None;
    }
    if !context.enabled {
        return Some(error(
            503,
            ProviderIntegrationErrorV1::ProviderCapabilityUnavailable.code(),
        ));
    }
    Some(match route(path)? {
        Route::List => list(context).unwrap_or_else(|_| unavailable()),
        Route::Detail(id) => detail(context, id),
        Route::Post(id, action) => post(ledger, context, id, action, body),
    })
}

fn challenge_body(provider_id: &str, challenge: String, expires_at_ms: u64) -> Value {
    json!({
        "provider_id": provider_id,
        "challenge": challenge,
        "expires_at_ms": expires_at_ms,
    })
}

fn post(
    ledger: &mut ProofLedger,
    context: &RouteContext<'_>,
    provider_id: &str,
    action: Action,
    body: &[u8],
) -> RouteAnswer {
    let Some(provider) = context.provider(provider_id) else {
        return error(404, NOT_FOUND);
    };
    let result = match action {
        Action::ConnectPreview => connect_preview(ledger, context, provider, body),
        // The caller runs connect in phases so no store lock is held while the provider answers.
        Action::Connect => Err(unavailable()),
        Action::SettingsPreview => settings_preview(ledger, context, provider, body),
        Action::Settings => settings_apply(ledger, context, provider, body),
        Action::DisconnectPreview => disconnect_preview(ledger, context, provider, body),
        Action::Disconnect => disconnect(ledger, context, provider, body),
    };
    result.unwrap_or_else(|answer| answer)
}

fn issue(
    ledger: &mut ProofLedger,
    context: &RouteContext<'_>,
    provider_id: &str,
    action: ProofAction,
    body_digest: [u8; 32],
) -> Result<(String, u64), RouteAnswer> {
    ledger
        .issue(provider_id, action, body_digest, context.now_ms)
        .ok_or_else(unavailable)
}

fn connected(
    context: &RouteContext<'_>,
    provider_id: &str,
) -> Result<ProviderConnection, RouteAnswer> {
    match provider_connection(context.connection, provider_id) {
        Ok(Some(stored)) if stored.state != ProviderConnectionStateV1::NotConnected => Ok(stored),
        Ok(_) => Err(error(409, NOT_CONNECTED)),
        Err(_) => Err(unavailable()),
    }
}

/// Refuses a change that names an undeclared capability or fact, or that managed policy would
/// change. Returns the change sorted for its digest.
fn checked_change(
    context: &RouteContext<'_>,
    provider: &CompiledProviderIntegrationV1,
    change: SettingsChange,
) -> Result<SettingsChange, RouteAnswer> {
    let change = change.normalized();
    let declared = |capability| {
        provider
            .capabilities
            .iter()
            .any(|declared| declared.capability == capability)
    };
    let mut seen = Vec::new();
    for setting in &change.settings {
        if !declared(setting.capability) {
            return Err(error(
                422,
                ProviderIntegrationErrorV1::ProviderCapabilityUnavailable.code(),
            ));
        }
        if seen.contains(&setting.capability) || !setting.quieted_reason_codes.is_empty() {
            return Err(error(400, INVALID_REQUEST));
        }
        seen.push(setting.capability);
        let requested = CapabilitySetting {
            effect_level: setting.effect,
            require_fresh: setting.require_fresh_check,
        };
        if context
            .managed
            .effective(&provider.id, setting.capability, requested)
            != requested
        {
            return Err(error(409, SETTING_MANAGED));
        }
    }
    let offered = shares(provider);
    if change
        .enabled_opt_in_facts
        .iter()
        .any(|fact| !fact.opt_in_only() || !offered.contains(fact))
    {
        return Err(error(400, INVALID_REQUEST));
    }
    Ok(change)
}

fn settings_preview(
    ledger: &mut ProofLedger,
    context: &RouteContext<'_>,
    provider: &CompiledProviderIntegrationV1,
    body: &[u8],
) -> Result<RouteAnswer, RouteAnswer> {
    let change = checked_change(context, provider, read_body(body)?)?;
    connected(context, &provider.id)?;
    let (challenge, expires_at_ms) = issue(
        ledger,
        context,
        &provider.id,
        ProofAction::Settings,
        change.digest(),
    )?;
    let mut answer = challenge_body(&provider.id, challenge, expires_at_ms);
    answer["settings"] = json!(change.settings);
    answer["enabled_opt_in_facts"] = json!(change.enabled_opt_in_facts);
    Ok(ok(answer))
}

fn settings_apply(
    ledger: &mut ProofLedger,
    context: &RouteContext<'_>,
    provider: &CompiledProviderIntegrationV1,
    body: &[u8],
) -> Result<RouteAnswer, RouteAnswer> {
    let request: ProviderSettingsRequestV1 = read_apply(ledger, body)?;
    let change = SettingsChange {
        settings: request.settings,
        enabled_opt_in_facts: request.enabled_opt_in_facts,
    }
    .normalized();
    if !ledger.spend(
        &request.proof,
        &provider.id,
        ProofAction::Settings,
        change.digest(),
        context.now_ms,
    ) {
        return Err(error(403, PROOF_INVALID));
    }
    // Managed policy may have changed since the preview.
    let change = checked_change(context, provider, change)?;
    // The connection read and every write are one change: a failure leaves nothing applied. The
    // proof stays spent.
    let write = || -> ProviderStoreResult<Option<()>> {
        let Some(mut stored) = provider_connection(context.connection, &provider.id)?
            .filter(|stored| stored.state != ProviderConnectionStateV1::NotConnected)
        else {
            return Ok(None);
        };
        stored.opt_in_facts = change.enabled_opt_in_facts.clone();
        stored.updated_at_ms = context.now_ms;
        for setting in &change.settings {
            put_capability_setting(
                context.connection,
                &provider.id,
                setting.capability,
                CapabilitySetting {
                    effect_level: setting.effect,
                    require_fresh: setting.require_fresh_check,
                },
            )?;
        }
        put_connection(context.connection, &stored).map(Some)
    };
    in_write_savepoint(context.connection, write)
        .map_err(|_| unavailable())?
        .ok_or_else(|| error(409, NOT_CONNECTED))?;
    // Only a written change supersedes a connect that is still calling the provider.
    ledger.advance(&provider.id);
    Ok(ok(json!({ "provider_id": provider.id, "applied": true })))
}

fn disconnect_preview(
    ledger: &mut ProofLedger,
    context: &RouteContext<'_>,
    provider: &CompiledProviderIntegrationV1,
    body: &[u8],
) -> Result<RouteAnswer, RouteAnswer> {
    let _: serde_json::Map<String, Value> = read_body(body)?;
    let (challenge, expires_at_ms) = issue(
        ledger,
        context,
        &provider.id,
        ProofAction::Disconnect,
        digest_of(&provider.id),
    )?;
    Ok(ok(challenge_body(&provider.id, challenge, expires_at_ms)))
}

fn disconnect(
    ledger: &mut ProofLedger,
    context: &RouteContext<'_>,
    provider: &CompiledProviderIntegrationV1,
    body: &[u8],
) -> Result<RouteAnswer, RouteAnswer> {
    let request: ProviderDisconnectRequestV1 = read_apply(ledger, body)?;
    if !ledger.spend(
        &request.proof,
        &provider.id,
        ProofAction::Disconnect,
        digest_of(&provider.id),
        context.now_ms,
    ) {
        return Err(error(403, PROOF_INVALID));
    }
    ledger.advance(&provider.id);
    // The key goes first: a connection row without a key is harmless, a key without one is not.
    let secrets = EncryptedFileSecretStore::new(context.guard_home);
    delete_provider_key(&secrets, &provider.id).map_err(|_| unavailable())?;
    let was_connected =
        forget_provider(context.connection, &provider.id).map_err(|_| unavailable())?;
    Ok(ok(json!({
        "provider_id": provider.id,
        "disconnected": was_connected,
    })))
}

#[path = "provider_integration_routes_connect.rs"]
mod connect;
use connect::connect_preview;
pub use connect::{
    finish_connect, is_connect, prepare_connect, spend_connect_proof, verify_connect,
    PreparedConnect,
};

#[cfg(test)]
#[path = "provider_integration_routes_connect_tests.rs"]
mod connect_tests;

#[path = "provider_integration_routes_reads.rs"]
mod reads;
use reads::{detail, list, shares};

#[cfg(test)]
#[path = "provider_integration_routes_tests.rs"]
pub(crate) mod tests;
