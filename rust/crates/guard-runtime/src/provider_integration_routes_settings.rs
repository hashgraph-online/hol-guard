//! The settings routes: `settings/preview` and `settings`.
//!
//! A settings apply writes every row it names, so it must not land on top of a change it never
//! saw. The detail answer carries `settings_baseline`, a digest of the stored settings, opt-in
//! facts and connection; a preview that names a stale baseline is refused with
//! `provider_settings_changed`, and the preview's proof is bound to the baseline it read, so a
//! change made while the person reviews the preview spends the proof without applying it.

use super::*;
use crate::provider_integration_store::capability_settings;

/// `POST .../settings/preview` body: the settings the person wants and, optionally, the
/// `settings_baseline` they were read from.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsPreviewRequest {
    settings: Vec<ProviderCapabilitySettingsV1>,
    enabled_opt_in_facts: Vec<ProviderShareableFactV1>,
    #[serde(default)]
    baseline: Option<String>,
}

/// A digest of everything a settings apply overwrites: the stored capability settings, the
/// opt-in facts, and the connection's state and last update.
pub(super) fn settings_baseline(
    connection: &Connection,
    provider_id: &str,
) -> ProviderStoreResult<String> {
    let stored = provider_connection(connection, provider_id)?;
    let rows: Vec<_> = capability_settings(connection, provider_id)?
        .into_iter()
        .map(|(capability, setting)| {
            (
                capability.as_str(),
                setting.effect_level,
                setting.require_fresh,
            )
        })
        .collect();
    let connection_state = stored.map(|stored| {
        (
            stored.state,
            stored.opt_in_facts,
            stored.connected_at_ms,
            stored.updated_at_ms,
        )
    });
    let bytes = serde_json::to_vec(&(rows, connection_state)).unwrap_or_default();
    Ok(Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
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

    /// The proof binding: this exact change on top of this stored state.
    fn bound_to(&self, baseline: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.digest());
        hasher.update(baseline.as_bytes());
        hasher.finalize().into()
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

pub(super) fn settings_preview(
    ledger: &mut ProofLedger,
    context: &RouteContext<'_>,
    provider: &CompiledProviderIntegrationV1,
    body: &[u8],
) -> Result<RouteAnswer, RouteAnswer> {
    let request: SettingsPreviewRequest = read_body(body)?;
    let read = request.baseline;
    let change = SettingsChange {
        settings: request.settings,
        enabled_opt_in_facts: request.enabled_opt_in_facts,
    };
    let change = checked_change(context, provider, change)?;
    connected(context, &provider.id)?;
    let baseline =
        settings_baseline(context.connection, &provider.id).map_err(|_| unavailable())?;
    if read.is_some_and(|read| read != baseline) {
        return Err(error(409, SETTINGS_CHANGED));
    }
    let (challenge, expires_at_ms) = issue(
        ledger,
        context,
        &provider.id,
        ProofAction::Settings,
        change.bound_to(&baseline),
    )?;
    let mut answer = challenge_body(&provider.id, challenge, expires_at_ms);
    answer["settings"] = json!(change.settings);
    answer["enabled_opt_in_facts"] = json!(change.enabled_opt_in_facts);
    answer["baseline"] = json!(baseline);
    Ok(ok(answer))
}

pub(super) fn settings_apply(
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
    // The proof is bound to the stored state the preview saw, so a change another client made
    // since then (or a disconnect and reconnect) refuses this apply instead of being overwritten.
    let Ok(baseline) = settings_baseline(context.connection, &provider.id) else {
        ledger.discard(&request.proof);
        return Err(unavailable());
    };
    if !ledger.spend(
        &request.proof,
        &provider.id,
        ProofAction::Settings,
        change.bound_to(&baseline),
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

#[cfg(test)]
#[path = "provider_integration_routes_settings_tests.rs"]
mod tests;
