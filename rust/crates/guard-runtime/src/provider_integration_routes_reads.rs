//! The read routes: the provider list and one provider's detail. Neither carries secret material.

use std::collections::BTreeMap;

use guard_command::provider_integration_compile::CompiledProviderIntegrationV1;
use guard_contracts::{
    ProviderAuthKindV1, ProviderCapabilitySettingsV1, ProviderConnectionStateV1, ProviderDetailV1,
    ProviderShareableFactV1, ProviderSummaryV1,
};
use serde_json::{json, Value};

use super::settings::settings_baseline;
use super::{error, fact_rank, ok, unavailable, RouteAnswer, RouteContext, NOT_FOUND};
use crate::provider_integration_store::{
    capability_settings, provider_connection, provider_connections, ProviderConnection,
};

fn state_of(stored: Option<&ProviderConnection>) -> ProviderConnectionStateV1 {
    stored.map_or(ProviderConnectionStateV1::NotConnected, |stored| {
        stored.state
    })
}

fn summary(
    provider: &CompiledProviderIntegrationV1,
    stored: Option<&ProviderConnection>,
) -> ProviderSummaryV1 {
    ProviderSummaryV1 {
        id: provider.id.clone(),
        name: provider.name.clone(),
        summary: provider.summary.clone(),
        verified: provider.verified,
        state: state_of(stored),
        capabilities: provider
            .capabilities
            .iter()
            .map(|capability| capability.capability)
            .collect(),
    }
}

pub(super) fn list(context: &RouteContext<'_>) -> Result<RouteAnswer, RouteAnswer> {
    let stored: BTreeMap<String, ProviderConnection> = provider_connections(context.connection)
        .map_err(|_| unavailable())?
        .into_iter()
        .map(|stored| (stored.provider_id.clone(), stored))
        .collect();
    let providers: Vec<ProviderSummaryV1> = context
        .providers
        .iter()
        .map(|provider| summary(provider, stored.get(&provider.id)))
        .collect();
    Ok(ok(json!({ "providers": providers })))
}

pub(super) fn shares(provider: &CompiledProviderIntegrationV1) -> Vec<ProviderShareableFactV1> {
    let mut facts: Vec<ProviderShareableFactV1> = provider
        .capabilities
        .iter()
        .flat_map(|capability| capability.shares.iter().copied())
        .collect();
    facts.sort_by_key(|fact| fact_rank(*fact));
    facts.dedup();
    facts
}

pub(super) fn detail(context: &RouteContext<'_>, provider_id: &str) -> RouteAnswer {
    let Some(provider) = context.provider(provider_id) else {
        return error(404, NOT_FOUND);
    };
    let read =
        || -> Result<ProviderDetailV1, crate::provider_integration_store::ProviderStoreError> {
            let stored = provider_connection(context.connection, provider_id)?;
            let local = capability_settings(context.connection, provider_id)?;
            let settings = provider
                .capabilities
                .iter()
                .map(|capability| {
                    let setting = context.managed.effective(
                        provider_id,
                        capability.capability,
                        local
                            .get(&capability.capability)
                            .copied()
                            .unwrap_or_default(),
                    );
                    ProviderCapabilitySettingsV1 {
                        capability: capability.capability,
                        effect: setting.effect_level,
                        require_fresh_check: setting.require_fresh,
                        quieted_reason_codes: Vec::new(),
                    }
                })
                .collect();
            let mut cache_counts = BTreeMap::new();
            for capability in &provider.capabilities {
                let count: i64 = context.connection.query_row(
                "select count(*) from provider_signals where provider_id = ?1 and capability = ?2",
                rusqlite::params![provider_id, capability.capability.as_str()],
                |row| row.get(0),
            )?;
                cache_counts.insert(
                    capability.capability.as_str().to_owned(),
                    u64::try_from(count).unwrap_or_default(),
                );
            }
            Ok(ProviderDetailV1 {
                summary: summary(provider, stored.as_ref()),
                auth_kind: ProviderAuthKindV1::ApiKey,
                shares: shares(provider),
                enabled_opt_in_facts: stored
                    .as_ref()
                    .map(|stored| stored.opt_in_facts.clone())
                    .unwrap_or_default(),
                settings,
                last_verified_at_ms: stored.and_then(|stored| stored.last_verified_at_ms),
                cache_counts,
                settings_baseline: settings_baseline(context.connection, provider_id)?,
            })
        };
    match read() {
        Ok(detail) => ok(serde_json::to_value(detail).unwrap_or(Value::Null)),
        Err(_) => unavailable(),
    }
}
