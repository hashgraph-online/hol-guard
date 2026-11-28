//! Cached provider answers on the browser approval card (BP-T134, PRD 6.8).
//!
//! The approval read model asks this module for the card's provider rows. It reads the provider
//! signal cache for the card's origin and nothing else: no lookup, no network, no waiting on the
//! worker. A row is listed only for a provider that is still connected to the same compiled
//! manifest, and an answer past its expiry is shown as stale. Every failure to read the cache
//! leaves the card without provider rows; it never fails the approval read.

use guard_command::browser_card_provider::provider_finding_row;
use guard_command::provider_integration_compile::CompiledProviderIntegrationV1;
use guard_contracts::{
    BrowserCardProviderFindingV1, ProviderCapabilityV1, ProviderConnectionStateV1,
    ProviderSignalStateV1,
};
use rusqlite::Connection;

use crate::provider_integration_purge::has_provider_tables;
use crate::provider_integration_routes::origin_subject;
use crate::provider_integration_store::{provider_connection, signals_for_subject};

/// Every capability, in card order. A subject digest is the hash of one canonical origin, so only
/// signals cached for this origin can match it.
const CAPABILITIES: [ProviderCapabilityV1; 5] = [
    ProviderCapabilityV1::OriginReputation,
    ProviderCapabilityV1::SitePolicy,
    ProviderCapabilityV1::PageDataRisk,
    ProviderCapabilityV1::ScriptIntegrity,
    ProviderCapabilityV1::DownloadReputation,
];

/// The rows for `origin` from the cached answers of `providers`.
pub(crate) fn provider_rows(
    connection: &Connection,
    providers: &[CompiledProviderIntegrationV1],
    origin: &str,
    now_ms: u64,
) -> Vec<BrowserCardProviderFindingV1> {
    if providers.is_empty() || !has_provider_tables(connection).unwrap_or(false) {
        return Vec::new();
    }
    let Some((_, subject)) = origin_subject(origin) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    for capability in CAPABILITIES {
        let Ok(signals) = signals_for_subject(connection, capability, &subject.digest) else {
            return Vec::new();
        };
        for stored in signals {
            let Some(provider) = providers
                .iter()
                .find(|provider| provider.id == stored.signal.provider_id)
            else {
                continue;
            };
            let connected = match provider_connection(connection, &provider.id) {
                Ok(Some(connected)) => connected,
                Ok(None) => continue,
                Err(_) => return Vec::new(),
            };
            if connected.state != ProviderConnectionStateV1::Connected
                || connected.manifest_digest != provider.manifest_digest
            {
                continue;
            }
            let Some(mut row) = provider_finding_row(provider, &stored.signal) else {
                continue;
            };
            if row.state == ProviderSignalStateV1::Fresh && now_ms >= stored.signal.expires_at_ms {
                row.state = ProviderSignalStateV1::Stale;
            }
            rows.push(row);
        }
    }
    rows
}

#[cfg(test)]
#[path = "approval_browser_provider_rows_tests.rs"]
mod tests;
