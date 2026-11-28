//! The daemon's provider lookup pass (PRD 6.7, BP-T122).
//!
//! One pass takes the requests the decision path queued ([`take_lookups`]) and runs each through
//! the worker's lookup executor ([`run_lookup`]), which owns every send check, the token bucket,
//! the negative cache, the circuit and the `key_invalid` write. The answer is cached for the decide
//! step, so it applies from the next action on that subject. Nothing here runs on the decision
//! path: the hook only queues, and the daemon calls [`drain_lookups`] from its own loop.
//!
//! A request is skipped, not sent, when its provider no longer ships, when the cache already holds
//! a fresh answer from that provider for the subject, or when the provider is not connected. A
//! request the worker holds back (rate limit, circuit, recent failure) is dropped: the next action
//! on the subject queues it again.

use std::collections::BTreeMap;

use guard_command::provider_integration_compile::CompiledProviderIntegrationV1;
use guard_contracts::ProviderShareableFactV1;
use guard_provider_integrations::client::ProviderTransport;
use rusqlite::Connection;
use serde_json::Value;

use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::provider_integration_lookup::{run_lookup, LookupJob, LookupReport};
use crate::provider_integration_queue::{take_lookups, QueuedLookup};
use crate::provider_integration_store::{signals_for_subject, ProviderStoreResult};
use crate::provider_integration_worker::ProviderWorker;

/// Requests one pass takes at most. A pass holds the store for one provider timeout per send.
pub const MAX_LOOKUPS_PER_PASS: usize = 8;

/// Runs `send` with a transport pinned to the provider's hosts. The daemon passes the HTTPS client
/// under the managed network policy; tests pass the testkit's fake. `None` means no transport could
/// be built (a managed network policy Guard cannot honour), and nothing is sent.
pub type TransportFor<'a> = &'a dyn Fn(
    &CompiledProviderIntegrationV1,
    &mut dyn FnMut(&dyn ProviderTransport) -> ProviderStoreResult<LookupReport>,
) -> Option<ProviderStoreResult<LookupReport>>;

/// What became of one taken request. Codes only: no origin, key or provider text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassEntry {
    pub provider_id: String,
    pub outcome: &'static str,
}

/// Runs one pass. Store errors stop the pass; every other outcome is in the entries.
pub fn drain_lookups(
    worker: &mut ProviderWorker,
    connection: &Connection,
    secrets: &mut EncryptedFileSecretStore,
    providers: &[CompiledProviderIntegrationV1],
    transport_for: TransportFor<'_>,
    now_ms: u64,
    jitter: &mut dyn FnMut() -> u32,
) -> ProviderStoreResult<Vec<PassEntry>> {
    let mut entries = Vec::new();
    for queued in take_lookups(connection, now_ms, MAX_LOOKUPS_PER_PASS)? {
        let outcome = run_one(
            worker,
            connection,
            secrets,
            providers,
            transport_for,
            &queued,
            now_ms,
            jitter(),
        )?;
        entries.push(PassEntry {
            provider_id: queued.provider_id,
            outcome,
        });
    }
    Ok(entries)
}

#[allow(clippy::too_many_arguments)]
fn run_one(
    worker: &mut ProviderWorker,
    connection: &Connection,
    secrets: &mut EncryptedFileSecretStore,
    providers: &[CompiledProviderIntegrationV1],
    transport_for: TransportFor<'_>,
    queued: &QueuedLookup,
    now_ms: u64,
    jitter: u32,
) -> ProviderStoreResult<&'static str> {
    let Some(provider) = providers
        .iter()
        .find(|provider| provider.id == queued.provider_id)
    else {
        return Ok("provider_not_shipped");
    };
    let fresh = signals_for_subject(connection, queued.capability, &queued.subject.digest)?
        .iter()
        .any(|stored| stored.signal.provider_id == provider.id && stored.signal.is_live_at(now_ms));
    if fresh {
        return Ok("provider_answer_fresh");
    }
    let facts = BTreeMap::from([(
        ProviderShareableFactV1::TargetOrigin,
        Value::String(queued.origin.clone()),
    )]);
    let job = LookupJob {
        manifest: provider,
        manifest_digest: &provider.manifest_digest,
        capability: queued.capability,
        subject: queued.subject.clone(),
        facts: &facts,
        jitter,
        cache: true,
    };
    let report = transport_for(provider, &mut |transport| {
        run_lookup(worker, connection, secrets, transport, &job, now_ms)
    });
    Ok(match report {
        None => "provider_transport_unavailable",
        Some(report) => match report? {
            LookupReport::Answered { .. } => "provider_answered",
            LookupReport::Failed { code, .. } => code,
            LookupReport::NotSent(reason) => reason.code(),
        },
    })
}

#[cfg(test)]
#[path = "provider_integration_schedule_tests.rs"]
mod tests;
