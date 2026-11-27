//! The provider enrichment worker's lookup executor (PRD 6.7, BP-T122).
//!
//! One call runs one lookup end to end, off the hook path:
//!
//! 1. Read the stored connection. Nothing is sent unless the user connected exactly this compiled
//!    manifest (`manifest_digest`) and the connection is still `connected`.
//! 2. Check the facts the request would carry. Only the facts the capability declares are used.
//!    An opt-in fact (`target.path_prefix`) goes out only when the user turned it on at connect,
//!    and an origin or site group on a loopback, private, `.local`, `.internal`, `.test` or
//!    single-label host is never sent (PRD 6.4). A refused fact stops the lookup before a token is
//!    taken.
//! 3. Load the provider key. A provider with no stored key is not called.
//! 4. Ask [`ProviderWorker::admit`] for a token, render the body with the provider crate's
//!    renderer and send the request through the given transport. Tests pass the testkit's fake;
//!    the daemon passes the pinned HTTPS client.
//! 5. Map a `2xx` answer through the manifest with the provider crate's `map_answer` and cache it
//!    with [`put_signal`]. `401` and `403` count as `Unauthorized`, `429` as `RateLimited`, and any
//!    other status, client error or unmappable body as `Failed`.
//! 6. Report the outcome to [`ProviderWorker::record`], which owns the negative cache, the circuit
//!    and the `key_invalid` write.
//!
//! The report carries codes only. Provider text never leaves the mapping step, and the key is held
//! in `Zeroizing` memory and never logged.

use std::collections::BTreeMap;

use guard_command::provider_integration_compile::{
    CompiledProviderCapabilityV1, CompiledProviderIntegrationV1, ProviderHttpMethodV1,
};
use guard_command::provider_origin_share::{
    provider_host_is_shareable, provider_origin_is_shareable,
};
use guard_contracts::{
    ProviderCapabilityV1, ProviderInventoryV1, ProviderShareableFactV1, ProviderSignalStateV1,
    ProviderSignalV1, ProviderSubjectV1, PROVIDER_SIGNAL_V1_VERSION,
};
use guard_provider_integrations::answer::{
    map_answer, AnswerMapping, ReasonCodeMapping, TtlMapping,
};
use guard_provider_integrations::client::{
    ProviderLimits, ProviderMethod, ProviderRequest, ProviderTransport,
};
use guard_provider_integrations::render::render_body;
use rusqlite::Connection;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::provider_integration_secret::load_provider_key;
use crate::provider_integration_store::{
    provider_connection, put_signal, ProviderStoreResult, PutSignalOutcome,
};
use crate::provider_integration_worker::{
    refresh_at, Admission, ExchangeOutcome, ProviderWorker, Recorded,
};

/// How long an answer is cached when the manifest declares no lifetime for it.
pub const DEFAULT_ANSWER_TTL_MS: u64 = 15 * 60 * 1000;

/// One lookup the worker was asked to run.
pub struct LookupJob<'a> {
    pub manifest: &'a CompiledProviderIntegrationV1,
    /// SHA-256 of `manifest`, compared with the digest the user connected.
    pub manifest_digest: &'a str,
    pub capability: ProviderCapabilityV1,
    pub subject: ProviderSubjectV1,
    /// The facts Guard holds for the subject. Only those the capability declares are read.
    pub facts: &'a BTreeMap<ProviderShareableFactV1, Value>,
    /// Any random `u32`; places the refresh point (see [`refresh_at`]).
    pub jitter: u32,
}

/// Why a lookup was not sent. None of these counts as a provider failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotSent {
    /// The provider has no stored connection.
    NotConnected,
    /// The stored connection was made for another version of the manifest.
    ManifestChanged,
    /// The manifest does not declare this capability.
    CapabilityUndeclared,
    /// The declared request sends no fact (a `GET`, or a `POST` with no body), so the answer
    /// would not be about this subject and could not be cached under it.
    SubjectNotCarried,
    /// A fact the request needs was refused (see the module notes) or is missing.
    FactRefused(ProviderShareableFactV1),
    /// The declared body could not be rendered from the facts.
    BodyInvalid,
    /// The provider has no stored key.
    KeyMissing,
    /// The worker held the lookup back.
    Held(Admission),
}

impl NotSent {
    pub fn code(self) -> &'static str {
        match self {
            Self::NotConnected => "provider_not_connected",
            Self::ManifestChanged => "provider_manifest_changed",
            Self::CapabilityUndeclared => "provider_capability_undeclared",
            Self::SubjectNotCarried => "provider_subject_not_carried",
            Self::FactRefused(_) => "provider_fact_refused",
            Self::BodyInvalid => "provider_body_invalid",
            Self::KeyMissing => "provider_key_missing",
            Self::Held(Admission::Send) => "provider_admitted",
            Self::Held(Admission::NotConnected(_)) => "provider_not_connected",
            Self::Held(Admission::CircuitOpen { .. }) => "provider_circuit_open",
            Self::Held(Admission::RecentlyFailed { .. }) => "provider_recently_failed",
            Self::Held(Admission::RateLimited) => "provider_rate_limited",
        }
    }
}

/// How a lookup ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupReport {
    NotSent(NotSent),
    /// The provider answered and the answer went to the cache.
    Answered {
        signal: ProviderSignalV1,
        stored: PutSignalOutcome,
        /// When the worker should ask again.
        refresh_at_ms: u64,
        recorded: Recorded,
    },
    /// The exchange failed. `code` is a stable failure code, never provider text.
    Failed {
        outcome: ExchangeOutcome,
        code: &'static str,
        recorded: Recorded,
    },
}

/// The stable string id of a shareable fact, as the manifest and the renderer spell it.
pub fn fact_id(fact: ProviderShareableFactV1) -> &'static str {
    match fact {
        ProviderShareableFactV1::TargetOrigin => "target.origin",
        ProviderShareableFactV1::TargetSiteGroup => "target.site_group",
        ProviderShareableFactV1::TargetPathPrefix => "target.path_prefix",
        ProviderShareableFactV1::ActionVerb => "action.verb",
        ProviderShareableFactV1::ActionIntent => "action.intent",
        ProviderShareableFactV1::PageScriptHashes => "page.script_hashes",
        ProviderShareableFactV1::DownloadSha256 => "download.sha256",
        ProviderShareableFactV1::GuardVersion => "guard.version",
    }
}

fn fact_value_is_shareable(fact: ProviderShareableFactV1, value: &Value) -> bool {
    match fact {
        ProviderShareableFactV1::TargetOrigin => {
            value.as_str().is_some_and(provider_origin_is_shareable)
        }
        ProviderShareableFactV1::TargetSiteGroup => {
            value.as_str().is_some_and(provider_host_is_shareable)
        }
        _ => true,
    }
}

/// The facts the request will carry, keyed by fact id, or the first fact that may not be sent.
fn shared_facts(
    capability: &CompiledProviderCapabilityV1,
    facts: &BTreeMap<ProviderShareableFactV1, Value>,
    opt_in: &[ProviderShareableFactV1],
) -> Result<BTreeMap<String, Value>, ProviderShareableFactV1> {
    let mut shared = BTreeMap::new();
    for (_, fact) in &capability.request.body {
        if fact.opt_in_only() && !opt_in.contains(fact) {
            return Err(*fact);
        }
        let Some(value) = facts.get(fact) else {
            return Err(*fact);
        };
        if !fact_value_is_shareable(*fact, value) {
            return Err(*fact);
        }
        shared.insert(fact_id(*fact).to_owned(), value.clone());
    }
    Ok(shared)
}

fn answer_mapping(capability: &CompiledProviderCapabilityV1) -> AnswerMapping<'_> {
    AnswerMapping {
        verdict_pointer: &capability.verdict_pointer,
        verdict_map: &capability.verdict_map,
        reason_codes: capability
            .reason_codes
            .as_ref()
            .map(|codes| ReasonCodeMapping {
                pointer: &codes.pointer,
                allow: &codes.allow,
            }),
        ttl: capability.ttl.as_ref().map(|ttl| TtlMapping {
            pointer: &ttl.pointer,
            min_seconds: ttl.min_seconds,
            max_seconds: ttl.max_seconds,
        }),
    }
}

/// Where the answer's inventory came from: the device when the request carried the page's script
/// hashes, the provider's own records for a script or page-data question asked without them, and
/// none for a question that needs no inventory (PRD 6.3).
fn inventory(capability: &CompiledProviderCapabilityV1) -> ProviderInventoryV1 {
    let sends_scripts = capability
        .request
        .body
        .iter()
        .any(|(_, fact)| *fact == ProviderShareableFactV1::PageScriptHashes);
    match capability.capability {
        _ if sends_scripts => ProviderInventoryV1::Device,
        ProviderCapabilityV1::ScriptIntegrity | ProviderCapabilityV1::PageDataRisk => {
            ProviderInventoryV1::ProviderSide
        }
        _ => ProviderInventoryV1::None,
    }
}

fn status_outcome(status: u16) -> ExchangeOutcome {
    match status {
        200..=299 => ExchangeOutcome::Answered,
        401 | 403 => ExchangeOutcome::Unauthorized,
        429 => ExchangeOutcome::RateLimited,
        _ => ExchangeOutcome::Failed,
    }
}

fn status_code(outcome: ExchangeOutcome) -> &'static str {
    match outcome {
        ExchangeOutcome::Answered => "provider_answered",
        ExchangeOutcome::Unauthorized => "provider_unauthorized",
        ExchangeOutcome::RateLimited => "provider_rate_limited",
        ExchangeOutcome::Failed => "provider_status_failed",
    }
}

/// Run one lookup. Store errors are returned; every other failure is in the report.
pub fn run_lookup(
    worker: &mut ProviderWorker,
    connection: &Connection,
    secrets: &mut EncryptedFileSecretStore,
    transport: &dyn ProviderTransport,
    job: &LookupJob<'_>,
    now_ms: u64,
) -> ProviderStoreResult<LookupReport> {
    let manifest = job.manifest;
    let not_sent = |reason| Ok(LookupReport::NotSent(reason));
    let Some(stored) = provider_connection(connection, &manifest.id)? else {
        return not_sent(NotSent::NotConnected);
    };
    if stored.manifest_digest != job.manifest_digest {
        return not_sent(NotSent::ManifestChanged);
    }
    let Some(capability) = manifest
        .capabilities
        .iter()
        .find(|declared| declared.capability == job.capability)
    else {
        return not_sent(NotSent::CapabilityUndeclared);
    };
    if capability.request.method != ProviderHttpMethodV1::Post || capability.request.body.is_empty()
    {
        return not_sent(NotSent::SubjectNotCarried);
    }
    let facts = match shared_facts(capability, job.facts, &stored.opt_in_facts) {
        Ok(facts) => facts,
        Err(fact) => return not_sent(NotSent::FactRefused(fact)),
    };
    let fields: Vec<(&str, &str)> = capability
        .request
        .body
        .iter()
        .map(|(field, fact)| (field.as_str(), fact_id(*fact)))
        .collect();
    let body = match render_body(&fields, &facts) {
        Ok(body) => body,
        Err(_) => return not_sent(NotSent::BodyInvalid),
    };
    let Some(key) = load_provider_key(secrets, &manifest.id) else {
        return not_sent(NotSent::KeyMissing);
    };
    let digest = job.subject.digest.as_str();
    let admission = worker.admit(
        now_ms,
        &manifest.id,
        stored.state,
        manifest.limits.max_requests_per_minute,
        job.capability,
        digest,
    );
    if admission != Admission::Send {
        return not_sent(NotSent::Held(admission));
    }
    let request = ProviderRequest {
        method: match capability.request.method {
            ProviderHttpMethodV1::Get => ProviderMethod::Get,
            ProviderHttpMethodV1::Post => ProviderMethod::Post,
        },
        host: capability.request.host.clone(),
        path: capability.request.path.clone(),
        header: manifest.auth.header.clone(),
        key: Zeroizing::new(key.expose().to_owned()),
        body: Some(body),
    };
    let limits = ProviderLimits {
        timeout_ms: manifest.limits.timeout_ms,
        max_response_bytes: manifest.limits.max_response_bytes,
    };
    let record = |worker: &mut ProviderWorker, outcome| {
        worker.record(
            connection,
            now_ms,
            &manifest.id,
            job.capability,
            digest,
            outcome,
        )
    };
    let response = match transport.send(&request, limits) {
        Ok(response) => response,
        Err(error) => {
            let recorded = record(worker, ExchangeOutcome::Failed)?;
            return Ok(LookupReport::Failed {
                outcome: ExchangeOutcome::Failed,
                code: error.code(),
                recorded,
            });
        }
    };
    let outcome = status_outcome(response.status);
    if outcome != ExchangeOutcome::Answered {
        let recorded = record(worker, outcome)?;
        return Ok(LookupReport::Failed {
            outcome,
            code: status_code(outcome),
            recorded,
        });
    }
    let answer = match map_answer(&response.body, &answer_mapping(capability)) {
        Ok(answer) => answer,
        Err(error) => {
            let recorded = record(worker, ExchangeOutcome::Failed)?;
            return Ok(LookupReport::Failed {
                outcome: ExchangeOutcome::Failed,
                code: error.code(),
                recorded,
            });
        }
    };
    let ttl_ms = answer
        .ttl_seconds
        .map_or(DEFAULT_ANSWER_TTL_MS, |seconds| {
            seconds.saturating_mul(1000)
        })
        .max(1);
    let expires_at_ms = now_ms.saturating_add(ttl_ms);
    let signal = ProviderSignalV1 {
        version: PROVIDER_SIGNAL_V1_VERSION,
        provider_id: manifest.id.clone(),
        capability: job.capability,
        subject: job.subject.clone(),
        verdict: answer.verdict,
        reason_codes: answer.reason_codes,
        observed_at_ms: now_ms,
        expires_at_ms,
        inventory: inventory(capability),
        state: ProviderSignalStateV1::Fresh,
    };
    // The provider answered, so the circuit closes whether or not the cache keeps this answer.
    let recorded = record(worker, ExchangeOutcome::Answered)?;
    let stored = put_signal(connection, &signal)?;
    Ok(LookupReport::Answered {
        refresh_at_ms: refresh_at(now_ms, expires_at_ms, job.jitter),
        signal,
        stored,
        recorded,
    })
}

#[cfg(test)]
#[path = "provider_integration_lookup_tests.rs"]
mod tests;
