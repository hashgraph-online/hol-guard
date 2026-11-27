//! `POST .../test`: one live lookup for a public origin the person typed (PRD 6.9).
//!
//! The route runs the worker's own lookup ([`run_lookup`]), so it sends nothing the hook path
//! would not: the stored connection must be for exactly this compiled manifest, only the facts the
//! capability declares are shared, a non-public origin never leaves the device, and the call takes
//! a token from the provider's bucket, which refills at the manifest's `max_requests_per_minute`.
//! That bucket is the route's rate limit, shared with background lookups, so a test can never send
//! more than the provider agreed to. The answer is never cached, so a test cannot change a later
//! decision; the bucket, the circuit and a refused key still count as for any lookup.
//!
//! The answer carries codes and the mapped signal only, never provider text, the key, or the
//! origin itself (the signal names its subject by digest).

use std::collections::BTreeMap;

use guard_command::provider_integration_compile::CompiledProviderIntegrationV1;
use guard_command::provider_origin_share::provider_origin_is_shareable;
use guard_contracts::{
    ProviderCapabilityV1, ProviderIntegrationErrorV1, ProviderShareableFactV1,
    ProviderSubjectKindV1, ProviderSubjectV1, ProviderTestRequestV1,
};
use guard_provider_integrations::client::ProviderTransport;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::NOT_FOUND;
use super::{error, ok, read_body, route, unavailable, Action, Route, RouteAnswer, RouteContext};
use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::provider_integration_lookup::{run_lookup, LookupJob, LookupReport, NotSent};
use crate::provider_integration_worker::{Admission, ExchangeOutcome, ProviderWorker};

/// Runs `send` with a transport pinned to the provider's hosts. The daemon passes the HTTPS client
/// under the managed network policy; tests pass the testkit's fake.
pub type WithTransport<'a> = &'a dyn Fn(
    &CompiledProviderIntegrationV1,
    &mut dyn FnMut(&dyn ProviderTransport) -> RouteAnswer,
) -> RouteAnswer;

/// Whether `method path` is the test route.
pub fn is_test(method: &str, path: &str) -> bool {
    method == "POST" && matches!(route(path), Some(Route::Post(_, Action::Test)))
}

/// The canonical spelling of a public origin and the subject it is cached under, or `None` when
/// the origin may not be shared (PRD 6.4). Scheme and host are case-insensitive, a trailing slash
/// is dropped and so is the scheme's default port, so one origin always has one digest.
pub fn origin_subject(origin: &str) -> Option<(String, ProviderSubjectV1)> {
    let canonical = origin.trim().to_ascii_lowercase();
    let canonical = canonical.strip_suffix('/').unwrap_or(&canonical);
    let canonical = [("https://", ":443"), ("http://", ":80")]
        .iter()
        .find(|(scheme, port)| {
            canonical
                .strip_prefix(scheme)
                .and_then(|rest| rest.strip_suffix(port))
                .is_some_and(|host| !host.contains(['/', '@', ':']))
        })
        .map_or(canonical, |(_, port)| {
            &canonical[..canonical.len() - port.len()]
        })
        .to_owned();
    if !provider_origin_is_shareable(&canonical) {
        return None;
    }
    let digest = Sha256::digest(canonical.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let subject = ProviderSubjectV1 {
        kind: ProviderSubjectKindV1::Origin,
        digest,
    };
    Some((canonical, subject))
}

/// Answers `POST .../test` under the store: one lookup through `with_transport`.
pub fn run_test(
    worker: &mut ProviderWorker,
    context: &RouteContext<'_>,
    path: &str,
    body: &[u8],
    with_transport: WithTransport<'_>,
) -> RouteAnswer {
    if !context.enabled {
        return error(
            503,
            ProviderIntegrationErrorV1::ProviderCapabilityUnavailable.code(),
        );
    }
    let Some(Route::Post(provider_id, Action::Test)) = route(path) else {
        return error(404, NOT_FOUND);
    };
    let Some(provider) = context.provider(provider_id) else {
        return error(404, NOT_FOUND);
    };
    let request: ProviderTestRequestV1 = match read_body(body) {
        Ok(request) => request,
        Err(answer) => return answer,
    };
    let Some((origin, subject)) = origin_subject(&request.origin) else {
        return error(
            400,
            NotSent::FactRefused(ProviderShareableFactV1::TargetOrigin).code(),
        );
    };
    let facts = BTreeMap::from([(ProviderShareableFactV1::TargetOrigin, Value::String(origin))]);
    let job = LookupJob {
        manifest: provider,
        manifest_digest: &provider.manifest_digest,
        capability: request.capability,
        subject,
        facts: &facts,
        jitter: context.now_ms as u32,
        cache: false,
    };
    let mut secrets = EncryptedFileSecretStore::new(context.guard_home);
    with_transport(provider, &mut |transport| match run_lookup(
        worker,
        context.connection,
        &mut secrets,
        transport,
        &job,
        context.now_ms,
    ) {
        Ok(report) => report_answer(&provider.id, request.capability, report),
        Err(_) => unavailable(),
    })
}

fn report_answer(
    provider_id: &str,
    capability: ProviderCapabilityV1,
    report: LookupReport,
) -> RouteAnswer {
    match report {
        LookupReport::Answered {
            signal,
            refresh_at_ms,
            ..
        } => ok(json!({
            "provider_id": provider_id,
            "capability": capability,
            "signal": signal,
            "refresh_at_ms": refresh_at_ms,
        })),
        LookupReport::Failed {
            outcome: ExchangeOutcome::Unauthorized,
            recorded,
            ..
        } => RouteAnswer {
            status: 400,
            body: json!({
                "error": ProviderIntegrationErrorV1::ProviderKeyInvalid.code(),
                "key_invalidated": recorded.key_invalidated,
            }),
        },
        LookupReport::Failed { outcome, code, .. } => RouteAnswer {
            status: if outcome == ExchangeOutcome::RateLimited {
                429
            } else {
                502
            },
            body: json!({"error": code}),
        },
        LookupReport::NotSent(reason) => error(not_sent_status(reason), reason.code()),
    }
}

fn not_sent_status(reason: NotSent) -> u16 {
    match reason {
        NotSent::NotConnected
        | NotSent::ManifestChanged
        | NotSent::KeyMissing
        | NotSent::Held(Admission::NotConnected(_)) => 409,
        NotSent::CapabilityUndeclared
        | NotSent::SubjectNotCarried
        | NotSent::FactRefused(_)
        | NotSent::BodyInvalid => 400,
        NotSent::Held(Admission::RateLimited) => 429,
        NotSent::Held(_) => 503,
    }
}

#[cfg(test)]
#[path = "provider_integration_routes_lookup_tests.rs"]
mod tests;
