//! The provider integration routes on the daemon edge.
//!
//! `/v1/integrations/providers` requests are answered here and never relayed:
//! the Python daemon has no handler for them. Every request needs the daemon's
//! header token or a local dashboard session, and a `POST` also needs an
//! allowed origin, as the discovery routes do. The routes are not on the
//! hosted dashboard API list, so a hosted origin's session is refused.
//!
//! The routes live in `provider_integration_routes`. This module opens the
//! store under the storage gate, reads the installed managed policy, and keeps
//! the one proof ledger the process holds, so a proof issued by a preview is
//! spent by the request that follows it on any connection.
//!
//! `connect` checks the key with the provider. The proof is spent under the
//! ledger lock, the provider is called with no lock or storage gate held, and
//! the key and connection row are written under the gate afterwards. The call
//! runs under the managed network policy and the manifest's pinned hosts.

use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use guard_command::provider_integration_compile::CompiledProviderIntegrationV1;
use guard_provider_integrations::client::HttpProviderTransport;
use rusqlite::Connection;
use serde_json::{json, Value};

use super::super::http::Request;
use super::{authorize_origin, authorize_token, json_response, refusals, NativeReads, ReadConfig};
use crate::hook_evidence_store_gate::hold_storage_gate;
use crate::managed_policy_floor::effective_managed_policy;
use crate::managed_policy_load::{load_managed_policy, ManagedPolicySource, ManagedPolicyState};
use crate::provider_integration_managed::{ManagedProviderSettings, PROVIDER_INTEGRATIONS_SETTING};
use crate::provider_integration_routes::{
    self as routes, PreparedConnect, ProofLedger, RouteAnswer, RouteContext,
};
use crate::provider_integration_store::ensure_provider_integration_schema;
use crate::supply_chain_eval_caller::CallerEgressFulfilment;

pub(super) const MANAGED_POLICY_UNAVAILABLE: &str = "provider_managed_policy_unavailable";
pub(super) const STORE_UNAVAILABLE: &str = "provider_store_unavailable";

pub(super) fn owns(method: &str, path: &str) -> bool {
    routes::owns(method, path)
}

fn ledger() -> &'static Mutex<ProofLedger> {
    static LEDGER: OnceLock<Mutex<ProofLedger>> = OnceLock::new();
    LEDGER.get_or_init(|| Mutex::new(ProofLedger::new()))
}

/// The providers this build ships. No reviewed provider pack has been
/// contributed yet, so the set is empty and every provider route answers for
/// an empty catalog.
fn shipped_providers() -> Vec<CompiledProviderIntegrationV1> {
    Vec::new()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

pub(super) fn response(
    request: &Request<'_>,
    body: &[u8],
    config: &ReadConfig,
    reads: &NativeReads,
) -> Vec<u8> {
    let build = config.dashboard_build.as_deref();
    let refused = |refusal: refusals::Refusal| {
        let (status, body, cors_origin) = refusals::respond(request, &refusal, None, config, reads);
        json_response(status, &body, build, cors_origin.as_deref(), false)
    };
    if request.method == "POST" && authorize_origin(request).is_none() {
        return json_response(
            403,
            &json!({"error": "forbidden_origin"}),
            build,
            None,
            false,
        );
    }
    if super::discovery::query_names_token(request.query) {
        return refused(refusals::Refusal::QueryToken);
    }
    let Some(caller) = authorize_token(request, &config.token) else {
        return refused(refusals::Refusal::Unauthorized);
    };
    reads.report_activity();
    let managed = managed_settings(&load_managed_policy(&ManagedPolicySource::native()));
    let (status, answer) = serve(
        config,
        &Served {
            enabled: routes::provider_integrations_enabled_now(),
            managed: managed.as_ref(),
            providers: &shipped_providers(),
            now_ms: now_ms(),
            verify: &verify_with_provider,
        },
        request.method,
        request.path,
        body,
    );
    json_response(status, &answer, build, caller.cors_origin.as_deref(), false)
}

/// The managed provider settings, or `None` when they cannot be known: a
/// policy that failed closed, or a `provider_integrations` value that does not
/// parse. Guard then refuses the routes rather than guess at a floor.
pub(super) fn managed_settings(state: &ManagedPolicyState) -> Option<ManagedProviderSettings> {
    if state.policy.is_none() && state.status.fails_closed() {
        return None;
    }
    let Some(policy) = effective_managed_policy(state) else {
        return Some(ManagedProviderSettings::none());
    };
    let locked = policy
        .locked_settings
        .contains(PROVIDER_INTEGRATIONS_SETTING);
    ManagedProviderSettings::from_settings(&policy.settings, locked).ok()
}

/// Checks a prepared connect's key with the provider.
pub(super) type Verify<'a> = &'a dyn Fn(&PreparedConnect<'_>) -> Result<bool, RouteAnswer>;

/// What a request is answered against, apart from the store.
pub(super) struct Served<'a> {
    pub(super) enabled: bool,
    pub(super) managed: Option<&'a ManagedProviderSettings>,
    pub(super) providers: &'a [CompiledProviderIntegrationV1],
    pub(super) now_ms: u64,
    pub(super) verify: Verify<'a>,
}

/// The verify call over HTTPS, under the managed network policy. A policy
/// Guard cannot honour refuses the call rather than send it unmanaged.
fn verify_with_provider(prepared: &PreparedConnect<'_>) -> Result<bool, RouteAnswer> {
    let Ok(egress) = CallerEgressFulfilment::resolve_policy(&ManagedPolicySource::native()) else {
        return Err(RouteAnswer {
            status: 503,
            body: json!({"error": MANAGED_POLICY_UNAVAILABLE}),
        });
    };
    let transport = HttpProviderTransport::new(prepared.provider().hosts.clone(), &egress);
    routes::verify_connect(prepared, &transport)
}

fn split(answer: RouteAnswer) -> (u16, Value) {
    (answer.status, answer.body)
}

fn lock_ledger() -> std::sync::MutexGuard<'static, ProofLedger> {
    ledger().lock().unwrap_or_else(|poison| poison.into_inner())
}

pub(super) fn serve(
    config: &ReadConfig,
    served: &Served<'_>,
    method: &str,
    path: &str,
    body: &[u8],
) -> (u16, Value) {
    let Some(managed) = served.managed else {
        return (503, json!({"error": MANAGED_POLICY_UNAVAILABLE}));
    };
    if routes::is_connect(method, path) {
        let prepared = routes::prepare_connect(
            &mut lock_ledger(),
            served.enabled,
            served.providers,
            path,
            body,
            served.now_ms,
        );
        let prepared = match prepared {
            Ok(prepared) => prepared,
            Err(answer) => return split(answer),
        };
        let verified = match (served.verify)(&prepared) {
            Ok(verified) => verified,
            Err(answer) => return split(answer),
        };
        return with_store(config, served, managed, |context| {
            routes::finish_connect(context, prepared, verified)
        });
    }
    with_store(config, served, managed, |context| {
        routes::answer(&mut lock_ledger(), context, method, path, body).unwrap_or(RouteAnswer {
            status: 404,
            body: json!({"error": "not_found"}),
        })
    })
}

/// Runs `answer` against the daemon store, opened under the storage gate.
fn with_store(
    config: &ReadConfig,
    served: &Served<'_>,
    managed: &ManagedProviderSettings,
    answer: impl FnOnce(&RouteContext<'_>) -> RouteAnswer,
) -> (u16, Value) {
    let unavailable = || (503, json!({"error": STORE_UNAVAILABLE}));
    let wait = Duration::from_millis(config.busy_timeout_ms.max(1));
    let Ok(_gate) = hold_storage_gate(Path::new(&config.guard_home), wait) else {
        return unavailable();
    };
    let Ok(connection) = Connection::open(&config.store_path) else {
        return unavailable();
    };
    if connection.busy_timeout(wait).is_err()
        || ensure_provider_integration_schema(&connection).is_err()
    {
        return unavailable();
    }
    split(answer(&RouteContext {
        enabled: served.enabled,
        providers: served.providers,
        connection: &connection,
        managed,
        guard_home: Path::new(&config.guard_home),
        now_ms: served.now_ms,
    }))
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_integrations_tests.rs"]
mod tests;
