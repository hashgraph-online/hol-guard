//! Guard Cloud bundle fetches for the resident's bundle sync.
//!
//! The resident never dials out itself. Each sync runs inside an
//! [`EgressScope`] that answers exchanges the caller already performed; an
//! unanswered one is recorded as a need, the round is discarded, and the
//! caller performs the need under the machine's managed network policy before
//! the sync runs again. A round that left a need behind writes nothing: the
//! store opens read-only while one is waiting.

use guard_command::egress_broker::{self, EgressScope};
use guard_command::guard_sync_transport::{
    self as gst, SyncBudget, SyncFetchError, SyncHttpFailure,
};
use guard_command::local_supply_chain::SupplyChainStore;
use guard_command::supply_chain_package_eval::{EvalError, GuardSyncRunnerApi};
use serde_json::{json, Map, Value};

use crate::managed_policy_load::ManagedPolicySource;
use crate::package_authority_op::ResidentGuardSyncRunner;
use crate::supply_chain_eval_caller::CallerEgressFulfilment;
use crate::supply_chain_eval_rounds::CallerEgress;

/// Rounds a sync may take. Each answers at most one Guard Cloud exchange, so
/// this bounds an index plus its partitions, the full bundle and the network
/// bundle, with room for DPoP nonce and rate-limit retries.
const MAX_ROUNDS: usize = 128;
const SYNC_HTTP_TIMEOUT_SECONDS: f64 = 20.0;
const SYNC_HTTP_RETRY_TIMEOUT_SECONDS: f64 = 120.0;
/// The time one fetch, retries and rate-limit waits included, may take.
const FETCH_BUDGET_SECONDS: f64 = 300.0;
pub(crate) const GUARD_CLOUD_UNREACHABLE_MESSAGE: &str =
    "Guard Cloud could not be reached. Local Guard keeps protecting this machine.";
/// I/O failures that clear up on their own, as `_is_network_outage_error`
/// reads them. TLS failures are not among them.
const OUTAGE_IO_KINDS: [&str; 8] = [
    "ConnectionRefused",
    "ConnectionReset",
    "ConnectionAborted",
    "HostUnreachable",
    "NetworkUnreachable",
    "NetworkDown",
    "TimedOut",
    "NotConnected",
];

/// Why a bundle sync stopped, in the classes the Python callers raise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncError {
    /// `GuardSyncNotConfiguredError`: no workspace or no sign-in.
    NotConfigured(String),
    /// `GuardSyncEndpointUntrustedError`: the saved sync host is not one
    /// Guard trusts.
    EndpointUntrusted(String),
    /// `GuardSyncAuthorizationExpiredError`.
    AuthExpired(String),
    /// `GuardSyncNotAvailableError`: a plan restriction or an outage.
    NotAvailable { message: String, retryable: bool },
    /// `RuntimeError`.
    Failed(String),
    /// An exchange is waiting on the caller; the round is discarded.
    Pending,
}

impl SyncError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::NotConfigured(message)
            | Self::EndpointUntrusted(message)
            | Self::AuthExpired(message)
            | Self::NotAvailable { message, .. }
            | Self::Failed(message) => message.clone(),
            Self::Pending => "Guard Cloud sync did not settle.".to_owned(),
        }
    }
}

/// A bundle fetch that failed.
#[derive(Debug)]
pub(crate) enum FetchError {
    /// Guard Cloud refused the access token (`_GuardBundleUnauthorizedError`).
    Unauthorized(String),
    Sync(SyncError),
}

impl From<FetchError> for SyncError {
    fn from(error: FetchError) -> Self {
        match error {
            FetchError::Unauthorized(message) => SyncError::Failed(message),
            FetchError::Sync(error) => error,
        }
    }
}

/// Run `sync` until every exchange it makes has an answer, performing each
/// round's needs under the managed network policy.
pub(crate) fn brokered<T>(mut sync: impl FnMut() -> Result<T, SyncError>) -> Result<T, SyncError> {
    let policy = CallerEgressFulfilment::resolve_policy(&ManagedPolicySource::native())
        .map_err(|reason| SyncError::Failed(format!("Guard sync failed: {reason}")))?;
    let mut caller = CallerEgressFulfilment::new(&policy);
    for _ in 0..MAX_ROUNDS {
        let spool_dir = caller.spool_dir().to_str().map(str::to_owned);
        let spool_dir = spool_dir.filter(|dir| !dir.is_empty());
        let scope = EgressScope::enter(caller.supplied(), spool_dir.as_deref())
            .map_err(|reason| SyncError::Failed(format!("Guard sync failed: {reason}")))?;
        let result = sync();
        let needs = scope.finish();
        if needs.is_empty() {
            return match result {
                Err(SyncError::Pending) => Err(SyncError::Failed(SyncError::Pending.message())),
                other => other,
            };
        }
        caller
            .fulfil(&needs)
            .map_err(|reason| SyncError::Failed(format!("Guard sync failed: {reason}")))?;
    }
    Err(SyncError::Failed(SyncError::Pending.message()))
}

/// `_resolve_guard_sync_auth_context`, from the resident's own sign-in, or
/// the context a caller that already resolved one supplied.
pub(crate) fn resolve_auth(
    store: &dyn SupplyChainStore,
    force_refresh: bool,
    supplied: Option<&Map<String, Value>>,
) -> Result<Map<String, Value>, SyncError> {
    let runner = ResidentGuardSyncRunner {
        auth_context_override: supplied.cloned(),
    };
    runner
        .resolve_guard_sync_auth_context(store, false, force_refresh)
        .map_err(|error| match error {
            _ if egress_broker::needs_pending() => SyncError::Pending,
            EvalError::NotFound(message) => SyncError::NotConfigured(message),
            EvalError::Validation(message) => SyncError::AuthExpired(message),
            other => SyncError::Failed(other.to_string()),
        })
}

/// `_fetch_supply_chain_bundle_payload` for one bundle endpoint.
pub(crate) fn fetch_bundle(auth: &Map<String, Value>, url: &str) -> Result<Value, FetchError> {
    let headers = Map::from_iter([(
        "Accept-Encoding".to_owned(),
        Value::String("identity".to_owned()),
    )]);
    let request = gst::guard_sync_request(
        &Value::Object(auth.clone()),
        url,
        "GET",
        None,
        Some(&headers),
        None,
    )
    .map_err(|error| FetchError::Sync(SyncError::Failed(error.to_string())))?;
    let budget = SyncBudget::new(FETCH_BUDGET_SECONDS);
    gst::urlopen_json_detailed(
        &request,
        SYNC_HTTP_TIMEOUT_SECONDS,
        SYNC_HTTP_RETRY_TIMEOUT_SECONDS,
        &budget,
    )
    .map_err(|error| {
        if egress_broker::needs_pending() {
            return FetchError::Sync(SyncError::Pending);
        }
        match error {
            SyncFetchError::Http(failure) => http_failure(&failure),
            SyncFetchError::Other(error) => FetchError::Sync(transport_failure(&error)),
        }
    })
}

/// `_cloud_http_error` for a refusal: its messages, whether it is retryable,
/// a plan restriction or an edge block.
pub(crate) fn http_answer(failure: &SyncHttpFailure) -> Option<Value> {
    let headers: Map<String, Value> = failure
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), Value::String(value.clone())))
        .collect();
    let args = json!({
        "status": failure.status,
        "reason": reason_phrase(failure.status),
        "headers": headers,
        "body": String::from_utf8_lossy(&failure.body),
    });
    crate::runner_cloud_http_error::cloud_http_error(&args).ok()
}

/// Classify a refusal the way `_fetch_supply_chain_bundle_payload` does.
fn http_failure(failure: &SyncHttpFailure) -> FetchError {
    let Some(answer) = http_answer(failure) else {
        return FetchError::Sync(SyncError::Failed(failure.reason()));
    };
    let text = |key: &str| {
        answer
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    if failure.status == 403 {
        let message = text("plan_message");
        return FetchError::Sync(if answer["plan_restricted"] == Value::Bool(true) {
            SyncError::NotAvailable {
                message,
                retryable: false,
            }
        } else {
            SyncError::Failed(message)
        });
    }
    let message = text("message");
    if answer["retryable"] == Value::Bool(true) {
        return FetchError::Sync(SyncError::NotAvailable {
            message,
            retryable: true,
        });
    }
    if failure.status == 401 && answer["edge_block"].is_null() {
        return FetchError::Unauthorized(message);
    }
    FetchError::Sync(SyncError::Failed(message))
}

/// A failure with no HTTP answer. An outage is retryable; anything else, TLS
/// verification included, is a failed sync.
fn transport_failure(error: &EvalError) -> SyncError {
    let text = match error {
        EvalError::Internal(text) => text.as_str(),
        other => return SyncError::Failed(other.to_string()),
    };
    if is_outage(text) {
        return SyncError::NotAvailable {
            message: GUARD_CLOUD_UNREACHABLE_MESSAGE.to_owned(),
            retryable: true,
        };
    }
    SyncError::Failed(unreachable_message(text))
}

/// `_sync_url_error_message`: a failure with no HTTP answer.
pub(crate) fn unreachable_message(reason: &str) -> String {
    let reason = reason.trim();
    if reason.is_empty() {
        "Guard sync failed because the remote endpoint could not be reached.".to_owned()
    } else {
        format!("Guard sync failed: {reason}")
    }
}

fn is_outage(text: &str) -> bool {
    if text.starts_with("timeout:") || text == "host not found" {
        return true;
    }
    text.strip_prefix("io: ")
        .is_some_and(|kind| OUTAGE_IO_KINDS.contains(&kind.trim()))
}

/// `http.client.responses`, for the statuses Guard Cloud answers with.
fn reason_phrase(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        413 => "Request Entity Too Large",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

/// One derived sync endpoint (`runner_native_sync.sync_url`).
pub(crate) fn sync_url(route: &str, url: &str, extra: &[(&str, Value)]) -> Option<String> {
    let mut args = Map::from_iter([
        ("route".to_owned(), Value::String(route.to_owned())),
        ("url".to_owned(), Value::String(url.to_owned())),
    ]);
    for (key, value) in extra {
        args.insert((*key).to_owned(), value.clone());
    }
    crate::runner_sync_url::sync_url(&Value::Object(args))
        .ok()?
        .get("url")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

#[cfg(test)]
#[path = "cloud_bundle_fetch_tests.rs"]
mod tests;
