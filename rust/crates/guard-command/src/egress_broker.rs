//! Caller-brokered network egress for the resident's supply-chain evaluation.
//!
//! The resident must not open a socket on its own for package evaluation: the
//! caller owns the managed network policy (destination allow-list, policy
//! proxy, CA bundle, proxy credentials, system proxies) and this process does
//! not. Every exchange therefore goes through [`exchange`] (or
//! [`exchange_archive`]), which only ever answers from outcomes the caller
//! supplied. An exchange with no supplied outcome is recorded as a need, and
//! the evaluation is abandoned for this round; the caller performs the needs
//! and repeats the request with the outcomes, which replays the evaluation up
//! to the next need. Parsing and every decision stay in Rust.
//!
//! Two rules keep a replay faithful:
//! * An exchange is identified by (class, method, url, request-body hash) and
//!   its occurrence number, never by headers, because DPoP proofs and nonces
//!   differ between replays of the same logical request.
//! * Retry pauses are not slept. They accumulate as a delay the caller honors
//!   before it performs the next need, and an already-supplied outcome costs
//!   no delay on replay.
//!
//! Only idempotent public-registry reads are collected speculatively after the
//! first need, so one round can carry every metadata lookup. Anything else
//! after a pending need is refused without being recorded, because its input
//! would depend on a response the resident has not seen.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use guard_contracts::{
    EgressNeedV1, EgressOutcomeV1, EgressSuppliedV1, EGRESS_MAX_HEADERS, EGRESS_MAX_NEEDS,
    EGRESS_MAX_NEED_BODY_BYTES, EGRESS_MAX_SUPPLIED,
};
use sha2::{Digest, Sha256};

use crate::egress_spool::response_body;
use crate::guard_sync_transport::{SyncHttpError, SyncResponse};
use crate::supply_chain_package_eval::GuardSyncRequest;

const MAX_URL_BYTES: usize = 8192;
const MAX_ERROR_MESSAGE_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EgressClass {
    Oauth,
    Cloud,
    Registry,
    Archive,
}

impl EgressClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Oauth => "oauth",
            Self::Cloud => "cloud",
            Self::Registry => "registry",
            Self::Archive => "archive",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        [Self::Oauth, Self::Cloud, Self::Registry, Self::Archive]
            .into_iter()
            .find(|class| class.as_str() == value)
    }
}

/// What the caller did with an external-archive need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveExchange {
    Downloaded {
        sha256: String,
        size: u64,
        final_url: String,
    },
    Failed {
        code: String,
        message: String,
    },
    /// No answer is available: the need was recorded, deferred or refused.
    Unavailable(String),
}

/// Reason reported when no caller is brokering the exchange (the scope denies all
/// network access), as opposed to an exchange that was merely deferred or recorded.
pub const NO_BROKERED_CALLER: &str = "egress unavailable: no brokered caller";

type Key = (EgressClass, String, String, String);

struct State {
    /// `None` outcomes map: every exchange is refused (no brokered caller).
    denied: bool,
    supplied: HashMap<(Key, u32), EgressOutcomeV1>,
    spool: Option<PathBuf>,
    counts: HashMap<Key, u32>,
    needs: Vec<EgressNeedV1>,
    pending: bool,
    pending_delay: f64,
}

thread_local! {
    static ACTIVE: RefCell<Option<State>> = const { RefCell::new(None) };
}

/// Installs the broker for the current evaluation and removes it on drop.
pub struct EgressScope(());

impl EgressScope {
    /// A scope that answers from `supplied` and records the rest as needs.
    pub fn enter(
        supplied: &[EgressSuppliedV1],
        spool_dir: Option<&str>,
    ) -> Result<Self, &'static str> {
        if supplied.len() > EGRESS_MAX_SUPPLIED {
            return Err("egress_supplied_too_many");
        }
        let spool = match spool_dir {
            None => None,
            Some(dir) if Path::new(dir).is_absolute() && !dir.contains('\0') => {
                Some(PathBuf::from(dir))
            }
            Some(_) => return Err("egress_spool_dir_invalid"),
        };
        let mut table = HashMap::new();
        for entry in supplied {
            let Some(class) = EgressClass::parse(&entry.class) else {
                return Err("egress_supplied_class_invalid");
            };
            if entry.occurrence == 0 || entry.url.len() > MAX_URL_BYTES {
                return Err("egress_supplied_key_invalid");
            }
            if let EgressOutcomeV1::Response { headers, .. } = &entry.outcome {
                if headers.len() > EGRESS_MAX_HEADERS {
                    return Err("egress_supplied_headers_too_many");
                }
            }
            let key = (
                class,
                entry.method.to_ascii_uppercase(),
                entry.url.clone(),
                entry.body_sha256.clone(),
            );
            if table
                .insert((key, entry.occurrence), entry.outcome.clone())
                .is_some()
            {
                return Err("egress_supplied_duplicate");
            }
        }
        Self::install(State {
            denied: false,
            supplied: table,
            spool,
            counts: HashMap::new(),
            needs: Vec::new(),
            pending: false,
            pending_delay: 0.0,
        })
    }

    /// A scope for a resident op that has no way to ask a caller: every
    /// exchange fails, as an unreachable network would.
    pub fn deny_all() -> Result<Self, &'static str> {
        Self::install(State {
            denied: true,
            supplied: HashMap::new(),
            spool: None,
            counts: HashMap::new(),
            needs: Vec::new(),
            pending: false,
            pending_delay: 0.0,
        })
    }

    fn install(state: State) -> Result<Self, &'static str> {
        ACTIVE.with(|cell| {
            let mut slot = cell.borrow_mut();
            if slot.is_some() {
                return Err("egress_scope_active");
            }
            *slot = Some(state);
            Ok(Self(()))
        })
    }

    /// The exchanges the evaluation could not answer, in the order asked.
    pub fn finish(self) -> Vec<EgressNeedV1> {
        ACTIVE.with(|cell| {
            cell.borrow_mut()
                .as_mut()
                .map(|state| std::mem::take(&mut state.needs))
                .unwrap_or_default()
        })
    }
}

impl Drop for EgressScope {
    fn drop(&mut self) {
        ACTIVE.with(|cell| cell.borrow_mut().take());
    }
}

/// True once an exchange is waiting on the caller. Everything the evaluation
/// does from then on is speculative, so persistent writes must be skipped.
pub fn needs_pending() -> bool {
    ACTIVE.with(|cell| cell.borrow().as_ref().is_some_and(|state| state.pending))
}

/// Record a retry pause. It is handed to the caller as a delay before the next
/// exchange instead of being slept here.
pub fn pause(seconds: f64) {
    let recorded = ACTIVE.with(|cell| {
        cell.borrow_mut().as_mut().map(|state| {
            if seconds.is_finite() && seconds > 0.0 {
                state.pending_delay += seconds;
            }
        })
    });
    #[cfg(test)]
    if recorded.is_none() {
        std::thread::sleep(std::time::Duration::from_secs_f64(seconds.max(0.0)));
    }
    #[cfg(not(test))]
    let _ = recorded;
}

enum Resolution {
    Supplied(EgressOutcomeV1, Option<PathBuf>),
    Unavailable(&'static str),
}

impl State {
    fn resolve(&mut self, class: EgressClass, spec: &NeedSpec<'_>) -> Resolution {
        if self.denied {
            return Resolution::Unavailable(NO_BROKERED_CALLER);
        }
        let key: Key = (
            class,
            spec.method.to_ascii_uppercase(),
            spec.url.to_owned(),
            spec.body_sha256.clone(),
        );
        let occurrence = {
            let count = self.counts.entry(key.clone()).or_insert(0);
            *count += 1;
            *count
        };
        if let Some(outcome) = self.supplied.get(&(key, occurrence)) {
            self.pending_delay = 0.0;
            return Resolution::Supplied(outcome.clone(), self.spool.clone());
        }
        if self.pending && class != EgressClass::Registry {
            return Resolution::Unavailable("egress deferred behind a pending exchange");
        }
        if self.needs.len() >= EGRESS_MAX_NEEDS {
            return Resolution::Unavailable("egress deferred: too many pending exchanges");
        }
        let body = match spec.body {
            None => None,
            Some(bytes) if bytes.len() <= EGRESS_MAX_NEED_BODY_BYTES => {
                match String::from_utf8(bytes.to_vec()) {
                    Ok(text) => Some(text),
                    Err(_) => return Resolution::Unavailable("egress request body is not text"),
                }
            }
            Some(_) => return Resolution::Unavailable("egress request body too large"),
        };
        self.needs.push(EgressNeedV1 {
            class: class.as_str().to_owned(),
            method: spec.method.to_ascii_uppercase(),
            url: spec.url.to_owned(),
            headers: spec.headers.clone(),
            body,
            body_sha256: spec.body_sha256.clone(),
            occurrence,
            timeout_seconds: spec.timeout_seconds,
            max_redirects: spec.max_redirects,
            max_response_bytes: spec.max_response_bytes,
            delay_seconds: std::mem::take(&mut self.pending_delay),
        });
        self.pending = true;
        Resolution::Unavailable("egress pending the caller")
    }
}

struct NeedSpec<'a> {
    method: &'a str,
    url: &'a str,
    headers: BTreeMap<String, String>,
    body: Option<&'a [u8]>,
    body_sha256: String,
    timeout_seconds: f64,
    max_redirects: u32,
    max_response_bytes: u64,
}

fn body_digest(body: Option<&[u8]>) -> String {
    body.filter(|bytes| !bytes.is_empty())
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .unwrap_or_default()
}

fn resolve(class: EgressClass, spec: &NeedSpec<'_>) -> Option<Resolution> {
    ACTIVE.with(|cell| {
        cell.borrow_mut()
            .as_mut()
            .map(|state| state.resolve(class, spec))
    })
}

/// One HTTP exchange, answered by the caller.
pub(crate) fn exchange(
    class: EgressClass,
    request: &GuardSyncRequest,
    timeout_seconds: f64,
    max_redirects: u32,
    max_response_bytes: u64,
) -> Result<SyncResponse, SyncHttpError> {
    let spec = NeedSpec {
        method: &request.method,
        url: &request.url,
        headers: request.headers.clone(),
        body: request.body.as_deref(),
        body_sha256: body_digest(request.body.as_deref()),
        timeout_seconds,
        max_redirects,
        max_response_bytes,
    };
    match resolve(class, &spec) {
        Some(Resolution::Supplied(outcome, spool)) => {
            replay_outcome(&outcome, spool.as_deref(), max_response_bytes)
        }
        Some(Resolution::Unavailable(reason)) => Err(SyncHttpError::Other(reason.to_owned())),
        None => no_scope(request, timeout_seconds, max_redirects, max_response_bytes),
    }
}

/// With no scope the resident has no managed policy to defer to, so it never
/// reaches the network. Only this crate's own transport tests talk to loopback
/// servers directly.
#[cfg(not(test))]
fn no_scope(
    _request: &GuardSyncRequest,
    _timeout_seconds: f64,
    _max_redirects: u32,
    _max_response_bytes: u64,
) -> Result<SyncResponse, SyncHttpError> {
    Err(SyncHttpError::Other(NO_BROKERED_CALLER.to_owned()))
}

#[cfg(test)]
fn no_scope(
    request: &GuardSyncRequest,
    timeout_seconds: f64,
    max_redirects: u32,
    max_response_bytes: u64,
) -> Result<SyncResponse, SyncHttpError> {
    crate::guard_sync_transport::execute_request_following(
        request,
        timeout_seconds,
        max_redirects,
        max_response_bytes,
    )
}

/// One external-archive download, answered by the caller.
pub fn exchange_archive(
    url: &str,
    max_bytes: u64,
    max_redirects: u32,
    timeout_seconds: f64,
) -> ArchiveExchange {
    let spec = NeedSpec {
        method: "GET",
        url,
        headers: BTreeMap::new(),
        body: None,
        body_sha256: String::new(),
        timeout_seconds,
        max_redirects,
        max_response_bytes: max_bytes,
    };
    match resolve(EgressClass::Archive, &spec) {
        Some(Resolution::Supplied(
            EgressOutcomeV1::Archive {
                sha256,
                size,
                final_url,
            },
            _,
        )) => ArchiveExchange::Downloaded {
            sha256,
            size,
            final_url,
        },
        Some(Resolution::Supplied(EgressOutcomeV1::ArchiveFailure { code, message }, _)) => {
            ArchiveExchange::Failed { code, message }
        }
        Some(Resolution::Supplied(EgressOutcomeV1::Blocked { code }, _)) => {
            ArchiveExchange::Failed {
                message: "managed network policy refused the archive download".to_owned(),
                code,
            }
        }
        Some(Resolution::Supplied(..)) => {
            ArchiveExchange::Unavailable("egress outcome does not match the request".to_owned())
        }
        Some(Resolution::Unavailable(reason)) => ArchiveExchange::Unavailable(reason.to_owned()),
        None => ArchiveExchange::Unavailable(NO_BROKERED_CALLER.to_owned()),
    }
}

fn replay_outcome(
    outcome: &EgressOutcomeV1,
    spool: Option<&Path>,
    max_response_bytes: u64,
) -> Result<SyncResponse, SyncHttpError> {
    match outcome {
        EgressOutcomeV1::Response {
            status,
            headers,
            body,
            body_file,
        } => {
            if !(100..=599).contains(status) {
                return Err(SyncHttpError::Other("egress status invalid".to_owned()));
            }
            let bytes = response_body(
                body.as_deref(),
                body_file.as_deref(),
                spool,
                max_response_bytes,
            )?;
            if (200..300).contains(status) {
                return Ok(SyncResponse { body_bytes: bytes });
            }
            Err(SyncHttpError::Http {
                status: *status,
                headers: headers
                    .iter()
                    .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
                    .collect(),
                body: bytes,
            })
        }
        EgressOutcomeV1::Timeout => Err(SyncHttpError::Timeout("request timed out".to_owned())),
        EgressOutcomeV1::Error { message } => Err(SyncHttpError::Other(
            message.chars().take(MAX_ERROR_MESSAGE_BYTES).collect(),
        )),
        EgressOutcomeV1::Blocked { code } => Err(SyncHttpError::Other(format!(
            "managed network policy refused the request: {}",
            code.chars()
                .take(MAX_ERROR_MESSAGE_BYTES)
                .collect::<String>()
        ))),
        EgressOutcomeV1::Archive { .. } | EgressOutcomeV1::ArchiveFailure { .. } => Err(
            SyncHttpError::Other("egress outcome does not match the request".to_owned()),
        ),
    }
}

#[cfg(test)]
#[path = "egress_broker_tests.rs"]
mod tests;
