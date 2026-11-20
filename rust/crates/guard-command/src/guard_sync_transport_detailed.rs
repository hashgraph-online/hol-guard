//! Guard Cloud exchanges that keep an HTTP refusal's full response
//! (status, headers and body) for callers whose handling depends on the
//! fields of Guard Cloud's error body.

use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    http_error_reason_message, sync_exchange, sync_http_eval_error, sync_retries, SyncBudget,
};
use crate::supply_chain_package_eval::{EvalError, GuardSyncRequest};

/// [`super::urlopen_json_within_budget`] that keeps an HTTP refusal's headers and body,
/// for callers whose handling depends on the fields of Guard Cloud's error body.
pub fn urlopen_json_detailed(
    request: &GuardSyncRequest,
    timeout_seconds: f64,
    retry_timeout_seconds: f64,
    budget: &SyncBudget,
) -> Result<Value, SyncFetchError> {
    sync_retries(
        request,
        timeout_seconds,
        retry_timeout_seconds,
        true,
        false,
        Some(budget),
    )?
    .ok_or_else(|| {
        EvalError::Internal("Guard Cloud sync returned an invalid response payload.".to_owned())
            .into()
    })
}

/// [`urlopen_json_detailed`] for an endpoint whose answer is not read
/// (`_urlopen_with_timeout_retry`).
pub fn urlopen_detailed(
    request: &GuardSyncRequest,
    timeout_seconds: f64,
    retry_timeout_seconds: f64,
    budget: &SyncBudget,
) -> Result<(), SyncFetchError> {
    sync_retries(
        request,
        timeout_seconds,
        retry_timeout_seconds,
        false,
        false,
        Some(budget),
    )
    .map(|_| ())
}

/// [`urlopen_json_detailed`] that returns the successful status and the body
/// unread, for an endpoint that may answer `204 No Content` or whose body the
/// caller parses itself.
pub fn urlopen_raw_detailed(
    request: &GuardSyncRequest,
    timeout_seconds: f64,
    retry_timeout_seconds: f64,
    budget: &SyncBudget,
) -> Result<(u16, Vec<u8>), SyncFetchError> {
    sync_exchange(
        request,
        timeout_seconds,
        retry_timeout_seconds,
        false,
        Some(budget),
    )
    .map(|response| (response.status, response.body_bytes))
}

/// An HTTP error response that survived the retry machine.
#[derive(Debug)]
pub struct SyncHttpFailure {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl SyncHttpFailure {
    /// The reason [`EvalError::HttpStatus`] would carry for this response.
    pub fn reason(&self) -> String {
        http_error_reason_message(self.status, &self.headers, &self.body)
    }
}

/// Why a Guard Cloud exchange failed: an HTTP refusal with its full response,
/// or any other failure.
#[derive(Debug)]
pub enum SyncFetchError {
    Http(SyncHttpFailure),
    Other(EvalError),
}

impl From<EvalError> for SyncFetchError {
    fn from(error: EvalError) -> Self {
        Self::Other(error)
    }
}

impl SyncFetchError {
    /// The [`EvalError`] the plain transport functions report.
    pub fn into_eval_error(self) -> EvalError {
        match self {
            Self::Http(failure) => {
                sync_http_eval_error(failure.status, &failure.headers, &failure.body)
            }
            Self::Other(error) => error,
        }
    }
}
