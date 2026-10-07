use super::*;

// ---------------------------------------------------------------------------
// Dependency seams (:40-113 imports) — traits replacing Python modules that are
// not yet ported to this crate. Mirrors the `local_supply_chain.rs` seam style:
// each trait method takes `&self`; dict-shaped payloads use `serde_json::Value`
// / `Map<String, Value>`; failures surface as `EvalError`.
// ---------------------------------------------------------------------------

/// Error type shared by every seam below. Maps the Python exception surface:
/// `Validation` covers `ValueError`/`GuardSyncEndpointUntrustedError`/
/// `PackageIdentityError`/`SupplyChainBundleMalformedError`/`DeadlineExceededError`
/// (message carries the machine-readable reason code); `NotFound` covers
/// `GuardSyncNotConfiguredError` and missing-workspace/entitlement lookups;
/// `Internal` covers everything else (I/O, transport, unexpected state).
#[derive(Debug, Clone)]
pub enum EvalError {
    /// Caller/validation failure — safe to surface verbatim to the harness.
    Validation(String),
    /// Missing prerequisite or not-configured dependency (e.g. Guard Cloud
    /// sync is not configured for this store).
    NotFound(String),
    /// Internal/transport failure — log and fail closed.
    Internal(String),
    /// `urllib.error.HTTPError` mirror (:1350) — carries the HTTP status code
    /// so `_evaluate_with_cloud` can branch on 401/403/400/404/other. The
    /// transport surface that produces this is `guard_sync.urlopen_json_with_timeout_retry`.
    HttpStatus(u16, String),
}

impl EvalError {
    /// `urllib.error.HTTPError.code` — the HTTP status when this error came
    /// from an HTTP response, `None` for any other failure class.
    pub fn http_status(&self) -> Option<u16> {
        match self {
            Self::HttpStatus(code, _) => Some(*code),
            _ => None,
        }
    }
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(m) | Self::NotFound(m) | Self::Internal(m) => f.write_str(m),
            Self::HttpStatus(code, m) => write!(f, "HTTP {code}: {m}"),
        }
    }
}

impl std::error::Error for EvalError {}

pub type EvalResult<T> = Result<T, EvalError>;

/// `runner._guard_sync_request(...)` (:4269) mirror — the prepared request
/// object handed to the transport (`urllib.request.Request` in Python).
/// `body` is `None` for bodiless methods; `dpop_nonce` is echoed for retry
/// bookkeeping by `_urlopen_json_with_timeout_retry`.
///
/// `retry_context` mirrors Python's `_resolve_guard_dpop_retry_context`
/// side-channel (`_GUARD_DPOP_REQUEST_CONTEXTS` + the
/// `_guard_dpop_retry_context` attribute). The prepared request carries the
/// auth context + request metadata so a DPoP nonce challenge (`use_dpop_nonce`)
/// or a timeout retry can re-sign the proof with a fresh nonce without the
/// caller re-deriving the credential material.
#[derive(Debug, Clone, Default)]
pub struct GuardSyncRequest {
    pub url: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub dpop_nonce: Option<String>,
    /// Python `_guard_dpop_retry_context` — `{auth_context, request_url,
    /// method, extra_headers}` for nonce/timeout re-signing. `None` when the
    /// request has no DPoP material.
    pub retry_context: Option<Map<String, Value>>,
}

/// `.runtime.runner` seam — the private Guard-Cloud-sync helpers this module
/// imports from `runner` (:78-84).
pub trait GuardSyncRunnerApi {
    /// `runner._resolve_guard_sync_auth_context(store)` (:5184) -> auth-context
    /// dict. `EvalError::NotFound` maps `GuardSyncNotConfiguredError`;
    /// `EvalError::Validation` maps `GuardSyncAuthorizationExpiredError`.
    fn resolve_guard_sync_auth_context(
        &self,
        store: &dyn SupplyChainStore,
        allow_primary_repair: bool,
        force_refresh: bool,
    ) -> EvalResult<Map<String, Value>>;
    /// `runner._validate_guard_sync_url(sync_url, issuer=)` (:4453) ->
    /// canonical sync URL. `EvalError::Validation` maps
    /// `GuardSyncEndpointUntrustedError`.
    fn validate_guard_sync_url(&self, sync_url: &str, issuer: Option<&str>) -> EvalResult<String>;
    /// `runner._guard_sync_request(auth_context, request_url=, method=, data=,
    /// extra_headers=, dpop_nonce=)` (:4269) -> prepared request.
    fn guard_sync_request(
        &self,
        auth_context: &Value,
        request_url: &str,
        method: &str,
        data: Option<&[u8]>,
        extra_headers: Option<&Map<String, Value>>,
        dpop_nonce: Option<&str>,
    ) -> EvalResult<GuardSyncRequest>;
    /// `runner._urlopen_json_with_timeout_retry(request=, timeout_seconds=,
    /// retry_timeout_seconds=)` (:5545) -> response JSON dict.
    fn urlopen_json_with_timeout_retry(
        &self,
        request: &GuardSyncRequest,
        timeout_seconds: u64,
        retry_timeout_seconds: u64,
    ) -> EvalResult<Map<String, Value>>;
    /// `runner._is_timeout_error(error)` (:5448) — classifies a transport error
    /// (including wrapped/`.reason` causes) as a timeout.
    fn is_timeout_error(&self, error: &(dyn std::error::Error + 'static)) -> bool;
    /// `runner._normalized_receipts_sync_url(sync_url)` (:5851) — rewrites a
    /// bare `/registry/api/v1` endpoint to the receipts sync path.
    fn normalized_receipts_sync_url(&self, sync_url: &str) -> String;
}

/// `lockfile_parse_result.LockfileDependencyEntry` (:46) mirror.
#[derive(Debug, Clone, Default)]
pub struct LockfileDependencyEntry {
    pub dependency_path: String,
    pub package_name: String,
    pub version: String,
    pub direct: bool,
}

/// `lockfile_parse_result.LockfileParseResult` (:54) mirror.
#[derive(Debug, Clone, Default)]
pub struct LockfileParseResult {
    pub entries: Vec<LockfileDependencyEntry>,
    pub complete: bool,
    pub format: String,
    pub source_hash: String,
    pub elapsed_ms: f64,
    pub budget_ms: f64,
    pub warnings: Vec<String>,
    pub error_reason: Option<String>,
    pub parser_version: String,
}

impl LockfileParseResult {
    /// `dependency_map` (:65) — `{dependency_path: version}`, empty unless the
    /// parse completed.
    pub fn dependency_map(&self) -> BTreeMap<String, String> {
        if !self.complete {
            return BTreeMap::new();
        }
        self.entries
            .iter()
            .map(|entry| (entry.dependency_path.clone(), entry.version.clone()))
            .collect()
    }
}

/// `.runtime.lockfile_evaluation_support` / `.runtime.lockfile_parse_result`
/// seam (:41-52 imports).
pub trait LockfileParseApi {
    /// `collect_lockfile_parse_results(workspace_dir, lockfile_paths,
    /// budget_ms=, parse_text_result=)` (lockfile_evaluation_support.py:24).
    /// Parses every supported workspace lockfile without returning partial
    /// data; paths that fail resolution/read become `incomplete` results.
    /// `lockfile_paths` mirrors the raw `artifact.metadata["lockfile_paths"]`
    /// list (`Value`, validated element-by-element in Python).
    fn collect_lockfile_parse_results(
        &self,
        workspace_dir: Option<&Path>,
        lockfile_paths: Option<&Value>,
        budget_ms: f64,
        parse_text_result: &dyn Fn(&str, &[u8]) -> LockfileParseResult,
    ) -> Vec<LockfileParseResult>;
    /// `parse_lockfile_with_budget(path, source_text, budget_seconds=,
    /// dependency_parser=, package_lock_parser=)`
    /// (lockfile_evaluation_support.py:66).
    fn parse_lockfile_with_budget(
        &self,
        path: &str,
        source_text: &[u8],
        budget_seconds: f64,
    ) -> LockfileParseResult;
    /// `incomplete_lockfile_result(path, source, error_reason=, budget_ms=,
    /// elapsed_ms=)` (lockfile_parse_result.py:90).
    fn incomplete_lockfile_result(
        &self,
        path: &str,
        source: &[u8],
        error_reason: &str,
        budget_ms: f64,
        elapsed_ms: f64,
    ) -> LockfileParseResult;
}
