//! Approved external archive acquisition with native URL, DNS, redirect,
//! TLS, header, stream, deadline and immutable-blob enforcement.
//!
//! Production uses the peer-verified transport; traits allow synthetic parity
//! and HTTPS peers without introducing production network overrides.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use super::restricted_archive_address::address_is_public;
use super::restricted_archive_destination::urljoin;
pub use super::restricted_archive_destination::{
    canonical_destination, is_external_https_archive_source,
};
use super::restricted_archive_stream::{
    response_header, validate_response_headers, write_bounded_response,
};

#[cfg(test)]
#[path = "restricted_archive_parity_tests.rs"]
mod parity_tests;

// ---------------------------------------------------------------------------
// restricted_archive_contract.py — pure constants / typed results
// ---------------------------------------------------------------------------

/// `_DEFAULT_MAX_BYTES` (restricted_archive_stream.py / contract defaults).
pub const DEFAULT_MAX_BYTES: u64 = 6 * 1024 * 1024;
/// `_DEFAULT_MAX_REDIRECTS` (restricted_archive_download.py).
pub const DEFAULT_MAX_REDIRECTS: u32 = 4;
/// `_DEFAULT_TIMEOUT_SECONDS` (restricted_archive_download.py).
pub const DEFAULT_TIMEOUT_SECONDS: f64 = 3.0;
/// `_REDIRECT_STATUSES` (restricted_archive_download.py).
const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];
/// `_DNS_RESOLVER_MAX_INFLIGHT` (restricted_archive_destination.py).
const DNS_RESOLVER_MAX_INFLIGHT: usize = 2;

/// Bounded semaphore mirroring `_DNS_RESOLVER_SLOTS` — at most
/// `DNS_RESOLVER_MAX_INFLIGHT` concurrent blocking `getaddrinfo` calls.
static DNS_RESOLVER_INFLIGHT: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static ARCHIVE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `restricted_archive_contract.RestrictedArchiveFailure` mirror.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestrictedArchiveFailure {
    pub code: String,
    pub message: String,
}

/// `restricted_archive_contract.RestrictedArchiveDownload` mirror.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestrictedArchiveDownload {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub source_url: String,
    pub final_url: String,
}

impl RestrictedArchiveDownload {
    /// `RestrictedArchiveDownload.cleanup` — remove the staged blob if present.
    pub fn cleanup(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `restricted_archive_contract.RestrictedArchiveDownloadResult` union mirror.
#[derive(Debug, Clone)]
pub enum RestrictedArchiveDownloadResult {
    Success(RestrictedArchiveDownload),
    Failure(RestrictedArchiveFailure),
}

/// `_CanonicalDestination` (restricted_archive_contract.py).
#[derive(Debug, Clone)]
pub struct CanonicalDestination {
    pub url: String,
    pub hostname: String,
    pub port: u16,
    pub request_target: String,
    pub host_header: String,
}

/// `_RestrictedDownloadError` (restricted_archive_contract.py).
#[derive(Debug, Clone)]
pub struct RestrictedDownloadError {
    pub code: String,
    pub message: String,
}

impl RestrictedDownloadError {
    pub(crate) fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for RestrictedDownloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.code)
    }
}

impl std::error::Error for RestrictedDownloadError {}

// ---------------------------------------------------------------------------
// Transport seams — the Python code binds raw sockets, verifies DNS pinning,
// and drives `http.client` directly. None of that exists in this workspace,
// so the shape is carried as traits with the same observable contract.
// ---------------------------------------------------------------------------

/// `_ReadableResponse` protocol (restricted_archive_contract.py).
pub trait ReadableResponse: Send {
    /// `read(amount)` — bounded body read, `amount` bytes or fewer.
    fn read(&mut self, amount: usize) -> Result<Vec<u8>, RestrictedDownloadError>;
    /// `get_header(name)` — case-insensitive single header lookup.
    fn get_header(&self, name: &str) -> Option<String>;
    /// `header_items()` — all response headers in wire order.
    fn header_items(&self) -> Vec<(String, String)>;
    /// `set_timeout(seconds)` — push the remaining budget into the socket.
    fn set_timeout(&mut self, seconds: f64);
    /// `close()` — release the TLS socket / response.
    fn close(&mut self);
    /// Response status code.
    fn status(&self) -> u16;
}

/// DNS resolution seam for `socket.getaddrinfo` (address-family filtered to
/// `AF_INET`/`AF_INET6`, `SOCK_STREAM`). Returns textual literal addresses.
pub trait DnsResolver: Send + Sync {
    /// `socket.getaddrinfo(hostname, None)` restricted to `AF_INET`/`AF_INET6`.
    /// `Ok(None)` mirrors `socket.gaierror` (host did not resolve);
    /// `Err` mirrors an unexpected resolver failure.
    fn getaddrinfo(&self, hostname: &str) -> Result<Option<Vec<String>>, String>;

    /// Default slot acquisition mirroring `_DNS_RESOLVER_SLOTS` + the
    /// `DNS_RESOLVER_WAIT_SECONDS` poll loop. The slot is released on drop.
    fn resolve_with_slot(
        &self,
        hostname: &str,
        deadline: Instant,
    ) -> Result<Option<Vec<String>>, RestrictedDownloadError> {
        let _slot = DnsResolverSlot::acquire(deadline)?;
        match self.getaddrinfo(hostname) {
            Ok(addresses) => Ok(addresses),
            Err(_) => Err(RestrictedDownloadError::new(
                "external_archive_dns_unresolved",
                "External archive destination did not resolve to a usable public address.",
            )),
        }
    }
}

/// `_DNS_RESOLVER_SLOTS.acquire(blocking=False)` + bounded poll loop.
pub(super) struct DnsResolverSlot;

impl DnsResolverSlot {
    pub(super) fn acquire(deadline: Instant) -> Result<DnsResolverSlot, RestrictedDownloadError> {
        require_remaining(deadline)?;
        loop {
            let inflight = DNS_RESOLVER_INFLIGHT.load(Ordering::SeqCst);
            if inflight >= DNS_RESOLVER_MAX_INFLIGHT {
                return Err(RestrictedDownloadError::new(
                    "external_archive_dns_timeout",
                    "External archive DNS resolver capacity is unavailable.",
                ));
            }
            if DNS_RESOLVER_INFLIGHT
                .compare_exchange(inflight, inflight + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Ok(DnsResolverSlot);
            }
        }
    }
}

impl Drop for DnsResolverSlot {
    fn drop(&mut self) {
        DNS_RESOLVER_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
    }
}

/// `_PinnedHTTPSResponse` analogue — the transport owns the socket+TLS+HTTP
/// plumbing behind [`ReadableResponse`]; this seam opens one pinned
/// connection to a pre-validated public address.
pub trait PinnedHttpsTransport: Send + Sync {
    /// Enforce managed destination policy on every hop, before DNS or sockets.
    fn validate_destination(
        &self,
        _destination: &CanonicalDestination,
    ) -> Result<(), RestrictedDownloadError> {
        Ok(())
    }
    /// `_open_pinned_https_response(destination, address, deadline=deadline)`.
    /// Implementations MUST verify the connected peer equals `address`
    /// (`external_archive_dns_rebinding` otherwise), wrap TLS with
    /// `server_hostname=destination.hostname`, issue the `GET` request built
    /// from `destination.request_target` / `destination.host_header`, and
    /// surface header-parse failures as
    /// `external_archive_response_headers_invalid`.
    fn open_pinned_https_response(
        &self,
        destination: &CanonicalDestination,
        address: &str,
        deadline: Instant,
    ) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError>;
}

/// Deadline helpers mirroring `restricted_archive_deadline.py`.
fn monotonic_now() -> Instant {
    Instant::now()
}

/// `_remaining_seconds(deadline)` — deadline already expired → timeout error.
fn remaining_seconds(deadline: Instant) -> f64 {
    match deadline.checked_duration_since(Instant::now()) {
        Some(remaining) => remaining.as_secs_f64(),
        None => {
            // Python raises the caller-specific timeout via
            // `_call_with_deadline`; for the pre-check sites the shared
            // "time limit" error is the same observable failure.
            0.0
        }
    }
}

/// Raise the deadline-expired error used by `_remaining_seconds` callers.
fn deadline_exceeded() -> RestrictedDownloadError {
    RestrictedDownloadError::new(
        "external_archive_download_timeout",
        "External archive download exceeded Guard's time limit.",
    )
}

pub(super) fn require_remaining(deadline: Instant) -> Result<f64, RestrictedDownloadError> {
    let remaining = remaining_seconds(deadline);
    if remaining <= 0.0 {
        return Err(deadline_exceeded());
    }
    Ok(remaining)
}

// ---------------------------------------------------------------------------
// restricted_archive_destination.py — canonicalization + DNS policy
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// `_address_is_public` — mirrors `ipaddress` exactly.
// ---------------------------------------------------------------------------

/// `_resolve_public_addresses` (restricted_archive_destination.py:158).
fn resolve_public_addresses(
    destination: &CanonicalDestination,
    resolver: &dyn DnsResolver,
    deadline: Instant,
) -> Result<Vec<String>, RestrictedDownloadError> {
    // Literal IP — no DNS resolution needed.
    if let Ok(literal) = destination.hostname.parse::<IpAddr>() {
        if !address_is_public(literal) {
            return Err(RestrictedDownloadError::new(
                "external_archive_destination_rejected",
                "External archive destination resolved to a non-public address.",
            ));
        }
        return Ok(vec![literal.to_string()]);
    }
    let results = match resolver.resolve_with_slot(&destination.hostname, deadline) {
        Ok(Some(infos)) => infos,
        Ok(None) => {
            return Err(RestrictedDownloadError::new(
                "external_archive_dns_unresolved",
                "External archive destination did not resolve to a usable public address.",
            ))
        }
        Err(error) => return Err(error),
    };

    let mut addresses: BTreeMap<Vec<u8>, String> = BTreeMap::new();
    let mut rejected_non_public = false;
    for info in results {
        let parsed = match info.parse::<IpAddr>() {
            Ok(address) => address,
            Err(_) => {
                return Err(RestrictedDownloadError::new(
                    "external_archive_dns_unresolved",
                    "External archive destination returned an invalid DNS address.",
                ))
            }
        };
        if address_is_public(parsed) {
            let key = match parsed {
                IpAddr::V4(v4) => [vec![4], v4.octets().to_vec()].concat(),
                IpAddr::V6(v6) => [vec![6], v6.octets().to_vec()].concat(),
            };
            addresses.entry(key).or_insert_with(|| parsed.to_string());
        } else {
            rejected_non_public = true;
        }
    }
    if rejected_non_public && !addresses.is_empty() {
        return Err(RestrictedDownloadError::new(
            "external_archive_dns_ambiguous",
            "External archive destination returned mixed public and non-public DNS addresses.",
        ));
    }
    if rejected_non_public {
        return Err(RestrictedDownloadError::new(
            "external_archive_destination_rejected",
            "External archive destination resolved to a non-public address.",
        ));
    }
    if addresses.is_empty() {
        return Err(RestrictedDownloadError::new(
            "external_archive_dns_unresolved",
            "External archive destination did not resolve to a usable public address.",
        ));
    }
    Ok(addresses.into_values().collect())
}

/// `_open_destination` (restricted_archive_download.py:164).
fn open_destination(
    destination: &CanonicalDestination,
    addresses: &[String],
    transport: &dyn PinnedHttpsTransport,
    deadline: Instant,
) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
    let mut last_failure: Option<RestrictedDownloadError> = None;
    for address in addresses {
        match transport.open_pinned_https_response(destination, address, deadline) {
            Ok(response) => return Ok(response),
            Err(error) => {
                if error.code == "external_archive_dns_rebinding" {
                    return Err(error);
                }
                last_failure = Some(error);
            }
        }
    }
    match last_failure {
        Some(error) => Err(error),
        None => Err(RestrictedDownloadError::new(
            "external_archive_connection_failed",
            "External archive connection failed.",
        )),
    }
}

// ---------------------------------------------------------------------------
// restricted_archive_stream.py — bounded read / digest / spill
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// restricted_archive_download.py — policy, redirect, and entry point
// ---------------------------------------------------------------------------

/// `download_restricted_archive` (restricted_archive_download.py:194).
pub fn download_restricted_archive(
    source_url: &str,
    max_bytes: u64,
    max_redirects: u32,
    timeout_seconds: f64,
    temp_dir: Option<&Path>,
    resolver: &dyn DnsResolver,
    transport: &dyn PinnedHttpsTransport,
) -> RestrictedArchiveDownloadResult {
    if max_bytes == 0 || !timeout_seconds.is_finite() || timeout_seconds <= 0.0 {
        return RestrictedArchiveDownloadResult::Failure(RestrictedArchiveFailure {
            code: "external_archive_download_policy_invalid".to_string(),
            message: "External archive download policy is invalid.".to_string(),
        });
    }
    let deadline = monotonic_now() + std::time::Duration::from_secs_f64(timeout_seconds);
    let mut current_url = source_url.to_string();
    let mut response: Option<Box<dyn ReadableResponse>> = None;
    let outcome = (|| -> Result<RestrictedArchiveDownload, RestrictedDownloadError> {
        for redirect_count in 0..=max_redirects {
            let destination = canonical_destination(&current_url)?;
            transport.validate_destination(&destination)?;
            let addresses = resolve_public_addresses(&destination, resolver, deadline)?;
            response = Some(open_destination(
                &destination,
                &addresses,
                transport,
                deadline,
            )?);
            validate_response_headers(response.as_ref().unwrap().as_ref())?;
            if REDIRECT_STATUSES.contains(&response.as_ref().unwrap().status()) {
                let location = response_header(response.as_ref().unwrap().as_ref(), "Location");
                if let Some(mut opened) = response.take() {
                    opened.close();
                }
                if redirect_count >= max_redirects {
                    return Err(RestrictedDownloadError::new(
                        "external_archive_redirect_limit",
                        "External archive exceeded Guard's redirect limit.",
                    ));
                }
                let location = match location {
                    Some(value) if !value.trim().is_empty() => value.trim().to_string(),
                    _ => {
                        return Err(RestrictedDownloadError::new(
                            "external_archive_redirect_rejected",
                            "External archive redirect did not provide a valid destination.",
                        ))
                    }
                };
                let redirect_url = urljoin(&destination.url, &location);
                match canonical_destination(&redirect_url) {
                    Ok(next) => current_url = next.url,
                    Err(_) => {
                        return Err(RestrictedDownloadError::new(
                            "external_archive_redirect_rejected",
                            "External archive redirect did not provide a valid public HTTPS destination.",
                        ))
                    }
                }
                continue;
            }
            if response.as_ref().unwrap().status() != 200 {
                return Err(RestrictedDownloadError::new(
                    "external_archive_http_error",
                    "External archive server returned a non-success response.",
                ));
            }
            let download = write_bounded_response(
                response.as_mut().unwrap().as_mut(),
                source_url,
                &destination.url,
                deadline,
                max_bytes,
                temp_dir,
            )?;
            if let Some(mut opened) = response.take() {
                opened.close();
            }
            return Ok(download);
        }
        Err(RestrictedDownloadError::new(
            "external_archive_redirect_limit",
            "External archive exceeded Guard's redirect limit.",
        ))
    })();
    if let Some(mut open) = response.take() {
        open.close();
    }
    match outcome {
        Ok(download) => RestrictedArchiveDownloadResult::Success(download),
        Err(error) => RestrictedArchiveDownloadResult::Failure(RestrictedArchiveFailure {
            code: error.code,
            message: error.message,
        }),
    }
}

/// `restricted_archive_download_sha256` — pull the digest off a success
/// payload; mirrors `restricted_archive_download_sha256(download)` in
/// `local_supply_chain.py`.
pub fn restricted_archive_download_sha256(
    download: &RestrictedArchiveDownloadResult,
) -> Option<String> {
    match download {
        RestrictedArchiveDownloadResult::Success(value) => Some(value.sha256.clone()),
        _ => None,
    }
}

/// `restricted_archive_download_to_evidence` — JSON projection consumed by
/// `local_supply_chain` evidence plumbing.
pub fn restricted_archive_download_to_evidence(
    download: &RestrictedArchiveDownloadResult,
) -> serde_json::Value {
    match download {
        RestrictedArchiveDownloadResult::Success(value) => serde_json::json!({
            "status": "downloaded",
            "path": value.path.to_string_lossy(),
            "sha256": value.sha256,
            "size": value.size,
            "source_url": value.source_url,
            "final_url": value.final_url,
        }),
        RestrictedArchiveDownloadResult::Failure(failure) => serde_json::json!({
            "status": "failed",
            "code": failure.code,
            "message": failure.message,
        }),
    }
}
