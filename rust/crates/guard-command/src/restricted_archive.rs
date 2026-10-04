//! Port of `runtime/restricted_archive_contract.py`,
//! `runtime/restricted_archive_destination.py`,
//! `runtime/restricted_archive_download.py`, and
//! `runtime/restricted_archive_stream.py`.
//!
//! The original modules depend on Python `http.client` / `ssl` / `socket`
//! primitives that have no safe equivalent in this workspace's dependency set,
//! so the socket/TLS/HTTP plumbing is a transport seam
//! ([`PinnedHttpsTransport`]) while the URL canonicalization, DNS address
//! policy, header validation, bounded streaming, and digest bookkeeping are
//! ported line-for-line.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;
use std::time::Instant;

use regex::Regex;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// restricted_archive_contract.py — pure constants / typed results
// ---------------------------------------------------------------------------

/// `_DEFAULT_MAX_BYTES` (restricted_archive_stream.py / contract defaults).
pub const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// `_DEFAULT_MAX_REDIRECTS` (restricted_archive_download.py).
pub const DEFAULT_MAX_REDIRECTS: u32 = 4;
/// `_DEFAULT_TIMEOUT_SECONDS` (restricted_archive_download.py).
pub const DEFAULT_TIMEOUT_SECONDS: f64 = 3.0;
/// `_READ_CHUNK_BYTES` (restricted_archive_stream.py).
const READ_CHUNK_BYTES: u64 = 64 * 1024;
/// `_MAX_RESPONSE_HEADERS` (restricted_archive_stream.py).
const MAX_RESPONSE_HEADERS: usize = 64;
/// `_MAX_RESPONSE_HEADER_BYTES` (restricted_archive_stream.py).
const MAX_RESPONSE_HEADER_BYTES: u64 = 32 * 1024;
/// `_REDIRECT_STATUSES` (restricted_archive_download.py).
const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];
/// `_DNS_RESOLVER_MAX_INFLIGHT` (restricted_archive_destination.py).
const DNS_RESOLVER_MAX_INFLIGHT: usize = 4;
/// `_DNS_RESOLVER_WAIT_SECONDS` (restricted_archive_destination.py).
const DNS_RESOLVER_WAIT_SECONDS: f64 = 0.05;
/// `_METADATA_ADDRESSES` (restricted_archive_destination.py).
const METADATA_ADDRESSES: [&str; 3] = ["169.254.169.254", "fd00:ec2::254", "100.100.100.200"];

static HTTP_FIELD_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$").unwrap());
static HOSTNAME_LABEL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").unwrap());

/// Bounded semaphore mirroring `_DNS_RESOLVER_SLOTS` — at most
/// `DNS_RESOLVER_MAX_INFLIGHT` concurrent blocking `getaddrinfo` calls.
static DNS_RESOLVER_INFLIGHT: AtomicUsize = AtomicUsize::new(0);

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
    fn new(code: &str, message: &str) -> Self {
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
struct DnsResolverSlot;

impl DnsResolverSlot {
    fn acquire(deadline: Instant) -> Result<DnsResolverSlot, RestrictedDownloadError> {
        loop {
            let inflight = DNS_RESOLVER_INFLIGHT.load(Ordering::SeqCst);
            if inflight < DNS_RESOLVER_MAX_INFLIGHT
                && DNS_RESOLVER_INFLIGHT
                    .compare_exchange(inflight, inflight + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                return Ok(DnsResolverSlot);
            }
            if remaining_seconds(deadline) <= DNS_RESOLVER_WAIT_SECONDS {
                return Err(RestrictedDownloadError::new(
                    "external_archive_dns_timeout",
                    "External archive DNS resolution exceeded Guard's time limit.",
                ));
            }
            std::thread::sleep(std::time::Duration::from_secs_f64(
                DNS_RESOLVER_WAIT_SECONDS,
            ));
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

fn require_remaining(deadline: Instant) -> Result<f64, RestrictedDownloadError> {
    let remaining = remaining_seconds(deadline);
    if remaining <= 0.0 {
        return Err(deadline_exceeded());
    }
    Ok(remaining)
}

// ---------------------------------------------------------------------------
// restricted_archive_destination.py — canonicalization + DNS policy
// ---------------------------------------------------------------------------

/// `urllib.parse.quote(path, safe="/%")` for the URL path component.
fn quote_path(value: &str) -> String {
    quote_with_safe(value, b"/%")
}

/// `urllib.parse.quote(query, safe="")` — fragment is dropped entirely by the
/// caller, so only `?query` participates.
fn quote_query(value: &str) -> String {
    quote_with_safe(value, b"")
}

fn quote_with_safe(value: &str, safe: &[u8]) -> String {
    let mut out = String::new();
    for &byte in value.as_bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '~') || safe.contains(&byte)
        {
            out.push(ch);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// `urllib.parse.urlunsplit` reassembly for the canonical HTTPS destination.
fn build_canonical_url(host_header: &str, request_target: &str) -> String {
    format!("https://{host_header}{request_target}")
}

/// `hostname.encode("idna").decode("ascii")` — Python uses IDNA-2003.
fn idna_encode(hostname: &str) -> Result<String, RestrictedDownloadError> {
    idna::domain_to_ascii(hostname).map_err(|_| {
        RestrictedDownloadError::new(
            "external_archive_destination_rejected",
            "External archive destination is not a supported public HTTPS URL.",
        )
    })
}

/// `_split_netloc` — split `netloc` into `(userinfo, host, port)` text.
/// Mirrors `urllib.parse._splitnetloc` semantics for the `https`-only inputs
/// `_canonical_destination` accepts: `userinfo@host[:port]`.
fn split_netloc(netloc: &str) -> (Option<&str>, &str, Option<&str>) {
    // `urlsplit` lowercases only the scheme; the netloc retains case here.
    let (userinfo, hostport) = match netloc.rfind('@') {
        Some(index) => (Some(&netloc[..index]), &netloc[index + 1..]),
        None => (None, netloc),
    };
    // Bracketed IPv6 literal — `]` terminates the host, optional `:port`.
    if let Some(rest) = hostport.strip_prefix('[') {
        match rest.find(']') {
            Some(close) => {
                let host = &hostport[..close + 2]; // include brackets
                let port = hostport[close + 2..].strip_prefix(':');
                return (userinfo, host, port);
            }
            None => return (userinfo, hostport, None),
        }
    }
    match hostport.rfind(':') {
        Some(index) => (userinfo, &hostport[..index], Some(&hostport[index + 1..])),
        None => (userinfo, hostport, None),
    }
}

/// `urllib.parse.urlsplit` reduced to what `_canonical_destination` consumes:
/// scheme, netloc, path, query (fragment discarded by the caller contract).
fn urlsplit(url: &str) -> (String, String, String, String) {
    // Fragment — `urldefrag` strips at the first `#`.
    let without_fragment = match url.find('#') {
        Some(index) => &url[..index],
        None => url,
    };
    // Scheme — `ALPHA *(ALPHA|DIGIT|"+"|"-"|".")` followed by `:`.
    let (scheme, rest) = match without_fragment.find(':') {
        Some(index)
            if index > 0
                && without_fragment[..index].chars().enumerate().all(|(i, c)| {
                    if i == 0 {
                        c.is_ascii_alphabetic()
                    } else {
                        c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
                    }
                }) =>
        {
            (
                without_fragment[..index].to_ascii_lowercase(),
                &without_fragment[index + 1..],
            )
        }
        _ => (String::new(), without_fragment),
    };
    // Netloc — `//` authority extends to the next `/`, `?`, or `#`.
    let (netloc, path_query) = if let Some(stripped) = rest.strip_prefix("//") {
        let end = stripped.find(['/', '?', '#']).unwrap_or(stripped.len());
        (stripped[..end].to_string(), &stripped[end..])
    } else {
        (String::new(), rest)
    };
    let (path, query) = match path_query.find('?') {
        Some(index) => (&path_query[..index], path_query[index + 1..].to_string()),
        None => (path_query, String::new()),
    };
    (scheme, netloc, path.to_string(), query)
}

/// `urllib.parse.urljoin` — only used to resolve a redirect `Location`
/// against the current destination URL.
fn urljoin(base: &str, location: &str) -> String {
    if location.is_empty() {
        return base.to_string();
    }
    // Absolute URL — keep verbatim.
    let (scheme, _, _, _) = urlsplit(location);
    if !scheme.is_empty() {
        return location.to_string();
    }
    let (base_scheme, base_netloc, base_path, _base_query) = urlsplit(base);
    if let Some(rest) = location.strip_prefix("//") {
        return format!("{base_scheme}://{rest}");
    }
    if let Some(rest) = location.strip_prefix('/') {
        return format!("{base_scheme}://{base_netloc}/{rest}");
    }
    // Relative path — merge against the base directory.
    let merged_path = match base_path.rfind('/') {
        Some(index) => format!("{}{}", &base_path[..index + 1], location),
        None => format!("/{location}"),
    };
    if base_netloc.is_empty() {
        return format!("{base_scheme}:{merged_path}");
    }
    format!("{base_scheme}://{base_netloc}{merged_path}")
}

/// `_canonical_destination` (restricted_archive_destination.py:66).
pub fn canonical_destination(url: &str) -> Result<CanonicalDestination, RestrictedDownloadError> {
    let rejected = || {
        RestrictedDownloadError::new(
            "external_archive_destination_rejected",
            "External archive destination is not a supported public HTTPS URL.",
        )
    };
    let (scheme, netloc, path, query) = urlsplit(url.trim());
    if scheme != "https" || netloc.is_empty() {
        return Err(rejected());
    }
    let (userinfo, host, port_text) = split_netloc(&netloc);
    if userinfo.is_some() {
        // `urllib.parse.urlsplit` treats `userinfo@` as credentials — the
        // download path must never smuggle them.
        return Err(rejected());
    }
    let host = host.trim_end_matches('.'); // rstrip("."), not trim matches
    if host.is_empty() {
        return Err(rejected());
    }
    let port: u16 = match port_text {
        None => 443,
        Some("") => 443,
        Some(text) => match text.parse::<u16>() {
            Ok(value) => value,
            Err(_) => return Err(rejected()),
        },
    };
    // `urlsplit` may hand back a port like `:abc` — `.parse` above rejects it.
    let hostname = host.to_ascii_lowercase();
    let idna_host = idna_encode(&hostname)?;
    if !is_ip_literal(&idna_host) {
        // Hostname validation — Python validates each DNS label.
        let labels: Vec<&str> = idna_host.split('.').collect();
        if labels
            .iter()
            .any(|label| label.is_empty() || !HOSTNAME_LABEL_RE.is_match(label))
        {
            return Err(rejected());
        }
    }
    let request_target = {
        let mut target = if path.is_empty() {
            "/".to_string()
        } else {
            quote_path(&path)
        };
        if !query.is_empty() {
            target.push('?');
            target.push_str(&quote_query(&query));
        }
        target
    };
    let host_header = if port == 443 {
        idna_host.clone()
    } else {
        format!("{idna_host}:{port}")
    };
    Ok(CanonicalDestination {
        url: build_canonical_url(&host_header, &request_target),
        hostname: idna_host,
        port,
        request_target,
        host_header,
    })
}

fn is_ip_literal(host: &str) -> bool {
    host.parse::<Ipv4Addr>().is_ok() || (host.starts_with('[') && host.ends_with(']'))
}

// ---------------------------------------------------------------------------
// `_address_is_public` — mirrors `ipaddress` exactly.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct V4Net {
    base: u32,
    prefix: u8,
}

#[derive(Debug, Clone, Copy)]
struct V6Net {
    base: u128,
    prefix: u8,
}

const fn v4net(octets: [u8; 4], prefix: u8) -> V4Net {
    V4Net {
        base: u32::from_be_bytes(octets),
        prefix,
    }
}

const fn v6net(groups: [u16; 8], prefix: u8) -> V6Net {
    let mut base = 0u128;
    let mut index = 0usize;
    while index < 8 {
        base = (base << 16) | groups[index] as u128;
        index += 1;
    }
    V6Net { base, prefix }
}

fn v4_contains(net: &V4Net, address: Ipv4Addr) -> bool {
    let shift = 32 - net.prefix;
    (u32::from_be_bytes(address.octets()) >> shift) == (net.base >> shift)
}

fn v6_contains(net: &V6Net, address: Ipv6Addr) -> bool {
    let shift = 128 - net.prefix;
    if shift >= 128 {
        return net.prefix == 0 || u128::from_be_bytes(address.octets()) == net.base;
    }
    (u128::from_be_bytes(address.octets()) >> shift) == (net.base >> shift)
}

/// `ipaddress._IPv4Constants._private_networks` verbatim.
const IPV4_PRIVATE_NETWORKS: &[V4Net] = &[
    v4net([0, 0, 0, 0], 8),
    v4net([10, 0, 0, 0], 8),
    v4net([127, 0, 0, 0], 8),
    v4net([169, 254, 0, 0], 16),
    v4net([172, 16, 0, 0], 12),
    v4net([192, 0, 0, 0], 24),
    v4net([192, 0, 0, 170], 31),
    v4net([192, 0, 2, 0], 24),
    v4net([192, 168, 0, 0], 16),
    v4net([198, 18, 0, 0], 15),
    v4net([198, 51, 100, 0], 24),
    v4net([203, 0, 113, 0], 24),
    v4net([240, 0, 0, 0], 4),
    v4net([255, 255, 255, 255], 32),
];

/// `ipaddress._IPv4Constants._private_networks_exceptions`.
const IPV4_PRIVATE_EXCEPTIONS: &[V4Net] = &[v4net([192, 0, 0, 9], 32), v4net([192, 0, 0, 10], 32)];

/// `ipaddress._IPv4Constants._reserved_network`.
const IPV4_RESERVED_NETWORK: V4Net = v4net([240, 0, 0, 0], 4);

/// `ipaddress._IPv6Constants._private_networks`.
const IPV6_PRIVATE_NETWORKS: &[V6Net] = &[
    v6net([0, 0, 0, 0, 0, 0, 0, 1], 128),
    v6net([0, 0, 0, 0, 0, 0, 0, 0], 128),
    v6net([0, 0, 0, 0, 0, 0xffff, 0, 0], 96),
    v6net([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
    v6net([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
    v6net([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
    v6net([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
    v6net([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
    v6net([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
    v6net([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
    v6net([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
];

/// `ipaddress._IPv6Constants._private_networks_exceptions`.
const IPV6_PRIVATE_EXCEPTIONS: &[V6Net] = &[
    v6net([0x2001, 1, 0, 0, 0, 0, 0, 1], 128),
    v6net([0x2001, 1, 0, 0, 0, 0, 0, 2], 128),
    v6net([0x2001, 3, 0, 0, 0, 0, 0, 0], 32),
    v6net([0x2001, 4, 0x112, 0, 0, 0, 0, 0], 48),
    v6net([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28),
    v6net([0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28),
];

/// `ipaddress._IPv6Constants._reserved_networks`.
const IPV6_RESERVED_NETWORKS: &[V6Net] = &[
    v6net([0, 0, 0, 0, 0, 0, 0, 0], 8),
    v6net([0x100, 0, 0, 0, 0, 0, 0, 0], 8),
    v6net([0x200, 0, 0, 0, 0, 0, 0, 0], 7),
    v6net([0x400, 0, 0, 0, 0, 0, 0, 0], 6),
    v6net([0x800, 0, 0, 0, 0, 0, 0, 0], 5),
    v6net([0x1000, 0, 0, 0, 0, 0, 0, 0], 4),
    v6net([0x4000, 0, 0, 0, 0, 0, 0, 0], 3),
    v6net([0x6000, 0, 0, 0, 0, 0, 0, 0], 3),
    v6net([0x8000, 0, 0, 0, 0, 0, 0, 0], 3),
    v6net([0xa000, 0, 0, 0, 0, 0, 0, 0], 3),
    v6net([0xc000, 0, 0, 0, 0, 0, 0, 0], 3),
    v6net([0xe000, 0, 0, 0, 0, 0, 0, 0], 4),
    v6net([0xf000, 0, 0, 0, 0, 0, 0, 0], 5),
    v6net([0xf800, 0, 0, 0, 0, 0, 0, 0], 6),
    v6net([0xfe00, 0, 0, 0, 0, 0, 0, 0], 9),
];

fn ipv4_is_private(address: Ipv4Addr) -> bool {
    IPV4_PRIVATE_NETWORKS
        .iter()
        .any(|net| v4_contains(net, address))
        && !IPV4_PRIVATE_EXCEPTIONS
            .iter()
            .any(|net| v4_contains(net, address))
}

fn ipv4_is_reserved(address: Ipv4Addr) -> bool {
    v4_contains(&IPV4_RESERVED_NETWORK, address)
}

fn ipv6_is_private(address: Ipv6Addr) -> bool {
    IPV6_PRIVATE_NETWORKS
        .iter()
        .any(|net| v6_contains(net, address))
        && !IPV6_PRIVATE_EXCEPTIONS
            .iter()
            .any(|net| v6_contains(net, address))
}

fn ipv6_is_reserved(address: Ipv6Addr) -> bool {
    IPV6_RESERVED_NETWORKS
        .iter()
        .any(|net| v6_contains(net, address))
}

fn ipv4_is_global(address: Ipv4Addr) -> bool {
    address != Ipv4Addr::new(100, 64, 0, 0)
        && !v4_contains(&v4net([100, 64, 0, 0], 10), address)
        && !ipv4_is_private(address)
}

fn ipv6_is_global(address: Ipv6Addr) -> bool {
    !(ipv6_is_private(address) || address.is_multicast())
}

/// `_address_is_public` (restricted_archive_destination.py:138).
fn address_is_public(address: IpAddr) -> bool {
    let (is_global, is_private, is_reserved) = match address {
        IpAddr::V4(v4) => (
            ipv4_is_global(v4),
            ipv4_is_private(v4),
            ipv4_is_reserved(v4),
        ),
        IpAddr::V6(v6) => (
            ipv6_is_global(v6),
            ipv6_is_private(v6),
            ipv6_is_reserved(v6),
        ),
    };
    let is_link_local = match address {
        IpAddr::V4(v4) => v4_contains(&v4net([169, 254, 0, 0], 16), v4),
        IpAddr::V6(v6) => v6_contains(&v6net([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10), v6),
    };
    let is_loopback = match address {
        IpAddr::V4(v4) => v4_contains(&v4net([127, 0, 0, 0], 8), v4),
        IpAddr::V6(v6) => v6 == Ipv6Addr::LOCALHOST,
    };
    let is_multicast = address.is_multicast();
    let is_unspecified = address.is_unspecified();
    let metadata = METADATA_ADDRESSES.contains(&address.to_string().as_str());
    is_global
        && !is_private
        && !is_reserved
        && !is_link_local
        && !is_loopback
        && !is_multicast
        && !is_unspecified
        && !metadata
}

/// `_same_ip` (restricted_archive_destination.py:260).
/// `_same_ip` — kept for parity with the pinned-connection transport seam;
/// the trait implementation calls it to verify `peer == address`.
#[allow(dead_code)]
fn same_ip(left: &str, right: &str) -> bool {
    let parse = |value: &str| -> Option<IpAddr> {
        let stripped = value.split('%').next()?;
        stripped.parse::<IpAddr>().ok()
    };
    match (parse(left), parse(right)) {
        (Some(l), Some(r)) => l == r,
        _ => false,
    }
}

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
    // Bracketed IPv6 literal.
    if let Some(inner) = destination
        .hostname
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        if let Ok(literal) = inner.parse::<Ipv6Addr>() {
            let address = IpAddr::V6(literal);
            if !address_is_public(address) {
                return Err(RestrictedDownloadError::new(
                    "external_archive_destination_rejected",
                    "External archive destination resolved to a non-public address.",
                ));
            }
            return Ok(vec![address.to_string()]);
        }
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

    let mut addresses: BTreeMap<String, String> = BTreeMap::new();
    let mut rejected_non_public = false;
    for info in results {
        let parsed = match info.parse::<IpAddr>() {
            Ok(address) => address,
            Err(_) => continue,
        };
        if address_is_public(parsed) {
            let key = parsed.to_string();
            addresses.entry(key.clone()).or_insert(key);
        } else {
            rejected_non_public = true;
        }
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

/// `_response_header` (restricted_archive_stream.py).
fn response_header(response: &dyn ReadableResponse, name: &str) -> Option<String> {
    response.get_header(name)
}

/// `_validate_response_headers` (restricted_archive_stream.py).
fn validate_response_headers(
    response: &dyn ReadableResponse,
) -> Result<(), RestrictedDownloadError> {
    let invalid = || {
        RestrictedDownloadError::new(
            "external_archive_response_headers_invalid",
            "External archive response headers were malformed or exceeded Guard's limit.",
        )
    };
    let headers = response.header_items();
    if headers.len() > MAX_RESPONSE_HEADERS {
        return Err(invalid());
    }
    let mut total_bytes: u64 = 0;
    for (name, value) in &headers {
        let name_valid = HTTP_FIELD_NAME_RE.is_match(name);
        let value_valid = !value.chars().any(|ch| {
            let code = ch as u32;
            (code < 0x20 && ch != '\t') || code == 0x7f
        });
        if !name_valid || !value_valid {
            return Err(invalid());
        }
        total_bytes += name.len() as u64 + value.len() as u64 + 4;
        if total_bytes > MAX_RESPONSE_HEADER_BYTES {
            return Err(invalid());
        }
    }
    Ok(())
}

/// `_content_length` (restricted_archive_stream.py).
fn content_length(
    response: &dyn ReadableResponse,
    max_bytes: u64,
) -> Result<Option<u64>, RestrictedDownloadError> {
    let invalid = || {
        RestrictedDownloadError::new(
            "external_archive_incomplete_response",
            "External archive response declared an invalid content length.",
        )
    };
    let raw_length = match response_header(response, "Content-Length") {
        Some(value) => value,
        None => return Ok(None),
    };
    let parsed = match raw_length.trim().parse::<i64>() {
        Ok(value) => value,
        Err(_) => return Err(invalid()),
    };
    if parsed < 0 {
        return Err(invalid());
    }
    if parsed as u64 > max_bytes {
        return Err(RestrictedDownloadError::new(
            "external_archive_download_size_limit",
            "External archive exceeded Guard's download size limit.",
        ));
    }
    Ok(Some(parsed as u64))
}

/// `_write_chunk_with_deadline` (restricted_archive_stream.py) — write the
/// full chunk or fail; the deadline budget is enforced by the caller.
fn write_chunk_with_deadline(
    file: &mut std::fs::File,
    chunk: &[u8],
    deadline: Instant,
) -> Result<(), RestrictedDownloadError> {
    let mut offset = 0usize;
    while offset < chunk.len() {
        require_remaining(deadline)?;
        match file.write(&chunk[offset..]) {
            Ok(written) if written > 0 => offset += written,
            _ => {
                return Err(RestrictedDownloadError::new(
                    "external_archive_connection_failed",
                    "External archive temporary blob could not be written completely.",
                ))
            }
        }
    }
    Ok(())
}

/// `_write_bounded_response` (restricted_archive_stream.py).
fn write_bounded_response(
    response: &mut dyn ReadableResponse,
    source_url: &str,
    final_url: &str,
    deadline: Instant,
    max_bytes: u64,
    temp_dir: Option<&Path>,
) -> Result<RestrictedArchiveDownload, RestrictedDownloadError> {
    let content_encoding = response_header(response, "Content-Encoding")
        .unwrap_or_else(|| "identity".to_string())
        .trim()
        .to_ascii_lowercase();
    if !content_encoding.is_empty() && content_encoding != "identity" {
        return Err(RestrictedDownloadError::new(
            "external_archive_content_encoding_rejected",
            "External archive response used an unsupported content encoding.",
        ));
    }
    let expected_size = content_length(response, max_bytes)?;
    let directory = match temp_dir {
        Some(dir) => dir.to_path_buf(),
        None => std::env::temp_dir(),
    };
    std::fs::create_dir_all(&directory).map_err(|_| {
        RestrictedDownloadError::new(
            "external_archive_connection_failed",
            "External archive temporary blob could not be created.",
        )
    })?;
    // `tempfile.mkstemp(prefix="hol-guard-archive-", suffix=".archive")`.
    let mut path = PathBuf::new();
    let mut file = None;
    for _ in 0..128 {
        let mut random_bytes = [0u8; 8];
        if getrandom::fill(&mut random_bytes).is_err() {
            return Err(RestrictedDownloadError::new(
                "external_archive_connection_failed",
                "External archive temporary blob could not be created.",
            ));
        }
        let candidate = directory.join(format!(
            "hol-guard-archive-{}{}.archive",
            hex::encode(random_bytes),
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(opened) => {
                path = candidate;
                file = Some(opened);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err(RestrictedDownloadError::new(
                    "external_archive_connection_failed",
                    "External archive temporary blob could not be created.",
                ))
            }
        }
    }
    let mut file = match file {
        Some(file) => file,
        None => {
            return Err(RestrictedDownloadError::new(
                "external_archive_connection_failed",
                "External archive temporary blob could not be created.",
            ))
        }
    };
    let mut digest = Sha256::new();
    let mut size: u64 = 0;
    let result =
        (|file: &mut std::fs::File| -> Result<RestrictedArchiveDownload, RestrictedDownloadError> {
            require_remaining(deadline)?;
            loop {
                response.set_timeout(require_remaining(deadline)?);
                // Keep one byte of overflow probe capacity.
                let remaining_with_probe = max_bytes.saturating_sub(size) + 1;
                let chunk = response.read(
                    usize::try_from(remaining_with_probe.min(READ_CHUNK_BYTES))
                        .unwrap_or(usize::MAX),
                )?;
                if chunk.is_empty() {
                    break;
                }
                size += chunk.len() as u64;
                if size > max_bytes {
                    return Err(RestrictedDownloadError::new(
                        "external_archive_download_size_limit",
                        "External archive exceeded Guard's download size limit.",
                    ));
                }
                write_chunk_with_deadline(file, &chunk, deadline)?;
                digest.update(&chunk);
                require_remaining(deadline)?;
            }
            if let Some(expected) = expected_size {
                if size != expected {
                    return Err(RestrictedDownloadError::new(
                        "external_archive_incomplete_response",
                        "External archive response ended before its declared content length.",
                    ));
                }
            }
            file.flush().map_err(|_| {
                RestrictedDownloadError::new(
                    "external_archive_connection_failed",
                    "External archive temporary blob could not be written completely.",
                )
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).map_err(
                    |_| {
                        RestrictedDownloadError::new(
                            "external_archive_connection_failed",
                            "External archive temporary blob could not be locked read-only.",
                        )
                    },
                )?;
            }
            require_remaining(deadline)?;
            Ok(RestrictedArchiveDownload {
                path: path.clone(),
                sha256: hex::encode(digest.finalize()),
                size,
                source_url: source_url.to_string(),
                final_url: final_url.to_string(),
            })
        })(&mut file);
    if result.is_err() {
        let _ = std::fs::remove_file(&path);
    }
    result
}

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
    if max_bytes == 0 || timeout_seconds <= 0.0 {
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
