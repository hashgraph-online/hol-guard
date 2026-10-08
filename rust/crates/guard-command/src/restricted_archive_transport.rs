//! Concrete `DnsResolver` + `PinnedHttpsTransport` for restricted archive
//! acquisition (RTM-029).
//!
//! `SystemDnsResolver` shells `getaddrinfo` via `std::net` and returns textual
//! addresses; the policy layer (`resolve_public_addresses`) filters them to
//! public-only before any transport runs. `UreqPinnedTransport` issues the
//! `GET` through `ureq` with a resolver pinned to the validated peer address —
//! DNS pinning is enforced because the resolver never lets the connection
//! dial anything else — while TLS still verifies `destination.hostname`
//! end-to-end (SNI + cert).

use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::restricted_archive::{
    CanonicalDestination, DnsResolver, PinnedHttpsTransport, ReadableResponse,
    RestrictedDownloadError,
};

/// System `getaddrinfo` — the contract requires `AF_INET`/`AF_INET6`,
/// `SOCK_STREAM`, so `(hostname, port)` tuple resolution is the direct port.
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn getaddrinfo(&self, hostname: &str) -> Result<Option<Vec<String>>, String> {
        // Port 443 only used to drive `ToSocketAddrs`; the transport pins the
        // real port. `getaddrinfo` returns `SocketAddr`s; we surface the IP
        // text exactly like Python's `item[4][0]`.
        match (hostname, 443u16).to_socket_addrs() {
            Ok(iter) => {
                let mut out = Vec::new();
                for sa in iter {
                    out.push(sa.ip().to_string());
                }
                if out.is_empty() {
                    // `socket.gaierror` analogue — unresolvable name.
                    Ok(None)
                } else {
                    Ok(Some(out))
                }
            }
            Err(e) => {
                // `gaierror` is the only non-fatal class; anything else is a
                // resolver failure the caller surfaces as `Err`.
                let text = e.to_string();
                if text.contains("failed to lookup address")
                    || text.contains("Name or service not known")
                    || text.contains("nodename nor servname provided")
                    || text.contains("Temporary failure in name resolution")
                {
                    Ok(None)
                } else {
                    Err(text)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pinned-IP ureq resolver — returns only the validated peer address.
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PinnedResolver {
    addr: IpAddr,
}

impl ureq::unversioned::resolver::Resolver for PinnedResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        let port = uri.port_u16().unwrap_or(443);
        let mut out = ureq::unversioned::resolver::ResolvedSocketAddrs::from_fn(|_| {
            SocketAddr::new(self.addr, port)
        });
        out.push(SocketAddr::new(self.addr, port));
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// ureq-backed response — `ReadableResponse` over `http::Response<Body>`.
// ---------------------------------------------------------------------------

struct UreqResponse {
    inner: ureq::http::Response<ureq::Body>,
}

impl ReadableResponse for UreqResponse {
    fn read(&mut self, amount: usize) -> Result<Vec<u8>, RestrictedDownloadError> {
        let mut buf = vec![0u8; amount.max(1)];
        let n = self
            .inner
            .body_mut()
            .as_reader()
            .read(&mut buf)
            .map_err(|_| {
                RestrictedDownloadError::new(
                    "external_archive_incomplete_response",
                    "External archive response ended before the body completed.",
                )
            })?;
        buf.truncate(n);
        Ok(buf)
    }

    fn get_header(&self, name: &str) -> Option<String> {
        self.inner
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }

    fn header_items(&self) -> Vec<(String, String)> {
        self.inner
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
            .collect()
    }

    fn set_timeout(&mut self, _seconds: f64) {
        // ureq drives timeouts through `Config::timeout_global`; the response
        // itself has no socket handle to retimeout. The deadline is still
        // enforced between chunks by the policy layer.
    }

    fn close(&mut self) {
        // Dropping the response releases the pooled connection.
    }

    fn status(&self) -> u16 {
        self.inner.status().as_u16()
    }
}

// ---------------------------------------------------------------------------
// ureq transport — pins the resolver, TLS verifies the hostname.
// ---------------------------------------------------------------------------

/// `PinnedHttpsTransport` over `ureq` + `rustls`. The custom `Resolver`
/// guarantees the TCP connect only ever targets the validated `address`;
/// `ureq`'s built-in connector carries the TLS layer, which verifies
/// `destination.hostname` (SNI + webpki chain).
pub struct UreqPinnedTransport;

impl PinnedHttpsTransport for UreqPinnedTransport {
    fn open_pinned_https_response(
        &self,
        destination: &CanonicalDestination,
        address: &str,
        deadline: Instant,
    ) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
        let addr = address
            .split('%')
            .next()
            .unwrap_or(address)
            .parse::<IpAddr>()
            .map_err(|_| {
                RestrictedDownloadError::new(
                    "external_archive_dns_rebinding",
                    "External archive connection did not use the validated DNS address.",
                )
            })?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(RestrictedDownloadError::new(
                "external_archive_download_timeout",
                "External archive download exceeded Guard's time limit.",
            ));
        }
        let config = ureq::config::Config::builder()
            .proxy(None)
            .https_only(true)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(remaining))
            .timeout_resolve(Some(Duration::from_secs(5)))
            .timeout_connect(Some(remaining))
            .timeout_recv_response(Some(remaining))
            .timeout_recv_body(Some(remaining))
            .build();
        let agent = ureq::Agent::with_parts(
            config,
            ureq::unversioned::transport::DefaultConnector::default(),
            PinnedResolver { addr },
        );
        let response = agent
            .get(&destination.url)
            .header("Host", &destination.host_header)
            .call()
            .map_err(|e| match e {
                ureq::Error::Timeout(_) => RestrictedDownloadError::new(
                    "external_archive_response_timeout",
                    "External archive response exceeded Guard's time limit.",
                ),
                ureq::Error::Tls(_) | ureq::Error::TlsRequired => RestrictedDownloadError::new(
                    "external_archive_tls_error",
                    "External archive TLS verification failed.",
                ),
                _ => RestrictedDownloadError::new(
                    "external_archive_connection_failed",
                    "External archive connection failed.",
                ),
            })?;
        Ok(Box::new(UreqResponse { inner: response }))
    }
}
