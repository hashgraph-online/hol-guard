//! Concrete `DnsResolver` + `PinnedHttpsTransport` for restricted archive
//! acquisition (RTM-029).
//!
//! `SystemDnsResolver` invokes system resolution through `std::net` and returns textual
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
    CanonicalDestination, DnsResolver, DnsResolverSlot, PinnedHttpsTransport, ReadableResponse,
    RestrictedDownloadError,
};

/// System `getaddrinfo` — the contract requires `AF_INET`/`AF_INET6`,
/// `SOCK_STREAM`, so `(hostname, port)` tuple resolution is the direct port.
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve_with_slot(
        &self,
        hostname: &str,
        deadline: Instant,
    ) -> Result<Option<Vec<String>>, RestrictedDownloadError> {
        let hostname = hostname.to_owned();
        resolve_system_with(deadline, move || SystemDnsResolver.getaddrinfo(&hostname))
    }

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

fn resolve_system_with(
    deadline: Instant,
    operation: impl FnOnce() -> Result<Option<Vec<String>>, String> + Send + 'static,
) -> Result<Option<Vec<String>>, RestrictedDownloadError> {
    let slot = DnsResolverSlot::acquire(deadline)?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("guard-archive-dns".into())
        .spawn(move || {
            // A timed-out getaddrinfo still holds its slot until it actually exits.
            let _slot = slot;
            let _ = sender.send(operation());
        })
        .map_err(|_| {
            RestrictedDownloadError::new(
                "external_archive_dns_unresolved",
                "External archive DNS resolver could not be started.",
            )
        })?;
    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(RestrictedDownloadError::new(
                "external_archive_dns_unresolved",
                "External archive destination could not be resolved.",
            ))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(RestrictedDownloadError::new(
            "external_archive_dns_timeout",
            "External archive destination DNS resolution timed out.",
        )),
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
            .map_err(|error| {
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) || error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<ureq::Error>())
                    .is_some_and(|e| matches!(e, ureq::Error::Timeout(_)))
                {
                    return RestrictedDownloadError::new(
                        "external_archive_download_timeout",
                        "External archive download exceeded Guard's time limit.",
                    );
                }
                RestrictedDownloadError::new(
                    "external_archive_incomplete_response",
                    "External archive response ended before the body completed.",
                )
            })?;
        buf.truncate(n);
        Ok(buf)
    }

    fn get_header(&self, name: &str) -> Option<String> {
        let values: Vec<_> = self
            .inner
            .headers()
            .get_all(name)
            .iter()
            .map(|value| {
                value
                    .as_bytes()
                    .iter()
                    .map(|b| char::from(*b))
                    .collect::<String>()
            })
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }

    fn header_items(&self) -> Vec<(String, String)> {
        self.inner
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    v.as_bytes().iter().map(|b| char::from(*b)).collect(),
                )
            })
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

#[cfg(test)]
#[path = "restricted_archive_transport_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "restricted_archive_https_tests.rs"]
mod https_tests;

// ---------------------------------------------------------------------------
// ureq transport — pins the resolver, TLS verifies the hostname.
// ---------------------------------------------------------------------------

/// `PinnedHttpsTransport` over `ureq` + `rustls`. The custom `Resolver`
/// guarantees the TCP connect only ever targets the validated `address`;
/// `ureq`'s built-in connector carries the TLS layer, which verifies
/// `destination.hostname` (SNI + webpki chain).
pub struct UreqPinnedTransport;

/// Trust material selected by the existing platform/managed policy service.
pub struct ManagedUreqPinnedTransport {
    pub roots: Vec<Vec<u8>>,
    pub allow_public_registries: bool,
}

impl PinnedHttpsTransport for ManagedUreqPinnedTransport {
    fn validate_destination(
        &self,
        destination: &CanonicalDestination,
    ) -> Result<(), RestrictedDownloadError> {
        validate_managed_destination(destination, self.allow_public_registries)
    }
    fn open_pinned_https_response(
        &self,
        destination: &CanonicalDestination,
        address: &str,
        deadline: Instant,
    ) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
        self.validate_destination(destination)?;
        if self.roots.is_empty() {
            return Err(RestrictedDownloadError::new(
                "external_archive_tls_error",
                "External archive TLS verification failed.",
            ));
        }
        let certificates: Vec<_> = self
            .roots
            .iter()
            .map(|der| ureq::tls::Certificate::from_der(der).to_owned())
            .collect();
        open_pinned(
            destination,
            address,
            deadline,
            Some(ureq::tls::RootCerts::from(certificates)),
        )
    }
}

/// Share the managed registry refusal across initial URLs and redirected hops.
pub fn validate_managed_destination(
    destination: &CanonicalDestination,
    allow_public_registries: bool,
) -> Result<(), RestrictedDownloadError> {
    if !allow_public_registries && PUBLIC_REGISTRIES.contains(&destination.hostname.as_str()) {
        return Err(RestrictedDownloadError::new(
            "managed_public_registry_disabled",
            "Managed network policy refused",
        ));
    }
    Ok(())
}

/// The registries a managed policy refuses when it disables public
/// registries, shared with the brokered egress caller's own destination check.
pub const PUBLIC_REGISTRIES: &[&str] = &[
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "api.npmjs.org",
    "registry.yarnpkg.com",
    "crates.io",
    "static.crates.io",
    "rubygems.org",
    "repo1.maven.org",
    "repo.maven.apache.org",
    "proxy.golang.org",
    "goproxy.io",
];

impl PinnedHttpsTransport for UreqPinnedTransport {
    fn open_pinned_https_response(
        &self,
        destination: &CanonicalDestination,
        address: &str,
        deadline: Instant,
    ) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
        open_pinned(destination, address, deadline, None)
    }
}

fn open_pinned(
    destination: &CanonicalDestination,
    address: &str,
    deadline: Instant,
    roots: Option<ureq::tls::RootCerts>,
) -> Result<Box<dyn ReadableResponse>, RestrictedDownloadError> {
    use ureq::unversioned::transport::{Connector, RustlsConnector};
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
    let mut builder = ureq::config::Config::builder()
        .proxy(None)
        .https_only(true)
        .max_redirects(0)
        .http_status_as_error(false)
        .timeout_global(Some(remaining))
        .timeout_resolve(Some(Duration::from_secs(5)))
        .timeout_connect(Some(remaining))
        .timeout_recv_response(Some(remaining))
        .timeout_recv_body(Some(remaining))
        .max_response_header_size(32 * 1024);
    if let Some(roots) = roots {
        builder = builder.tls_config(ureq::tls::TlsConfig::builder().root_certs(roots).build());
    }
    let config = builder.build();
    let agent = ureq::Agent::with_parts(
        config,
        super::restricted_archive_peer::PinnedConnector {
            peer: SocketAddr::new(addr, destination.port),
            deadline,
        }
        .chain(RustlsConnector::default()),
        PinnedResolver { addr },
    );
    let response = agent
        .get(&destination.url)
        .header("Host", &destination.host_header)
        .header("Accept", "application/octet-stream")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", "hol-guard-restricted-archive/1")
        .call()
        .map_err(|e| match e {
            ureq::Error::Timeout(_) => RestrictedDownloadError::new(
                "external_archive_download_timeout",
                "External archive download exceeded Guard's time limit.",
            ),
            ureq::Error::Io(ref error) if error.kind() == std::io::ErrorKind::InvalidData => {
                RestrictedDownloadError::new(
                    "external_archive_tls_error",
                    "External archive TLS verification failed.",
                )
            }
            ureq::Error::Tls(_) | ureq::Error::TlsRequired => RestrictedDownloadError::new(
                "external_archive_tls_error",
                "External archive TLS verification failed.",
            ),
            ureq::Error::LargeResponseHeader(..) | ureq::Error::Protocol(_) => {
                RestrictedDownloadError::new(
                    "external_archive_response_headers_invalid",
                    "External archive response headers were malformed or exceeded Guard's limit.",
                )
            }
            ureq::Error::Io(ref error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                RestrictedDownloadError::new(
                    "external_archive_dns_rebinding",
                    "External archive connection did not use the validated DNS address.",
                )
            }
            _ => RestrictedDownloadError::new(
                "external_archive_connection_failed",
                "External archive connection failed.",
            ),
        })?;
    Ok(Box::new(UreqResponse { inner: response }))
}
