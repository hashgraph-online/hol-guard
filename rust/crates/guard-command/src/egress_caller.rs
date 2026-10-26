//! Caller side of the brokered egress for supply-chain evaluation.
//!
//! The resident answers `supply_chain_egress_required` with the exchanges it
//! wants (see `egress_broker` for the replay rules and
//! `guard_contracts::supply_chain_egress` for the wire shapes). This module
//! performs them and keeps the outcomes the next request must carry. It only
//! moves bytes: the resident parses every response and owns every decision.
//!
//! Port of `native_supply_chain_egress.py`'s `EgressExchanger`, with the same
//! bounds: one exchange is capped in wall-clock time as well as per read, a
//! redirect is followed only for a credential-free body-less read, a body is
//! inlined while the request's inline budget allows and spooled otherwise, and
//! an oversized body is an error rather than a truncated answer.
//!
//! The destination allow-list, policy proxy, CA bundle and proxy credentials
//! of a managed network policy are not resolved here: a caller that performs
//! exchanges through [`EgressFulfilment`] supplies them as an
//! [`EgressPolicy`], and [`UnmanagedEgressPolicy`] is only correct where the
//! caller has established that no managed policy applies.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use guard_contracts::{
    EgressNeedV1, EgressOutcomeV1, EgressSuppliedV1, EGRESS_MAX_HEADERS,
    EGRESS_MAX_INLINE_BODY_BYTES, EGRESS_MAX_NEEDS, EGRESS_MAX_SUPPLIED,
};

/// Wall-clock cap for one exchange. The `timeout_seconds` the resident asks
/// for bounds the connect and each read; this bounds a peer that keeps every
/// read just inside it. It stays inside the resident's evaluation timeout.
pub const MAX_EXCHANGE_SECONDS: f64 = 20.0;
/// Cap for a retry pause the resident asked the caller to wait.
pub const MAX_DELAY_SECONDS: f64 = 30.0;
/// Inline bodies stop short of the request-size budget so the rest of every
/// supplied outcome, and the artifact, still fit.
const INLINE_BUDGET_BYTES: usize = 64 * 1024;
const REDIRECT_STATUSES: [u16; 5] = [301, 302, 303, 307, 308];
/// A credential or cookie must never ride along to a redirect target.
const CREDENTIAL_HEADERS: [&str; 4] = ["authorization", "dpop", "cookie", "proxy-authorization"];
/// The request headers that may follow a hop to another origin. A header the
/// resident set for its destination is not sent to a host that destination
/// redirected to, so a bespoke credential header cannot be harvested by a
/// redirect.
const CROSS_ORIGIN_HEADERS: [&str; 6] = [
    "accept",
    "accept-encoding",
    "accept-language",
    "if-modified-since",
    "if-none-match",
    "user-agent",
];

/// How much of a managed policy's refusal code is reported.
pub(crate) const POLICY_CODE_MAX_CHARS: usize = 128;

/// What an archive need is told when the managed policy refuses its
/// destination, whether it is refused here or at the bound transport's hop.
pub(crate) const ARCHIVE_POLICY_REFUSAL_MESSAGE: &str =
    "External archive destination is refused by the managed network policy.";

/// The managed network policy the caller performs exchanges under.
pub trait EgressPolicy {
    /// `Err(code)` refuses the destination; the code reaches the resident as
    /// a `blocked` outcome.
    fn validate(&self, url: &str) -> Result<(), String>;

    /// The proxy this destination is reached through. The default is the
    /// unmanaged answer: the environment's own proxy configuration, as
    /// `requests` does with `trust_env` set.
    fn proxy(&self, _url: &str) -> EgressProxy {
        EgressProxy::Environment
    }

    /// The trust anchors every exchange verifies against. The default is the
    /// unmanaged answer: the TLS stack's own roots.
    fn trust(&self) -> EgressTrust {
        EgressTrust::Default
    }
}

/// What an exchange verifies the destination's and the proxy's certificates
/// against.
#[derive(Clone)]
pub enum EgressTrust {
    /// No managed policy pins trust, so the TLS stack's own roots verify.
    Default,
    /// The managed trust roots. A managed policy with a private CA has the
    /// whole set exported for it - public, system and private together, as
    /// `export_managed_trust_roots` materialises them - so these are the only
    /// anchors an exchange accepts. Verification is never relaxed and never
    /// falls back to the default roots.
    Roots(Arc<Vec<ureq::tls::Certificate<'static>>>),
}

/// How one exchange reaches its destination.
pub enum EgressProxy {
    /// No managed policy applies, so the environment's proxy variables are
    /// honoured — `session.trust_env = not managed`.
    Environment,
    /// A managed policy applies and selects no proxy for this destination.
    /// The environment is not consulted: a managed machine with no policy
    /// proxy connects directly.
    Direct,
    /// Every hop goes through this already-validated proxy URL, with the
    /// proxy-only credentials the managed OS credential store holds for it.
    Url {
        url: String,
        credentials: Option<EgressProxyCredentials>,
    },
}

/// `ProxyCredentials` (mdm/network_transport.py:191).
///
/// Authorization for the proxy itself, never for the destination and never a
/// policy secret: the managed OS credential store holds it and it is sent on
/// the proxy exchange alone.
#[derive(Clone)]
pub struct EgressProxyCredentials {
    pub username: String,
    pub password: String,
}

/// External archives the caller acquires for the resident, when it has that
/// wired. An archive need is not an HTTP exchange: the caller downloads the
/// blob under bounded acquisition and inspects it offline.
pub trait ArchiveEgress {
    fn fulfil(&mut self, need: &EgressNeedV1) -> EgressOutcomeV1;

    /// Hand over the retained blobs the resident's answer names and remove
    /// every other blob this acquisition holds.
    ///
    /// An answer that names a blob the caller does not hold is a protocol
    /// failure, not an empty claim: nothing may launch against bytes nobody
    /// inspected.
    fn claim(
        &mut self,
        descriptors: &serde_json::Value,
    ) -> Result<Vec<crate::restricted_archive::RestrictedArchiveDownload>, &'static str>;
}

/// No managed network policy applies. Only correct where the caller has
/// established that: a machine with a managed policy document refuses
/// destinations this allows.
pub struct UnmanagedEgressPolicy;

impl EgressPolicy for UnmanagedEgressPolicy {
    fn validate(&self, _url: &str) -> Result<(), String> {
        Ok(())
    }
}

/// The exchanges performed so far, and where a spooled body is written.
pub struct EgressFulfilment<'a> {
    spool_dir: PathBuf,
    policy: &'a dyn EgressPolicy,
    archives: Option<&'a mut dyn ArchiveEgress>,
    supplied: Vec<EgressSuppliedV1>,
    inline_used: usize,
    spool_count: u32,
}

impl<'a> EgressFulfilment<'a> {
    /// A caller that cannot acquire external archives; archive needs report
    /// that acquisition is unavailable.
    pub fn new(spool_dir: &Path, policy: &'a dyn EgressPolicy) -> Self {
        Self {
            spool_dir: spool_dir.to_path_buf(),
            policy,
            archives: None,
            supplied: Vec::new(),
            inline_used: 0,
            spool_count: 0,
        }
    }

    /// A caller that also performs the external-archive needs.
    pub fn with_archives(
        spool_dir: &Path,
        policy: &'a dyn EgressPolicy,
        archives: &'a mut dyn ArchiveEgress,
    ) -> Self {
        Self {
            archives: Some(archives),
            ..Self::new(spool_dir, policy)
        }
    }

    /// Every outcome the next request must carry, in the order asked.
    pub fn supplied(&self) -> &[EgressSuppliedV1] {
        &self.supplied
    }

    /// Where a spooled body is written, which the next request must name so
    /// the resident reads the body from the same directory.
    pub fn spool_dir(&self) -> &Path {
        &self.spool_dir
    }

    /// The retained archive blobs the resident's answer names.
    ///
    /// A caller with no archive acquisition wired holds nothing, so an answer
    /// that names a blob is the same protocol failure as one that names a blob
    /// an acquisition never retained.
    pub fn claim_archives(
        &mut self,
        descriptors: Option<&serde_json::Value>,
    ) -> Result<Vec<crate::restricted_archive::RestrictedArchiveDownload>, &'static str> {
        let nothing = serde_json::Value::Null;
        let descriptors = descriptors.unwrap_or(&nothing);
        match self.archives.as_mut() {
            Some(archives) => archives.claim(descriptors),
            // Python's `elif descriptors:` refuses any truthy descriptor here,
            // not just a non-empty list: a malformed container still names
            // blobs this caller never held.
            None if truthy(descriptors) => Err(crate::egress_caller_archive::UNHELD_ARCHIVE),
            None => Ok(Vec::new()),
        }
    }

    /// Perform one answer's needs. The resident replays the whole evaluation
    /// every round, so the outcomes accumulate across rounds.
    pub fn fulfil(&mut self, needs: &[EgressNeedV1]) -> Result<(), &'static str> {
        if needs.len() > EGRESS_MAX_NEEDS {
            return Err("egress_needs_too_many");
        }
        for need in needs {
            if self.supplied.len() >= EGRESS_MAX_SUPPLIED {
                return Err("egress_supplied_too_many");
            }
            let supplied = self.answer(need);
            self.supplied.push(supplied);
        }
        Ok(())
    }

    fn answer(&mut self, need: &EgressNeedV1) -> EgressSuppliedV1 {
        let delay = need.delay_seconds.clamp(0.0, MAX_DELAY_SECONDS);
        if delay > 0.0 && delay.is_finite() {
            std::thread::sleep(Duration::from_secs_f64(delay));
        }
        let outcome = if need.class == "archive" {
            // The archive path answers through a separate acquisition seam, so
            // the destination is screened here as well: a caller cannot reach
            // a host the managed policy refuses by routing it as an archive.
            match self.policy.validate(&need.url) {
                Err(code) => archive_refusal(&code),
                Ok(()) => match self.archives.as_mut() {
                    Some(archives) => archives.fulfil(need),
                    // A caller that has not wired archive acquisition reports
                    // the refusal; the resident never dials out for the blob
                    // itself.
                    None => EgressOutcomeV1::ArchiveFailure {
                        code: "external_archive_download_unavailable".to_owned(),
                        message: "External archive acquisition is unavailable.".to_owned(),
                    },
                },
            }
        } else {
            self.http(need)
        };
        EgressSuppliedV1 {
            class: need.class.clone(),
            method: need.method.clone(),
            url: need.url.clone(),
            body_sha256: need.body_sha256.clone(),
            occurrence: need.occurrence,
            outcome,
        }
    }

    fn http(&mut self, need: &EgressNeedV1) -> EgressOutcomeV1 {
        match fetch(need, self.policy) {
            Fetched::Outcome(outcome) => outcome,
            Fetched::Response {
                status,
                headers,
                body,
            } => self.response_outcome(status, headers, body, need.max_response_bytes),
        }
    }

    fn response_outcome(
        &mut self,
        status: u16,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
        limit: u64,
    ) -> EgressOutcomeV1 {
        if body.len() as u64 > limit {
            return error_outcome("response too large");
        }
        let headers = headers.into_iter().take(EGRESS_MAX_HEADERS).collect();
        if body.is_empty() {
            return EgressOutcomeV1::Response {
                status,
                headers,
                body: None,
                body_file: None,
            };
        }
        if self.inline_used + body.len() <= INLINE_BUDGET_BYTES {
            if let Some(text) = inline_text(&body) {
                self.inline_used += body.len();
                return EgressOutcomeV1::Response {
                    status,
                    headers,
                    body: Some(text),
                    body_file: None,
                };
            }
        }
        match self.spool(&body) {
            Ok(name) => EgressOutcomeV1::Response {
                status,
                headers,
                body: None,
                body_file: Some(name),
            },
            Err(message) => error_outcome(&message),
        }
    }

    /// Write the body under a fresh name in the spool directory, refusing to
    /// follow a link or to replace a file that is already there.
    fn spool(&mut self, body: &[u8]) -> Result<String, String> {
        self.spool_count += 1;
        let name = format!("body-{}", self.spool_count);
        let path = self.spool_dir.join(&name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut handle = options
            .open(&path)
            .map_err(|error| format!("spool: {}", error.kind()))?;
        handle
            .write_all(body)
            .map_err(|error| format!("spool: {}", error.kind()))?;
        Ok(name)
    }
}

/// What one exchange produced: the final response, or the outcome replacing it.
enum Fetched {
    Response {
        status: u16,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    },
    Outcome(EgressOutcomeV1),
}

/// Perform one HTTP exchange, following the redirects the need allows.
///
/// Redirects are never followed by the transport: each hop is a fresh request,
/// so the managed policy validates every destination and the exact hop limit
/// the resident asked for is enforced here.
fn fetch(need: &EgressNeedV1, policy: &dyn EgressPolicy) -> Fetched {
    let mut url = need.url.clone();
    let body = need.body.as_ref().map(|text| text.as_bytes().to_vec());
    let budget = redirect_budget(
        &need.method,
        body.is_some(),
        &need.headers,
        need.max_redirects,
    );
    let deadline = Instant::now() + Duration::from_secs_f64(MAX_EXCHANGE_SECONDS);
    let origin = origin_of(&url);
    let mut hops = 0u32;
    loop {
        if !matches!(scheme_of(&url).as_deref(), Some("http") | Some("https")) {
            return Fetched::Outcome(blocked("egress_scheme_not_allowed"));
        }
        if let Err(code) = policy.validate(&url) {
            return Fetched::Outcome(EgressOutcomeV1::Blocked {
                code: policy_code(&code),
            });
        }
        let cross_origin = hops > 0 && origin_of(&url) != origin;
        let response = match exchange(
            need,
            &url,
            body.clone(),
            deadline,
            cross_origin,
            &policy.proxy(&url),
            &policy.trust(),
        ) {
            Ok(response) => response,
            Err(outcome) => return Fetched::Outcome(*outcome),
        };
        if budget > 0 && REDIRECT_STATUSES.contains(&response.status) {
            if let Some(location) = response.headers.get("location") {
                if hops >= budget {
                    return Fetched::Outcome(error_outcome("too many redirects"));
                }
                let Some(target) = redirect_target(&url, location) else {
                    return Fetched::Outcome(blocked("egress_redirect_not_allowed"));
                };
                url = target;
                hops += 1;
                continue;
            }
        }
        return Fetched::Response {
            status: response.status,
            headers: response.headers,
            body: response.body,
        };
    }
}

/// The managed policy's proxy, with the proxy-only credentials the OS
/// credential store holds for it.
///
/// ureq holds the credentials in the proxy's own URI and emits them as a
/// `Proxy-Authorization` header on the proxy's CONNECT exchange, so the
/// destination never sees them. They never reach the request URL that log lines
/// and error outcomes carry, and `load_proxy_credentials` has already refused
/// any credential that URI authority parsing would not carry literally.
///
/// The host keeps the brackets a bracketed IPv6 address arrives with: the
/// builder assembles `scheme://user:pass@host:port` and parses it back, so a
/// bare `::1` would not survive as an authority.
fn managed_proxy(url: &str, credentials: Option<&EgressProxyCredentials>) -> Option<ureq::Proxy> {
    let Some(credentials) = credentials else {
        return ureq::Proxy::new(url).ok();
    };
    let (scheme, authority) = url.split_once("://")?;
    let protocol = match scheme {
        "http" => ureq::ProxyProtocol::Http,
        "https" => ureq::ProxyProtocol::Https,
        _ => return None,
    };
    let (host, port) = authority.rsplit_once(':')?;
    ureq::Proxy::builder(protocol)
        .host(host)
        .port(port.parse().ok()?)
        .username(&credentials.username)
        .password(&credentials.password)
        .build()
        .ok()
}

struct Exchange {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

/// One request, with no redirect followed by the transport.
///
/// `cross_origin` says the hop left the origin the need addressed, so only the
/// headers in [`CROSS_ORIGIN_HEADERS`] are carried over.
fn exchange(
    need: &EgressNeedV1,
    url: &str,
    body: Option<Vec<u8>>,
    deadline: Instant,
    cross_origin: bool,
    proxy: &EgressProxy,
    trust: &EgressTrust,
) -> Result<Exchange, Box<EgressOutcomeV1>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Box::new(EgressOutcomeV1::Timeout));
    }
    let per_read = Duration::from_secs_f64(per_read_seconds(need.timeout_seconds));
    let builder = ureq::config::Config::builder()
        .timeout_global(Some(remaining))
        .timeout_connect(Some(per_read.min(remaining)))
        .timeout_recv_response(Some(per_read.min(remaining)))
        .timeout_recv_body(Some(per_read.min(remaining)))
        .http_status_as_error(false)
        .max_redirects(0);
    // A managed policy with a private certificate authority pins the anchors
    // every certificate on the exchange is verified against, the proxy's
    // included. The roots it supplies are the whole managed set, so pinning
    // them does not drop the public ones.
    let builder = match trust {
        EgressTrust::Default => builder,
        EgressTrust::Roots(roots) => builder.tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::Specific(roots.clone()))
                .build(),
        ),
    };
    // The default configuration reads `HTTP_PROXY` and friends. Under a
    // managed policy the environment is not authority, so the proxy is set
    // from the policy's answer on every exchange.
    let config = match proxy {
        EgressProxy::Environment => builder.build(),
        EgressProxy::Direct => builder.proxy(None).build(),
        EgressProxy::Url { url, credentials } => match managed_proxy(url, credentials.as_ref()) {
            Some(proxy) => builder.proxy(Some(proxy)).build(),
            None => {
                return Err(Box::new(blocked("managed_proxy_url_invalid")));
            }
        },
    };
    let agent = ureq::Agent::with_parts(
        config,
        ureq::unversioned::transport::DefaultConnector::default(),
        ureq::unversioned::resolver::DefaultResolver::default(),
    );
    let mut builder = ureq::http::Request::builder()
        .method(need.method.to_uppercase().as_str())
        .uri(url);
    for (name, value) in &need.headers {
        if cross_origin && !carries_across_origins(name) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    let request = builder
        .body(body.unwrap_or_default())
        .map_err(|_| Box::new(error_outcome("request")))?;
    let mut response = agent
        .run(request)
        .map_err(|error| Box::new(map_error(error)))?;
    let status = response.status().as_u16();
    let mut headers = BTreeMap::new();
    for (name, value) in response.headers() {
        if let Ok(text) = value.to_str() {
            headers.insert(name.as_str().to_ascii_lowercase(), text.to_owned());
        }
    }
    // One byte past the cap, so an oversized body is detectable rather than
    // silently truncated into an answer the resident would parse.
    let body = response
        .body_mut()
        .with_config()
        .limit(need.max_response_bytes.saturating_add(1))
        .read_to_vec()
        .map_err(|error| Box::new(map_error(error)))?;
    Ok(Exchange {
        status,
        headers,
        body,
    })
}

fn map_error(error: ureq::Error) -> EgressOutcomeV1 {
    match error {
        ureq::Error::Timeout(_) => EgressOutcomeV1::Timeout,
        ureq::Error::Io(inner) if inner.kind() == std::io::ErrorKind::TimedOut => {
            EgressOutcomeV1::Timeout
        }
        ureq::Error::Io(inner) => error_outcome(&format!("io: {}", inner.kind())),
        ureq::Error::Tls(_) | ureq::Error::TlsRequired | ureq::Error::Rustls(_) => {
            error_outcome("tls")
        }
        ureq::Error::BodyExceedsLimit(_) => error_outcome("response too large"),
        ureq::Error::HostNotFound => error_outcome("host not found"),
        _ => error_outcome("transport"),
    }
}

/// The refusal an archive need gets when the managed policy denies its
/// destination, reported in the archive shape the resident expects.
fn archive_refusal(code: &str) -> EgressOutcomeV1 {
    EgressOutcomeV1::ArchiveFailure {
        code: policy_code(code),
        message: ARCHIVE_POLICY_REFUSAL_MESSAGE.to_owned(),
    }
}

/// A refusal code from the managed policy, bounded so a policy cannot put an
/// unbounded string into an answer. Cut on a character boundary: the code is
/// reported, not parsed as bytes.
pub(crate) fn policy_code(code: &str) -> String {
    match code.char_indices().nth(POLICY_CODE_MAX_CHARS) {
        Some((end, _)) => code[..end].to_owned(),
        None => code.to_owned(),
    }
}

fn error_outcome(message: &str) -> EgressOutcomeV1 {
    EgressOutcomeV1::Error {
        message: message.to_owned(),
    }
}

fn blocked(code: &str) -> EgressOutcomeV1 {
    EgressOutcomeV1::Blocked {
        code: code.to_owned(),
    }
}

/// Redirects are followed only for body-less reads that carry no credential.
fn redirect_budget(
    method: &str,
    has_body: bool,
    headers: &BTreeMap<String, String>,
    requested: u32,
) -> u32 {
    if requested == 0 || has_body {
        return 0;
    }
    let method = method.to_ascii_uppercase();
    if method != "GET" && method != "HEAD" {
        return 0;
    }
    if headers
        .keys()
        .any(|name| CREDENTIAL_HEADERS.contains(&name.to_ascii_lowercase().as_str()))
    {
        return 0;
    }
    requested.min(10)
}

/// Resolve a `Location`, refusing a non-HTTP scheme or an https -> http hop.
fn redirect_target(current: &str, location: &str) -> Option<String> {
    let target = join_url(current, location)?;
    let scheme = scheme_of(&target)?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    if scheme_of(current).as_deref() == Some("https") && scheme != "https" {
        return None;
    }
    Some(target)
}

/// Resolve `location` against `current` the way `urllib.parse.urljoin` does:
/// absolute, protocol-relative, root-relative, query-only or relative to the
/// current path, with `.` and `..` segments removed.
fn join_url(current: &str, location: &str) -> Option<String> {
    let location = location.trim();
    if location.is_empty() || location.contains(['\r', '\n', ' ']) {
        return None;
    }
    let mut target = url::Url::parse(current).ok()?.join(location).ok()?;
    // A fragment is never put on the wire, and each hop is its own request.
    target.set_fragment(None);
    Some(target.into())
}

/// The scheme, host and port a URL addresses, for comparing two hops.
fn origin_of(url: &str) -> Option<String> {
    Some(url::Url::parse(url).ok()?.origin().ascii_serialization())
}

/// Whether a request header the resident set may follow a hop that leaves the
/// origin the need addressed. Anything else — a registry token in a bespoke
/// header, say — stays with the origin it was addressed to.
fn carries_across_origins(name: &str) -> bool {
    CROSS_ORIGIN_HEADERS.contains(&name.to_ascii_lowercase().as_str())
}

/// The connect and per-read bound for one exchange: the timeout the resident
/// asked for, never widened, capped by the wall-clock bound. A value that is
/// not a usable duration falls back to that cap, which the deadline in
/// [`fetch`] still bounds.
fn per_read_seconds(requested: f64) -> f64 {
    if requested.is_finite() && requested > 0.0 {
        requested.min(MAX_EXCHANGE_SECONDS)
    } else {
        MAX_EXCHANGE_SECONDS
    }
}

/// The lowercase scheme of an absolute URL.
fn scheme_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty()
        || rest.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return None;
    }
    Some(scheme.to_ascii_lowercase())
}

/// CPython's truth value for a decoded JSON value.
fn truthy(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(flag) => *flag,
        serde_json::Value::Number(number) => number.as_f64() != Some(0.0),
        serde_json::Value::String(text) => !text.is_empty(),
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(fields) => !fields.is_empty(),
    }
}

fn inline_text(body: &[u8]) -> Option<String> {
    if body.len() > EGRESS_MAX_INLINE_BODY_BYTES {
        return None;
    }
    String::from_utf8(body.to_vec()).ok()
}

#[cfg(test)]
#[path = "egress_caller_tests.rs"]
mod tests;
