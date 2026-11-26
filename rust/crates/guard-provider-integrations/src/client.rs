//! The HTTPS transport to a provider.
//!
//! Every request names one host, which must be on the manifest's pinned list before anything
//! connects. The URL is always `https://<host><path>`, built here from parts that were checked, so a
//! request cannot carry a port, user info, a query or a fragment. Redirects are never followed:
//! a `3xx` answer is a transport failure. The exchange runs through
//! `guard_command::egress_caller::policy_send`, which applies the managed network policy (refused
//! destinations, proxy, trust roots) and bounds the body and the wall-clock time.

use std::collections::BTreeMap;

use guard_command::egress_caller::{policy_send, EgressPolicy};
use guard_contracts::EgressOutcomeV1;
use zeroize::Zeroizing;

use crate::ProviderClientError;

/// The HTTP method a capability uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderMethod {
    Get,
    Post,
}

impl ProviderMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// One request to a provider. `key` is the API key; it is only ever placed in `header`.
pub struct ProviderRequest {
    pub method: ProviderMethod,
    pub host: String,
    pub path: String,
    pub header: String,
    pub key: Zeroizing<String>,
    pub body: Option<String>,
}

/// The bounds one exchange runs under, from the manifest's `limits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderLimits {
    pub timeout_ms: u64,
    pub max_response_bytes: u64,
}

/// What the provider answered: any non-redirect status, with its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Something that can carry a provider exchange: the HTTPS client, or the testkit.
pub trait ProviderTransport {
    fn send(
        &self,
        request: &ProviderRequest,
        limits: ProviderLimits,
    ) -> Result<ProviderResponse, ProviderClientError>;
}

/// The HTTPS client: pinned hosts and the managed network policy it runs under.
pub struct HttpProviderTransport<'a> {
    pinned_hosts: Vec<String>,
    policy: &'a dyn EgressPolicy,
}

impl<'a> HttpProviderTransport<'a> {
    pub fn new(pinned_hosts: Vec<String>, policy: &'a dyn EgressPolicy) -> Self {
        Self {
            pinned_hosts,
            policy,
        }
    }
}

fn is_dns_host(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes[0] != b'-'
                && bytes[bytes.len() - 1] != b'-'
                && bytes
                    .iter()
                    .all(|&byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && labels
            .last()
            .is_some_and(|tld| tld.as_bytes()[0].is_ascii_lowercase())
}

/// A literal absolute path of `[A-Za-z0-9._~-]` segments with no empty, `.` or `..` segment.
pub(crate) fn is_request_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    path.len() <= 256
        && (rest.is_empty()
            || rest.split('/').all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-')
                    })
            }))
}

/// Header names the transport sets itself, that frame the message, or that a proxy reads. A
/// credential under one of these would replace the JSON headers or mis-frame the request.
const RESERVED_HEADERS: &[&str] = &[
    "accept",
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "expect",
    "host",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !RESERVED_HEADERS.contains(&name)
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_header_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// The URL for a checked request: only the scheme, the pinned host and the literal path.
pub(crate) fn checked_url(
    request: &ProviderRequest,
    pinned_hosts: &[String],
) -> Result<String, ProviderClientError> {
    if !is_dns_host(&request.host) || !pinned_hosts.iter().any(|host| host == &request.host) {
        return Err(ProviderClientError::HostNotPinned);
    }
    if !is_request_path(&request.path) {
        return Err(ProviderClientError::PathInvalid);
    }
    if !is_header_name(&request.header) || !is_header_value(&request.key) {
        return Err(ProviderClientError::CredentialInvalid);
    }
    Ok(format!("https://{}{}", request.host, request.path))
}

/// Map a refused exchange onto a provider error. The outcome's own text never leaves here.
fn refused(outcome: &EgressOutcomeV1) -> ProviderClientError {
    match outcome {
        EgressOutcomeV1::Blocked { .. } => ProviderClientError::Blocked,
        EgressOutcomeV1::Timeout => ProviderClientError::Timeout,
        EgressOutcomeV1::Error { message } if message == "response too large" => {
            ProviderClientError::ResponseTooLarge
        }
        _ => ProviderClientError::Transport,
    }
}

impl ProviderTransport for HttpProviderTransport<'_> {
    fn send(
        &self,
        request: &ProviderRequest,
        limits: ProviderLimits,
    ) -> Result<ProviderResponse, ProviderClientError> {
        let url = checked_url(request, &self.pinned_hosts)?;
        let mut headers = BTreeMap::new();
        headers.insert("accept".to_owned(), "application/json".to_owned());
        if request.body.is_some() {
            headers.insert("content-type".to_owned(), "application/json".to_owned());
        }
        headers.insert(request.header.clone(), request.key.as_str().to_owned());
        let seconds = limits.timeout_ms as f64 / 1000.0;
        let (status, _, body) = policy_send(
            request.method.as_str(),
            &url,
            headers,
            request.body.clone(),
            seconds,
            0,
            limits.max_response_bytes,
            self.policy,
        )
        .map_err(|outcome| refused(&outcome))?;
        if (300..400).contains(&status) {
            return Err(ProviderClientError::Transport);
        }
        Ok(ProviderResponse { status, body })
    }
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
