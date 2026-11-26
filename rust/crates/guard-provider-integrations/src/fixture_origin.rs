//! The loopback provider fixture origin (PRD 8.3).
//!
//! Gauntlet runs use exact-source release wheels, so the `testkit` feature is not there. A live case
//! instead starts a loopback provider stub and sets [`FIXTURE_ORIGIN_ENV`] in the resident's own
//! environment. It is the only provider test hook in a release build, and every restriction is
//! enforced here rather than trusted to the caller:
//!
//! - The value must be `http://127.0.0.1:<port>` and nothing else ([`FixtureOrigin::parse`]).
//! - It applies only to provider ids under [`PROVIDER_FIXTURE_ID_PREFIX`]. Any other provider keeps
//!   its pinned HTTPS host whatever the variable says ([`route`]).
//! - A fixture provider never reaches a real host: without a valid fixture origin it has no route.
//! - The only key ever sent to the fixture origin is the literal [`FIXTURE_KEY`]. The transport
//!   replaces whatever key the caller loaded, so a stored secret cannot leave the resident through
//!   it ([`FixtureProviderTransport`]).
//! - The Integrations page marks the provider as a fixture ([`is_fixture_provider`]).
//!
//! The manifest compiler refuses the prefix for anything under `contributions/`, so no shipped
//! manifest can claim the fixture route.

use std::collections::BTreeMap;

use guard_command::egress_caller::{policy_send, EgressPolicy};
use guard_contracts::PROVIDER_FIXTURE_ID_PREFIX;

use crate::client::{
    is_request_path, ProviderLimits, ProviderRequest, ProviderResponse, ProviderTransport,
};
use crate::ProviderClientError;

/// Read once by the resident at start, from its own process environment.
pub const FIXTURE_ORIGIN_ENV: &str = "HOL_GUARD_PROVIDER_FIXTURE_ORIGIN";

/// The one credential a fixture origin ever receives. Not a secret; the stub checks for it.
pub const FIXTURE_KEY: &str = "fixture-provider-key-not-a-secret";

/// Whether `provider_id` is under the reserved fixture prefix.
pub fn is_fixture_provider(provider_id: &str) -> bool {
    provider_id
        .strip_prefix(PROVIDER_FIXTURE_ID_PREFIX)
        .is_some_and(|rest| !rest.is_empty())
}

/// A validated `http://127.0.0.1:<port>` origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixtureOrigin {
    port: u16,
}

impl FixtureOrigin {
    /// Accept `http://127.0.0.1:<port>` with a port of 1 to 65535 written as plain digits, and
    /// nothing else: no other host, scheme, user info, path, query or trailing text.
    pub fn parse(value: &str) -> Option<Self> {
        let port = value.strip_prefix("http://127.0.0.1:")?;
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        match port.parse::<u16>() {
            Ok(0) | Err(_) => None,
            Ok(port) => Some(Self { port }),
        }
    }

    /// The origin from the resident's environment, when it is set and valid.
    pub fn from_env() -> Option<Self> {
        std::env::var(FIXTURE_ORIGIN_ENV)
            .ok()
            .and_then(|value| Self::parse(&value))
    }

    pub fn port(self) -> u16 {
        self.port
    }

    fn url(self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

/// Where a provider's requests go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRoute {
    /// The manifest's pinned HTTPS hosts, through the ordinary client.
    Pinned,
    /// The loopback fixture origin, with the fixture key only.
    Fixture(FixtureOrigin),
}

/// The route for `provider_id` given the fixture origin read at start. `None` means the provider
/// has nowhere to go: a fixture provider without a fixture origin.
pub fn route(provider_id: &str, fixture: Option<FixtureOrigin>) -> Option<ProviderRoute> {
    if !is_fixture_provider(provider_id) {
        return Some(ProviderRoute::Pinned);
    }
    fixture.map(ProviderRoute::Fixture)
}

/// The transport for a fixture provider. It sends to the loopback origin only and always with
/// [`FIXTURE_KEY`], whatever key the request carries.
pub struct FixtureProviderTransport<'a> {
    origin: FixtureOrigin,
    policy: &'a dyn EgressPolicy,
}

impl<'a> FixtureProviderTransport<'a> {
    /// A transport for `provider_id`, or `None` when the id is not a fixture id.
    pub fn new(
        provider_id: &str,
        origin: FixtureOrigin,
        policy: &'a dyn EgressPolicy,
    ) -> Option<Self> {
        is_fixture_provider(provider_id).then_some(Self { origin, policy })
    }
}

/// The headers a fixture request carries. Only the declared header name comes from the request;
/// its value is always [`FIXTURE_KEY`].
pub(crate) fn fixture_headers(request: &ProviderRequest) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    headers.insert("accept".to_owned(), "application/json".to_owned());
    if request.body.is_some() {
        headers.insert("content-type".to_owned(), "application/json".to_owned());
    }
    headers.insert(request.header.clone(), FIXTURE_KEY.to_owned());
    headers
}

impl ProviderTransport for FixtureProviderTransport<'_> {
    fn send(
        &self,
        request: &ProviderRequest,
        limits: ProviderLimits,
    ) -> Result<ProviderResponse, ProviderClientError> {
        if !is_request_path(&request.path) {
            return Err(ProviderClientError::PathInvalid);
        }
        let seconds = limits.timeout_ms as f64 / 1000.0;
        let (status, _, body) = policy_send(
            request.method.as_str(),
            &self.origin.url(&request.path),
            fixture_headers(request),
            request.body.clone(),
            seconds,
            0,
            limits.max_response_bytes,
            self.policy,
        )
        .map_err(|_| ProviderClientError::Transport)?;
        if (300..400).contains(&status) {
            return Err(ProviderClientError::Transport);
        }
        Ok(ProviderResponse { status, body })
    }
}

#[cfg(test)]
#[path = "fixture_origin_tests.rs"]
mod tests;
