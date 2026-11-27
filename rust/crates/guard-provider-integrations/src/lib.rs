#![forbid(unsafe_code)]
//! Browser provider integrations: the client side of a third-party signal provider (PRD 6.7).
//!
//! A provider is described by data, a compiled `guard.provider-integration.v1` manifest. This
//! crate owns the pieces that talk to one:
//!
//! - `client`: the HTTPS transport. One pinned host per request, HTTPS only, no redirects, a capped
//!   body and a wall-clock bound, through the managed network policy.
//! - `render`: a request body built from declared body fields and the shareable facts of one
//!   action, and nothing else.
//! - `parse`: strict JSON with duplicate keys refused, and bounded JSON pointer reads.
//! - `answer`: a response mapped onto the closed verdicts, declared reason codes and a clamped
//!   lifetime. Anything the manifest does not declare reads `unknown` or is dropped.
//! - `adapter`: the closed list of reviewed adapters for protocols data cannot express, and the
//!   bar a new one must meet. Empty in this phase.
//! - `noise`: the per-session caps that keep a provider from adding prompts (PRD 6.12).
//! - `overrides`: repeated allow-throughs of one provider reason, the offer to quiet it and undo.
//! - `compose`: several providers on one subject, one deciding row and the card order.
//! - `fixture_origin`: the loopback provider stub route for live runs on release builds, with the
//!   fixture key only.
//! - `testkit` (feature `testkit`): an in-memory provider for acceptance tests.
//!
//! Nothing here reads settings, stores a secret or decides an action. The resident worker is the
//! only caller, and the hook path never waits on a provider.

pub mod adapter;
pub mod answer;
pub mod client;
pub mod compose;
pub mod conformance;
pub mod conformance_fixtures;
pub mod fixture_origin;
pub mod noise;
pub mod overrides;
pub mod parse;
pub mod render;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

use std::fmt;

/// Why a provider exchange did not produce a response. Each variant has a stable
/// [`code`](Self::code); none carries provider text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderClientError {
    /// The host is not one the manifest pins, or is not a plain DNS name.
    HostNotPinned,
    /// The path is not a literal absolute path.
    PathInvalid,
    /// The credential header or key is not usable.
    CredentialInvalid,
    /// The managed network policy refused the destination.
    Blocked,
    /// The exchange ran past its deadline.
    Timeout,
    /// The response body was larger than the manifest allows.
    ResponseTooLarge,
    /// DNS, TLS, connect or read failed, or the provider answered with a redirect.
    Transport,
}

impl ProviderClientError {
    pub fn code(self) -> &'static str {
        match self {
            Self::HostNotPinned => "provider_host_not_pinned",
            Self::PathInvalid => "provider_path_invalid",
            Self::CredentialInvalid => "provider_credential_invalid",
            Self::Blocked => "provider_blocked_by_policy",
            Self::Timeout => "provider_timeout",
            Self::ResponseTooLarge => "provider_response_too_large",
            Self::Transport => "provider_transport_failed",
        }
    }
}

impl fmt::Display for ProviderClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ProviderClientError {}
