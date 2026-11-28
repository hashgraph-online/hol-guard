//! Wire types for the provider integration daemon routes (`/v1/integrations/providers/...`).
//!
//! Secret-bearing requests deserialize only. They never implement `Serialize`, and their `Debug`
//! shows whether a key is present, never the key.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ProviderCapabilityV1, ProviderEffectLevelV1, ProviderShareableFactV1};

/// Manifest `schemaVersion` for provider integrations.
pub const PROVIDER_INTEGRATION_V1_SCHEMA: &str = "guard.provider-integration.v1";
/// Guard caps on manifest limits.
pub const PROVIDER_LIMIT_MAX_TIMEOUT_MS: u64 = 2_000;
pub const PROVIDER_LIMIT_MAX_RESPONSE_BYTES: u64 = 64 * 1024;
pub const PROVIDER_LIMIT_MAX_REQUESTS_PER_MINUTE: u32 = 60;
/// Longest key Guard accepts at connect, whatever the manifest declares.
pub const PROVIDER_KEY_MAX_BYTES: usize = 4_096;

/// Rollback switch: `off` turns every integration route into `provider_capability_unavailable`.
pub const PROVIDER_INTEGRATIONS_ENV: &str = "HOL_GUARD_PROVIDER_INTEGRATIONS";
/// Rollback switch: `legacy` restores the pre-change browser classification and grants.
pub const BROWSER_PROTECTION_ENV: &str = "HOL_GUARD_BROWSER_PROTECTION";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProviderConnectionStateV1 {
    NotConnected,
    Connected,
    KeyInvalid,
    Disabled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderAuthKindV1 {
    ApiKey,
    /// Reserved for adapters that enroll with a signed exchange.
    SignedEnrollment,
}

/// Route error codes, in the daemon's existing style.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProviderIntegrationErrorV1 {
    ProviderIntegrationUnavailable,
    ProviderKeyInvalid,
    ProviderHostRefused,
    ProviderRateLimited,
    ProviderResponseTooLarge,
    ProviderCapabilityUnavailable,
}

impl ProviderIntegrationErrorV1 {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProviderIntegrationUnavailable => "provider_integration_unavailable",
            Self::ProviderKeyInvalid => "provider_key_invalid",
            Self::ProviderHostRefused => "provider_host_refused",
            Self::ProviderRateLimited => "provider_rate_limited",
            Self::ProviderResponseTooLarge => "provider_response_too_large",
            Self::ProviderCapabilityUnavailable => "provider_capability_unavailable",
        }
    }
}

/// Per-capability settings. Protected: changed through preview plus one-use proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilitySettingsV1 {
    pub capability: ProviderCapabilityV1,
    pub effect: ProviderEffectLevelV1,
    pub require_fresh_check: bool,
    /// Reason codes the user chose to stop being asked about. Lowered to `observe`.
    pub quieted_reason_codes: Vec<String>,
}

/// One row of `GET /v1/integrations/providers`. No secret material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSummaryV1 {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub verified: bool,
    pub state: ProviderConnectionStateV1,
    pub capabilities: Vec<ProviderCapabilityV1>,
}

/// `GET /v1/integrations/providers/<id>`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderDetailV1 {
    pub summary: ProviderSummaryV1,
    /// Who publishes the manifest. `summary.verified` says whether HOL checked that claim.
    pub publisher_name: String,
    pub publisher_url: Option<String>,
    pub surfaces: Vec<String>,
    /// The only hosts Guard calls for this provider.
    pub hosts: Vec<String>,
    pub privacy_url: String,
    pub terms_url: String,
    /// Where a person gets a key. The dashboard adds a static referral parameter and nothing else.
    pub obtain_url: Option<String>,
    pub auth_kind: ProviderAuthKindV1,
    pub shares: Vec<ProviderShareableFactV1>,
    pub enabled_opt_in_facts: Vec<ProviderShareableFactV1>,
    pub settings: Vec<ProviderCapabilitySettingsV1>,
    pub last_verified_at_ms: Option<u64>,
    /// Cached signal count per capability id.
    pub cache_counts: BTreeMap<String, u64>,
    /// Digest of the stored settings and opt-in facts. A settings preview that names it is
    /// refused when the stored state has changed since this read.
    #[serde(default)]
    pub settings_baseline: String,
}

/// `POST .../connect/preview` response: the exact share set and a one-use proof challenge.
///
/// The challenge comes back as the connect request's proof, so `Debug` omits it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderConnectPreviewV1 {
    pub provider_id: String,
    pub shares: Vec<ProviderShareableFactV1>,
    pub opt_in_facts: Vec<ProviderShareableFactV1>,
    pub hosts: Vec<String>,
    pub challenge: String,
    pub expires_at_ms: u64,
}

impl std::fmt::Debug for ProviderConnectPreviewV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderConnectPreviewV1")
            .field("provider_id", &self.provider_id)
            .field("shares", &self.shares)
            .field("opt_in_facts", &self.opt_in_facts)
            .field("hosts", &self.hosts)
            .field("challenge", &!self.challenge.is_empty())
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// `POST .../connect` body. Holds the user's key, so it deserializes only.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderConnectRequestV1 {
    pub key: String,
    pub proof: String,
    #[serde(default)]
    pub enabled_opt_in_facts: Vec<ProviderShareableFactV1>,
}

impl std::fmt::Debug for ProviderConnectRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderConnectRequestV1")
            .field("key", &!self.key.is_empty())
            .field("proof", &!self.proof.is_empty())
            .field("enabled_opt_in_facts", &self.enabled_opt_in_facts)
            .finish()
    }
}

impl ProviderConnectRequestV1 {
    /// Rejects keys over [`PROVIDER_KEY_MAX_BYTES`] and keys with control characters before any
    /// manifest-specific format check.
    pub fn key_is_plausible(&self) -> bool {
        !self.key.is_empty()
            && self.key.len() <= PROVIDER_KEY_MAX_BYTES
            && !self.key.chars().any(char::is_control)
    }
}

/// `POST .../settings` body. Holds a one-use proof, so it deserializes only.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderSettingsRequestV1 {
    pub proof: String,
    pub settings: Vec<ProviderCapabilitySettingsV1>,
    pub enabled_opt_in_facts: Vec<ProviderShareableFactV1>,
}

impl std::fmt::Debug for ProviderSettingsRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderSettingsRequestV1")
            .field("proof", &!self.proof.is_empty())
            .field("settings", &self.settings)
            .field("enabled_opt_in_facts", &self.enabled_opt_in_facts)
            .finish()
    }
}

/// `POST .../disconnect` body. Deletes the stored key and the signal cache. Holds a one-use
/// proof, so it deserializes only.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderDisconnectRequestV1 {
    pub proof: String,
}

impl std::fmt::Debug for ProviderDisconnectRequestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderDisconnectRequestV1")
            .field("proof", &!self.proof.is_empty())
            .finish()
    }
}

/// `POST .../test` body: one live call for a public origin the user typed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderTestRequestV1 {
    pub capability: ProviderCapabilityV1,
    pub origin: String,
}
