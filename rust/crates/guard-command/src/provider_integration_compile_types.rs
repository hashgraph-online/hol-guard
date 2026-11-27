//! Compiled `guard.provider-integration.v1` shapes. Every value here passed the compiler rules in
//! the parent module.

use std::collections::{BTreeMap, BTreeSet};

use guard_contracts::{ProviderCapabilityV1, ProviderShareableFactV1, ProviderVerdictV1};
use serde::Deserialize;

/// Characters a provider key is made of. The connect dialog checks a pasted key against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKeyCharsetV1 {
    Base64url,
    Base64,
    Hex,
    Alphanumeric,
}

/// HTTP methods a provider request may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum ProviderHttpMethodV1 {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "POST")]
    Post,
}

/// Where the user's key goes and what it must look like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProviderAuthV1 {
    pub header: String,
    pub key_min_length: u32,
    pub key_max_length: u32,
    pub key_charset: ProviderKeyCharsetV1,
}

/// One request: a literal path on a declared host and a body built only from facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProviderRequestV1 {
    pub method: ProviderHttpMethodV1,
    pub host: String,
    pub path: String,
    pub body: Vec<(String, ProviderShareableFactV1)>,
}

impl CompiledProviderRequestV1 {
    /// The absolute URL the request is sent to.
    pub fn url(&self) -> String {
        format!("https://{}{}", self.host, self.path)
    }
}

/// Where reason codes are read, which ones are kept and how each is labelled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProviderReasonCodesV1 {
    pub pointer: String,
    pub allow: Vec<String>,
    pub labels: BTreeMap<String, String>,
}

/// Where the answer's lifetime is read and the bounds it is clamped to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProviderTtlV1 {
    pub pointer: String,
    pub min_seconds: u64,
    pub max_seconds: u64,
}

/// One capability the provider answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProviderCapabilityV1 {
    pub capability: ProviderCapabilityV1,
    pub request: CompiledProviderRequestV1,
    pub verdict_pointer: String,
    /// Provider verdict values onto Guard verdicts. Any other value reads as `unknown`.
    pub verdict_map: BTreeMap<String, ProviderVerdictV1>,
    pub reason_codes: Option<CompiledProviderReasonCodesV1>,
    pub ttl: Option<CompiledProviderTtlV1>,
    /// Exactly the facts the request carries.
    pub shares: BTreeSet<ProviderShareableFactV1>,
}

/// Guard-capped limits for one provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompiledProviderLimitsV1 {
    pub timeout_ms: u64,
    pub max_response_bytes: u64,
    pub max_requests_per_minute: u64,
}

/// A manifest that passed every compiler rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProviderIntegrationV1 {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub publisher_name: String,
    pub publisher_url: Option<String>,
    pub verified: bool,
    pub surfaces: Vec<String>,
    pub auth: CompiledProviderAuthV1,
    pub obtain_url: Option<String>,
    pub hosts: Vec<String>,
    pub capabilities: Vec<CompiledProviderCapabilityV1>,
    pub verify: Option<CompiledProviderRequestV1>,
    pub limits: CompiledProviderLimitsV1,
    pub privacy_url: String,
    pub terms_url: String,
    pub icon: Option<String>,
}
