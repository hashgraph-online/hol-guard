//! Compiler for `guard.provider-integration.v1` manifests (PRD section 6.2).
//!
//! A provider integration is data: the hosts Guard may call, the one header the user's key goes in,
//! the closed facts each request carries and where each answer is read. The compiler enforces every
//! rule the JSON schema cannot:
//!
//! - `hosts` are exact public HTTPS host names: no wildcard, IP literal, port, local or reserved
//!   suffix, or shared-hosting domain. A request renders to `https://<host><path>` with a literal
//!   path, so no query string can carry a credential.
//! - `auth.kind` is the closed list; `api-key` is the only v1 kind a manifest may use. The key goes
//!   in exactly one declared header, never a header the HTTP client owns.
//! - Request bodies are built only from the closed fact set in `guard-contracts`. A body value is
//!   `{"fact": ...}` and nothing else: no literal, template or user-supplied value.
//! - `shares` must equal the facts the request uses, because the connect dialog renders from it.
//! - Responses are read through JSON pointers. Verdicts map onto Guard's closed verdicts and
//!   reason-code labels must be safe plain text.
//! - Limits are capped by Guard.
//!
//! Duplicate JSON keys are refused at every level. A compiled manifest is inert until the user
//! connects it, and nothing in it can lower a Guard decision.

use std::collections::{BTreeMap, BTreeSet};

use guard_contracts::{
    provider_id_is_valid, provider_reason_code_is_valid, ProviderCapabilityV1,
    ProviderShareableFactV1, ProviderVerdictV1, PROVIDER_FIXTURE_ID_PREFIX,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[path = "provider_integration_compile_error.rs"]
mod error;
#[path = "provider_integration_compile_raw.rs"]
mod raw;
#[path = "provider_integration_compile_text.rs"]
mod text;
#[path = "provider_integration_compile_types.rs"]
mod types;

pub use error::ProviderIntegrationCompileError;
use raw::{RawCapability, RawManifest, RawRequest, RawResponse};
pub use types::*;

/// The only accepted `schemaVersion`.
pub const PROVIDER_INTEGRATION_SCHEMA_VERSION: &str = "guard.provider-integration.v1";
/// Largest accepted manifest, in bytes.
pub const PROVIDER_INTEGRATION_MAX_BYTES: usize = 64 * 1024;
/// Guard's cap on a provider request timeout.
pub const PROVIDER_TIMEOUT_MAX_MS: u64 = 2_000;
/// Guard's cap on a provider response body.
pub const PROVIDER_RESPONSE_MAX_BYTES: u64 = 64 * 1024;
/// Guard's cap on requests to one provider per minute.
pub const PROVIDER_REQUESTS_PER_MINUTE_MAX: u64 = 60;
/// Bounds on how long a provider answer may be cached.
pub const PROVIDER_TTL_MIN_SECONDS: u64 = 60;
pub const PROVIDER_TTL_MAX_SECONDS: u64 = 86_400;

const SURFACES: &[&str] = &["browser"];
const KEY_LENGTH_MIN: u32 = 16;
const KEY_LENGTH_MAX: u32 = 512;
const MAX_HOSTS: usize = 4;
const MAX_BODY_FIELDS: usize = 16;
const MAX_VERDICT_VALUES: usize = 16;
const MAX_REASON_CODES: usize = 32;
const MAX_NAME_CHARS: usize = 60;
const MAX_SUMMARY_CHARS: usize = 200;
const MAX_LABEL_CHARS: usize = 80;

type CompileResult<T> = Result<T, ProviderIntegrationCompileError>;
use ProviderIntegrationCompileError as E;

/// Compile one manifest. `verified_providers` is the maintainer-owned list of provider ids whose
/// `publisher.verified` claim is honoured.
pub fn compile_provider_integration(
    bytes: &[u8],
    verified_providers: &[&str],
) -> CompileResult<CompiledProviderIntegrationV1> {
    if bytes.is_empty() || bytes.len() > PROVIDER_INTEGRATION_MAX_BYTES {
        return Err(E::SourceBytesInvalid);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let manifest = RawManifest::deserialize(&mut decoder).map_err(|_| E::JsonInvalid)?;
    decoder.end().map_err(|_| E::JsonInvalid)?;
    let mut compiled = compile_manifest(manifest, verified_providers)?;
    compiled.manifest_digest = hex::encode(Sha256::digest(bytes));
    Ok(compiled)
}

/// Compile a set of manifests and refuse two with the same id.
pub fn compile_provider_integration_set(
    sources: &[&[u8]],
    verified_providers: &[&str],
) -> CompileResult<Vec<CompiledProviderIntegrationV1>> {
    let mut ids = BTreeSet::new();
    let mut compiled = Vec::with_capacity(sources.len());
    for bytes in sources {
        let manifest = compile_provider_integration(bytes, verified_providers)?;
        if !ids.insert(manifest.id.clone()) {
            return Err(E::ProviderIdDuplicate);
        }
        compiled.push(manifest);
    }
    Ok(compiled)
}

/// Compile the manifests shipped under `contributions/provider-integrations/`. On top of the set
/// rules, a contributed manifest may not use the id prefix reserved for the loopback fixture
/// origin, so no shipped provider can ever be routed to it.
pub fn compile_contributed_provider_integration_set(
    sources: &[&[u8]],
    verified_providers: &[&str],
) -> CompileResult<Vec<CompiledProviderIntegrationV1>> {
    let compiled = compile_provider_integration_set(sources, verified_providers)?;
    if compiled
        .iter()
        .any(|manifest| manifest.id.starts_with(PROVIDER_FIXTURE_ID_PREFIX))
    {
        return Err(E::FixtureIdContributed);
    }
    Ok(compiled)
}

fn compile_manifest(
    manifest: RawManifest,
    verified_providers: &[&str],
) -> CompileResult<CompiledProviderIntegrationV1> {
    if manifest.schema_version != PROVIDER_INTEGRATION_SCHEMA_VERSION {
        return Err(E::SchemaVersionUnsupported);
    }
    if !provider_id_is_valid(&manifest.id) {
        return Err(E::IdInvalid);
    }
    if !text::is_display_text(&manifest.name, MAX_NAME_CHARS) {
        return Err(E::NameInvalid);
    }
    if !text::is_display_text(&manifest.summary, MAX_SUMMARY_CHARS) {
        return Err(E::SummaryInvalid);
    }
    let publisher = manifest.publisher;
    if !text::is_display_text(&publisher.name, MAX_NAME_CHARS)
        || publisher
            .url
            .as_deref()
            .is_some_and(|url| !text::is_https_url(url))
    {
        return Err(E::PublisherInvalid);
    }
    if publisher.verified && !verified_providers.contains(&manifest.id.as_str()) {
        return Err(E::PublisherVerificationUnproven);
    }
    let surfaces = compile_surfaces(manifest.surfaces)?;
    let auth = compile_auth(&manifest.auth)?;
    let obtain_url = manifest.auth.obtain_url;
    if obtain_url
        .as_deref()
        .is_some_and(|url| !text::is_https_url(url))
    {
        return Err(E::PolicyUrlInvalid);
    }
    let hosts = compile_hosts(manifest.hosts)?;
    let capabilities = compile_capabilities(&manifest.capabilities, &hosts)?;
    let verify = manifest
        .verify
        .as_ref()
        .map(|request| {
            if request.body.is_some() {
                return Err(E::VerifyInvalid);
            }
            compile_request(request, &hosts)
        })
        .transpose()?;
    let limits = compile_limits(&manifest.limits)?;
    if !text::is_https_url(&manifest.privacy_url) || !text::is_https_url(&manifest.terms_url) {
        return Err(E::PolicyUrlInvalid);
    }
    if manifest
        .icon
        .as_deref()
        .is_some_and(|icon| !text::is_icon(icon))
    {
        return Err(E::IconInvalid);
    }
    Ok(CompiledProviderIntegrationV1 {
        id: manifest.id,
        name: manifest.name,
        summary: manifest.summary,
        publisher_name: publisher.name,
        publisher_url: publisher.url,
        verified: publisher.verified,
        surfaces,
        auth,
        obtain_url,
        hosts,
        capabilities,
        verify,
        limits,
        privacy_url: manifest.privacy_url,
        terms_url: manifest.terms_url,
        icon: manifest.icon,
        manifest_digest: String::new(),
    })
}

/// Read `value` as one entry of a closed serde enum.
fn closed<T: DeserializeOwned>(value: &str) -> Option<T> {
    serde_json::from_value(Value::String(value.to_owned())).ok()
}

fn compile_surfaces(surfaces: Vec<String>) -> CompileResult<Vec<String>> {
    let unique: BTreeSet<&str> = surfaces.iter().map(String::as_str).collect();
    if surfaces.is_empty()
        || unique.len() != surfaces.len()
        || !unique.iter().all(|surface| SURFACES.contains(surface))
    {
        return Err(E::SurfacesInvalid);
    }
    Ok(surfaces)
}

fn compile_auth(auth: &raw::RawAuth) -> CompileResult<CompiledProviderAuthV1> {
    match auth.kind.as_str() {
        "api-key" => {}
        "signed-enrollment" => return Err(E::AuthKindReserved),
        _ => return Err(E::AuthKindUnsupported),
    }
    if !text::is_credential_header(&auth.header) {
        return Err(E::AuthHeaderInvalid);
    }
    let format = &auth.key_format;
    let charset = closed::<ProviderKeyCharsetV1>(&format.charset).ok_or(E::KeyFormatInvalid)?;
    if format.min_length < KEY_LENGTH_MIN
        || format.max_length > KEY_LENGTH_MAX
        || format.min_length > format.max_length
    {
        return Err(E::KeyFormatInvalid);
    }
    Ok(CompiledProviderAuthV1 {
        header: auth.header.clone(),
        key_min_length: format.min_length,
        key_max_length: format.max_length,
        key_charset: charset,
    })
}

fn compile_hosts(hosts: Vec<String>) -> CompileResult<Vec<String>> {
    let unique: BTreeSet<&str> = hosts.iter().map(String::as_str).collect();
    if hosts.is_empty() || hosts.len() > MAX_HOSTS || unique.len() != hosts.len() {
        return Err(E::HostsInvalid);
    }
    if !hosts.iter().all(|host| text::is_endpoint_host(host)) {
        return Err(E::HostInvalid);
    }
    Ok(hosts)
}

fn compile_capabilities(
    capabilities: &[RawCapability],
    hosts: &[String],
) -> CompileResult<Vec<CompiledProviderCapabilityV1>> {
    if capabilities.is_empty() || capabilities.len() > ProviderCapabilityV1::ALL.len() {
        return Err(E::CapabilitiesInvalid);
    }
    let mut seen = BTreeSet::new();
    let mut compiled = Vec::with_capacity(capabilities.len());
    for raw in capabilities {
        let capability = closed::<ProviderCapabilityV1>(&raw.id).ok_or(E::CapabilityUnknown)?;
        if !seen.insert(capability) {
            return Err(E::CapabilityDuplicate);
        }
        let request = compile_request(&raw.request, hosts)?;
        if request.method != ProviderHttpMethodV1::Post || request.body.is_empty() {
            return Err(E::RequestBodyInvalid);
        }
        let used: BTreeSet<ProviderShareableFactV1> =
            request.body.iter().map(|(_, fact)| *fact).collect();
        let mut shares = BTreeSet::new();
        for fact in &raw.shares {
            let fact = closed::<ProviderShareableFactV1>(fact).ok_or(E::FactUnknown)?;
            if !shares.insert(fact) {
                return Err(E::SharesMismatch);
            }
        }
        if shares != used {
            return Err(E::SharesMismatch);
        }
        let (verdict_pointer, verdict_map, reason_codes, ttl) = compile_response(&raw.response)?;
        compiled.push(CompiledProviderCapabilityV1 {
            capability,
            request,
            verdict_pointer,
            verdict_map,
            reason_codes,
            ttl,
            shares,
        });
    }
    Ok(compiled)
}

fn compile_request(
    request: &RawRequest,
    hosts: &[String],
) -> CompileResult<CompiledProviderRequestV1> {
    let method = closed::<ProviderHttpMethodV1>(&request.method).ok_or(E::RequestMethodInvalid)?;
    let host = match (&request.host, hosts) {
        (Some(host), _) if hosts.contains(host) => host.clone(),
        (Some(_), _) => return Err(E::RequestHostInvalid),
        (None, [only]) => only.clone(),
        (None, _) => return Err(E::RequestHostInvalid),
    };
    if !text::is_request_path(&request.path) {
        return Err(E::RequestPathInvalid);
    }
    let mut body = Vec::new();
    if let Some(fields) = &request.body {
        if method == ProviderHttpMethodV1::Get || fields.len() > MAX_BODY_FIELDS {
            return Err(E::RequestBodyInvalid);
        }
        for (field, value) in fields.iter() {
            if !text::is_body_field(field) {
                return Err(E::RequestBodyInvalid);
            }
            let fact = closed::<ProviderShareableFactV1>(&value.fact).ok_or(E::FactUnknown)?;
            body.push((field.clone(), fact));
        }
    }
    Ok(CompiledProviderRequestV1 {
        method,
        host,
        path: request.path.clone(),
        body,
    })
}

type CompiledResponse = (
    String,
    BTreeMap<String, ProviderVerdictV1>,
    Option<CompiledProviderReasonCodesV1>,
    Option<CompiledProviderTtlV1>,
);

fn compile_response(response: &RawResponse) -> CompileResult<CompiledResponse> {
    let verdict = &response.verdict;
    if !text::is_json_pointer(&verdict.pointer) {
        return Err(E::ResponsePointerInvalid);
    }
    if verdict.map.is_empty() || verdict.map.len() > MAX_VERDICT_VALUES {
        return Err(E::VerdictMapInvalid);
    }
    let mut verdict_map = BTreeMap::new();
    for (value, mapped) in verdict.map.iter() {
        if !text::is_provider_token(value) {
            return Err(E::VerdictMapInvalid);
        }
        let mapped = closed::<ProviderVerdictV1>(mapped).ok_or(E::VerdictMapInvalid)?;
        verdict_map.insert(value.clone(), mapped);
    }
    let reason_codes = response
        .reason_codes
        .as_ref()
        .map(compile_reason_codes)
        .transpose()?;
    let ttl = response
        .ttl_seconds
        .as_ref()
        .map(|ttl| {
            if !text::is_json_pointer(&ttl.pointer) {
                return Err(E::ResponsePointerInvalid);
            }
            if ttl.min < PROVIDER_TTL_MIN_SECONDS
                || ttl.max > PROVIDER_TTL_MAX_SECONDS
                || ttl.min > ttl.max
            {
                return Err(E::TtlInvalid);
            }
            Ok(CompiledProviderTtlV1 {
                pointer: ttl.pointer.clone(),
                min_seconds: ttl.min,
                max_seconds: ttl.max,
            })
        })
        .transpose()?;
    Ok((verdict.pointer.clone(), verdict_map, reason_codes, ttl))
}

fn compile_reason_codes(
    codes: &raw::RawReasonCodes,
) -> CompileResult<CompiledProviderReasonCodesV1> {
    if !text::is_json_pointer(&codes.pointer) {
        return Err(E::ResponsePointerInvalid);
    }
    let unique: BTreeSet<&str> = codes.allow.iter().map(String::as_str).collect();
    if codes.allow.is_empty()
        || codes.allow.len() > MAX_REASON_CODES
        || unique.len() != codes.allow.len()
        || !codes
            .allow
            .iter()
            .all(|code| provider_reason_code_is_valid(code))
    {
        return Err(E::ReasonCodesInvalid);
    }
    let mut labels = BTreeMap::new();
    if let Some(declared) = &codes.labels {
        for (code, label) in declared.iter() {
            if !unique.contains(code.as_str()) || !text::is_safe_label(label, MAX_LABEL_CHARS) {
                return Err(E::ReasonLabelInvalid);
            }
            labels.insert(code.clone(), label.clone());
        }
    }
    Ok(CompiledProviderReasonCodesV1 {
        pointer: codes.pointer.clone(),
        allow: codes.allow.clone(),
        labels,
    })
}

fn compile_limits(limits: &raw::RawLimits) -> CompileResult<CompiledProviderLimitsV1> {
    if !(1..=PROVIDER_TIMEOUT_MAX_MS).contains(&limits.timeout_ms)
        || !(1..=PROVIDER_RESPONSE_MAX_BYTES).contains(&limits.max_response_bytes)
        || !(1..=PROVIDER_REQUESTS_PER_MINUTE_MAX).contains(&limits.max_requests_per_minute)
    {
        return Err(E::LimitsInvalid);
    }
    Ok(CompiledProviderLimitsV1 {
        timeout_ms: limits.timeout_ms,
        max_response_bytes: limits.max_response_bytes,
        max_requests_per_minute: limits.max_requests_per_minute,
    })
}

#[cfg(test)]
#[path = "provider_integration_compile_request_tests.rs"]
mod request_tests;
#[cfg(test)]
#[path = "provider_integration_compile_tests.rs"]
mod tests;
