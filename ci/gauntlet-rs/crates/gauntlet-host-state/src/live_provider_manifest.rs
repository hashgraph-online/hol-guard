//! Inert check of the Python/MLX provider handoff. The manifest's signing key
//! is self-declared, so this proves internal consistency and outside digest/
//! candidate binding, not independent provider provenance or execution.

use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_contracts::canonicalize;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const MODEL_ID: &str = "mlx-community/Qwen3.6-35B-A3B-8bit";

pub struct LiveProviderManifestExpectation<'a> {
    pub provider_sha256: &'a str,
    pub model_sha256: &'a str,
    pub job_id: &'a str,
    pub profile: &'a str,
    pub candidate_source_sha: &'a str,
    pub known_tokens_before: u64,
}

fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parsed(raw: &[u8], expected_digest: &str) -> Result<Value, &'static str> {
    if raw.is_empty()
        || raw.len() > MAX_MANIFEST_BYTES
        || !lower_hex(expected_digest, 64)
        || digest(raw) != expected_digest
    {
        return Err("provider handoff manifest bytes differ from outside pin");
    }
    let canonical = canonicalize(raw).map_err(|_| "provider handoff manifest JSON invalid")?;
    serde_json::from_slice(&canonical).map_err(|_| "provider handoff manifest JSON invalid")
}

fn canonical_value(value: &Value) -> Result<Vec<u8>, &'static str> {
    let raw = serde_json::to_vec(value).map_err(|_| "provider handoff record JSON invalid")?;
    canonicalize(&raw).map_err(|_| "provider handoff record JSON invalid")
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, &'static str> {
    value
        .get(name)
        .ok_or("provider handoff required field absent")
}

fn string<'a>(value: &'a Value, name: &str) -> Result<&'a str, &'static str> {
    field(value, name)?
        .as_str()
        .ok_or("provider handoff text field invalid")
}

fn natural(value: &Value, name: &str) -> Result<u64, &'static str> {
    field(value, name)?
        .as_u64()
        .ok_or("provider handoff count invalid")
}

/// Read already-captured, outside-SHA-pinned bytes only. Callers must separately
/// prove the host file custody, process identity, retained allowance authority and
/// live quota journal before this claim can inform a run.
pub fn verify_live_provider_manifest_claim(
    provider_raw: &[u8],
    model_raw: &[u8],
    expected: &LiveProviderManifestExpectation<'_>,
) -> Result<Value, &'static str> {
    if !lower_hex(expected.job_id, 16)
        || !lower_hex(expected.candidate_source_sha, 40)
        || !matches!(
            expected.profile,
            "beta-e2e" | "feature-ai" | "feature-ai-protocol"
        )
    {
        return Err("fixed provider handoff job, profile and source required");
    }
    let provider = parsed(provider_raw, expected.provider_sha256)?;
    let model = parsed(model_raw, expected.model_sha256)?;
    let provider_object = provider
        .as_object()
        .ok_or("provider handoff envelope invalid")?;
    if provider_object.len() != 3
        || !["anchor", "binding", "signed_result"]
            .iter()
            .all(|name| provider_object.contains_key(*name))
    {
        return Err("provider handoff envelope invalid");
    }
    let anchor = field(&provider, "anchor")?;
    let binding = field(&provider, "binding")?;
    let signed = field(&provider, "signed_result")?;
    let record = field(signed, "record")?;
    if anchor.get("qualification") != Some(&Value::Bool(false))
        || record.get("qualification") != Some(&Value::Bool(false))
        || record.get("started") != Some(&Value::Bool(true))
    {
        return Err("fresh unqualified provider startup required");
    }
    let key = STANDARD
        .decode(string(anchor, "public_key")?)
        .map_err(|_| "provider handoff public key invalid")?;
    let signature = STANDARD
        .decode(string(signed, "signature")?)
        .map_err(|_| "provider handoff signature invalid")?;
    if key.len() != 32 || signature.len() != 64 {
        return Err("provider handoff signing lengths invalid");
    }
    UnparsedPublicKey::new(&ED25519, &key)
        .verify(&canonical_value(record)?, &signature)
        .map_err(|_| "provider handoff signature mismatch")?;

    let binding_sha256 = string(record, "binding_sha256")?;
    let mut binding_bytes = canonical_value(binding)?;
    binding_bytes.push(b'\n');
    let status = field(record, "quota_before_any_control")?;
    if !lower_hex(binding_sha256, 64)
        || binding_sha256 != digest(&binding_bytes)
        || string(status, "binding_sha256")? != binding_sha256
        || string(record, "job_id")? != expected.job_id
        || string(record, "profile")? != expected.profile
        || string(record, "candidate_source_sha")? != expected.candidate_source_sha
        || string(binding, "job_id")? != expected.job_id
        || string(binding, "profile")? != expected.profile
        || string(binding, "candidate_source_sha")? != expected.candidate_source_sha
    {
        return Err("provider handoff differs from requested candidate and binding");
    }
    let config_sha256 = string(anchor, "config_sha256")?;
    if !lower_hex(config_sha256, 64) || string(record, "config_sha256")? != config_sha256 {
        return Err("provider handoff config identity differs");
    }
    let quota = field(status, "quota")?;
    if natural(quota, "pending_requests")? != 0
        || natural(quota, "reserved_tokens")? != 0
        || natural(quota, "known_tokens")? != expected.known_tokens_before
        || natural(binding, "maximum_accounted_tokens")? > natural(binding, "lifetime_token_cap")?
    {
        return Err("provider handoff quota differs from outside observation");
    }
    let loaded = field(record, "loaded")?;
    if loaded != field(&model, "loaded")?
        || field(&model, "model_identity")? != field(binding, "model_identity")?
        || field(&model, "model_identity_digest")? != field(binding, "model_identity_digest")?
        || string(loaded, "model_id")? != MODEL_ID
        || loaded.get("weights_verified_before_and_after_load") != Some(&Value::Bool(true))
    {
        return Err("provider handoff model identity differs");
    }
    Ok(json!({
        "schema":"hol-gauntlet-live-provider-manifest-claim.v1",
        "job_id":expected.job_id,
        "profile":expected.profile,
        "candidate_source_sha":expected.candidate_source_sha,
        "binding_sha256":binding_sha256,
        "provider_sha256":expected.provider_sha256,
        "model_sha256":expected.model_sha256,
        "known_tokens_before":expected.known_tokens_before,
        "self_declared_signature_valid":true,
        "producer_claim_only":true,
        "execution_eligible":false,
    }))
}
