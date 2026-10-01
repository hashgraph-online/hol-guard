//! Native approval-context digest authority.
//!
//! Saved approvals are bound to an opaque context token built from five
//! component digests, and to domain-separated configured environment/header
//! digests. Computing those digests is authoritative work: this module owns
//! the canonical serialization and hashing so Python callers transport raw
//! components and project the typed result, never a Python-built hash, into
//! approval evidence.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::context_digest_json::{
    write_canonical_json, write_canonical_json_with_limit, write_json_string,
};
use guard_contracts::{
    ContextDigestComponentsV1, ContextDigestKindV1, ContextDigestRequestV1, ContextDigestResultV1,
    APPROVAL_CONTEXT_TOKEN_PREFIX, CONTEXT_DIGEST_REQUEST_SCHEMA, CONTEXT_DIGEST_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;

const TOKEN_VERSION: u64 = 1;
const TOKEN_DOMAIN: &str = "hol.guard.approval-context";
const CONFIGURED_ENV_HASH_DOMAIN: &[u8] = b"hol.guard.configured-environment:v1\0";
const CONFIGURED_HEADER_HASH_DOMAIN: &[u8] = b"hol.guard.configured-headers:v1\0";
const TOKEN_HASH_FIELDS: [&str; 5] = ["identity", "content", "capabilities", "policy", "sandbox"];

pub(super) const ERR_COMPONENT: &str = "native_context_component_invalid";
const ERR_VALUES: &str = "native_context_values_invalid";

fn component_hash(component: &str, value: &Value) -> Result<String, &'static str> {
    // {"component": ..., "domain": ..., "value": ..., "version": 1}
    // Wrapper keys are already in sorted order for the canonical writer.
    let mut material = Vec::with_capacity(128);
    material.push(b'{');
    write_json_string("component", &mut material);
    material.push(b':');
    write_json_string(component, &mut material);
    material.push(b',');
    write_json_string("domain", &mut material);
    material.push(b':');
    write_json_string(TOKEN_DOMAIN, &mut material);
    material.push(b',');
    write_json_string("value", &mut material);
    material.push(b':');
    write_canonical_json(value, &mut material)?;
    material.push(b',');
    write_json_string("version", &mut material);
    material.push(b':');
    material.push(b'1');
    material.push(b'}');
    Ok(digest_bytes(&material))
}

fn base64_url_no_pad(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len() * 4 / 3 + 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let block = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(block >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(block >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(block >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[block as usize & 0x3f] as char);
        }
    }
    out
}

fn base64_url_decode(encoded: &str) -> Option<Vec<u8>> {
    fn nibble(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a' + 26) as u32),
            b'0'..=b'9' => Some((byte - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = encoded.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let v0 = nibble(chunk[0])?;
        let v1 = nibble(chunk[1])?;
        out.push(((v0 << 2) | (v1 >> 4)) as u8);
        if chunk.len() > 2 {
            let v2 = nibble(chunk[2])?;
            out.push((((v1 & 0x0f) << 4) | (v2 >> 2)) as u8);
            if chunk.len() > 3 {
                let v3 = nibble(chunk[3])?;
                out.push((((v2 & 0x03) << 6) | v3) as u8);
            }
        }
    }
    Some(out)
}

/// Parsed non-secret approval-context component digests.
struct ParsedContextToken {
    identity: String,
    content: String,
    capabilities: String,
    policy: String,
    sandbox: String,
}

fn is_sha256_hex(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    if text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Some(text.to_owned())
    } else {
        None
    }
}

fn parse_context_token(token: &Value) -> Option<ParsedContextToken> {
    let text = token.as_str()?;
    let encoded = text.strip_prefix(APPROVAL_CONTEXT_TOKEN_PREFIX)?;
    if text.len() > guard_contracts::APPROVAL_CONTEXT_TOKEN_MAX_BYTES
        || encoded.is_empty()
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let raw = base64_url_decode(encoded)?;
    let payload_text = std::str::from_utf8(&raw).ok()?;
    let payload: Value = serde_json::from_str(payload_text).ok()?;
    let object = payload.as_object()?;
    if object.len() != 6 {
        return None;
    }
    // Python compares `payload.get("version") != 1` numerically: JSON 1.0
    // passes (`1.0 == 1`) and `true` also passes (`True == 1`).
    match object.get("version") {
        Some(Value::Bool(true)) => {}
        Some(other) if other.as_f64() == Some(TOKEN_VERSION as f64) => {}
        _ => return None,
    }
    let mut parsed: [Option<String>; 5] = std::array::from_fn(|_| None);
    for (index, field) in TOKEN_HASH_FIELDS.iter().enumerate() {
        parsed[index] = Some(is_sha256_hex(object.get(*field)?)?);
    }
    let [identity, content, capabilities, policy, sandbox] = parsed;
    Some(ParsedContextToken {
        identity: identity?,
        content: content?,
        capabilities: capabilities?,
        policy: policy?,
        sandbox: sandbox?,
    })
}

fn build_context_token(components: &ContextDigestComponentsV1) -> Result<String, &'static str> {
    let policy_wrapped = {
        let mut wrapped = Map::with_capacity(2);
        wrapped.insert(
            "extension_control_digest".to_owned(),
            Value::String(components.extension_control_digest.clone()),
        );
        wrapped.insert("policy".to_owned(), components.policy.clone());
        Value::Object(wrapped)
    };
    let digests = [
        component_hash("identity", &components.identity)?,
        component_hash("content", &components.content)?,
        component_hash("capabilities", &components.capabilities)?,
        component_hash("policy", &policy_wrapped)?,
        component_hash("sandbox", &components.sandbox)?,
    ];
    // Payload keys emitted in sorted order: capabilities, content, identity,
    // policy, sandbox, version.
    let mut payload = Vec::with_capacity(512);
    payload.push(b'{');
    for (index, (key, digest)) in [
        ("capabilities", &digests[2]),
        ("content", &digests[1]),
        ("identity", &digests[0]),
        ("policy", &digests[3]),
        ("sandbox", &digests[4]),
    ]
    .iter()
    .enumerate()
    {
        if index > 0 {
            payload.push(b',');
        }
        write_json_string(key, &mut payload);
        payload.push(b':');
        write_json_string(digest, &mut payload);
    }
    payload.extend_from_slice(b",\"version\":1}");
    Ok(format!(
        "{APPROVAL_CONTEXT_TOKEN_PREFIX}{}",
        base64_url_no_pad(&payload)
    ))
}

/// First-difference validation over two opaque tokens; malformed input fails
/// closed as changed content, matching the legacy contract exactly.
fn validate_context_tokens(saved: &Value, current: &Value) -> Option<String> {
    let saved = parse_context_token(saved);
    let current = parse_context_token(current);
    let (Some(saved), Some(current)) = (saved, current) else {
        return Some("approval_reuse_content_changed".to_owned());
    };
    let comparisons = [
        (
            saved.identity,
            current.identity,
            "approval_reuse_identity_changed",
        ),
        (
            saved.content,
            current.content,
            "approval_reuse_content_changed",
        ),
        (
            saved.capabilities,
            current.capabilities,
            "approval_reuse_capability_changed",
        ),
        (
            saved.policy,
            current.policy,
            "approval_reuse_policy_changed",
        ),
        (
            saved.sandbox,
            current.sandbox,
            "approval_reuse_sandbox_changed",
        ),
    ];
    for (left, right, reason) in comparisons {
        if !crate::constant_time_eq(left.as_bytes(), right.as_bytes()) {
            return Some(reason.to_owned());
        }
    }
    None
}

/// CPython `str.strip()` whitespace set: the ASCII controls 0x09-0x0d and
/// 0x1c-0x1f plus every Unicode code point whose `isspace` is true.
fn is_python_space(ch: char) -> bool {
    matches!(
        ch,
        '\u{09}'..='\u{0d}'
            | ' '
            | '\u{1c}'..='\u{1f}'
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'..='\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn python_strip(text: &str) -> &str {
    text.trim_matches(|ch: char| is_python_space(ch))
}

fn configured_values_hash(
    values: Option<&Value>,
    configured_keys: Option<&[String]>,
    domain: &[u8],
) -> Result<String, &'static str> {
    // Python evaluates `(values or {})`: every JSON-falsy input normalizes to
    // an empty mapping, while truthy non-mappings fail on `.items()`.
    //
    // Mappings arrive as ordered `["key", value]` pairs: distinct raw keys can
    // collide after whitespace stripping, and the legacy dict comprehension
    // resolves the collision by the last pair in caller iteration order. A
    // plain JSON object cannot transport that order, so objects are rejected
    // rather than silently reordering a caller's inputs.
    let mut normalized: Map<String, Value> = Map::new();
    match values {
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(Value::Number(number)) if number.as_f64() == Some(0.0) => {}
        Some(Value::String(text)) if text.is_empty() => {}
        Some(Value::Array(items)) => {
            for item in items {
                let pair = item.as_array().ok_or(ERR_VALUES)?;
                let (Some(raw_key), Some(entry)) = (pair.first(), pair.get(1)) else {
                    return Err(ERR_VALUES);
                };
                let raw_key = raw_key.as_str().ok_or(ERR_VALUES)?;
                if pair.len() != 2 {
                    return Err(ERR_VALUES);
                }
                let stripped = python_strip(raw_key);
                if stripped.is_empty() {
                    continue;
                }
                normalized.insert(stripped.to_owned(), entry.clone());
            }
        }
        Some(_) => return Err(ERR_VALUES),
    }
    let mut keys: Vec<String> = match configured_keys {
        None => normalized.keys().cloned().collect(),
        Some(configured) => configured
            .iter()
            .map(|key| python_strip(key).to_owned())
            .filter(|key| !key.is_empty())
            .collect(),
    };
    keys.sort();
    keys.dedup();

    let mut hasher = Sha256::new();
    hasher.update(domain);
    for key in keys {
        let key_bytes = key.as_bytes();
        hasher.update((key_bytes.len() as u64).to_be_bytes());
        hasher.update(key_bytes);
        match normalized.get(&key) {
            None => hasher.update([0x00]),
            Some(Value::String(text)) => {
                hasher.update([0x01]);
                let value_bytes = text.as_bytes();
                hasher.update((value_bytes.len() as u64).to_be_bytes());
                hasher.update(value_bytes);
            }
            // Python raises AttributeError on non-str values; the native op
            // surfaces the same boundary as a typed failure.
            Some(_) => return Err(ERR_VALUES),
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

fn evaluate_request(
    request: &ContextDigestRequestV1,
    result: &mut ContextDigestResultV1,
) -> Result<(), &'static str> {
    match &request.kind {
        ContextDigestKindV1::BuildApprovalContextToken { components } => {
            result.token = Some(build_context_token(components)?);
        }
        ContextDigestKindV1::ValidateApprovalContextTokens {
            saved_token,
            current_token,
        } => {
            result.validation_reason = validate_context_tokens(saved_token, current_token);
        }
        ContextDigestKindV1::ValidateApprovalContext {
            saved_token,
            components,
        } => {
            let current = build_context_token(components)?;
            result.validation_reason =
                validate_context_tokens(saved_token, &Value::String(current));
        }
        ContextDigestKindV1::ConfiguredEnvironmentHash {
            values,
            configured_keys,
        } => {
            result.digest = Some(configured_values_hash(
                values.as_ref(),
                configured_keys.as_deref(),
                CONFIGURED_ENV_HASH_DOMAIN,
            )?);
        }
        ContextDigestKindV1::ConfiguredHeadersHash {
            values,
            configured_keys,
        } => {
            result.digest = Some(configured_values_hash(
                values.as_ref(),
                configured_keys.as_deref(),
                CONFIGURED_HEADER_HASH_DOMAIN,
            )?);
        }
        ContextDigestKindV1::LaunchArgvDigest { argv } => {
            // _launch_argv_digest: sha256 over ensure_ascii compact JSON of
            // the argv list — no sort_keys (arrays keep their order).
            let mut material = Vec::with_capacity(128);
            let argv_values: Vec<Value> =
                argv.iter().map(|arg| Value::String(arg.clone())).collect();
            write_canonical_json(&Value::Array(argv_values), &mut material)?;
            result.digest = Some(digest_bytes(&material));
        }
    }
    Ok(())
}

/// Canonical-JSON digest of a request — order-independent, so the caller can
/// reproduce it by canonicalizing its own request serialization.
fn request_digest(request: &ContextDigestRequestV1) -> Result<String, &'static str> {
    let material = serde_json::to_value(request).map_err(|_| "native_context_digest_invalid")?;
    let mut canonical = Vec::with_capacity(512);
    // The request itself is already bounded by transport framing; the
    // component cap is enforced when hashing components, not the envelope.
    write_canonical_json_with_limit(&material, &mut canonical, usize::MAX)?;
    Ok(digest_bytes(&canonical))
}

pub(crate) fn evaluate_context_digest_request(
    request: &ContextDigestRequestV1,
) -> Result<Vec<u8>, String> {
    if request.schema != CONTEXT_DIGEST_REQUEST_SCHEMA {
        return Err("native_context_digest_schema_mismatch".to_owned());
    }
    let mut result = ContextDigestResultV1 {
        schema: CONTEXT_DIGEST_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256: request_digest(request)?,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        token: None,
        digest: None,
        validation_reason: None,
    };
    if let Err(code) = evaluate_request(request, &mut result) {
        result.status = "error".to_owned();
        result.code = code.to_owned();
    }
    crate::encode_response(&result)
}

pub(crate) fn evaluate_context_digest_bytes(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let value = crate::strict_json_value(bytes)?;
    let request: ContextDigestRequestV1 = serde_json::from_value(value)
        .map_err(|_| "native_context_digest_invalid_json".to_owned())?;
    evaluate_context_digest_request(&request)
}

#[cfg(test)]
#[path = "context_digest_tests.rs"]
mod tests;
