//! `ProtectRequest` — resident op for install-time protect.
//!
//! Parses the wrapped command through
//! `guard_command::protect_request::parse_protect_command`, reads the store's
//! `publisher_cache` read-only, and evaluates the local verdict with
//! `evaluate_protect_request`. The store is never written.

use crate::local_store_read::{open_read_only, require_store_path, table_exists};
use crate::package_authority_op::request_digest_with_limit;
use guard_command::protect_request::{
    evaluate_protect_request_in, parse_protect_command, ProtectParseError, ProtectRequest,
    ProtectTarget,
};
use guard_contracts::{
    ProtectCachedAdvisoryV1, ProtectParsedRequestV1, ProtectRequestRequestV1,
    ProtectRequestResultV1, ProtectTargetV1, ProtectVerdictV1, PROTECT_REQUEST_MAX_BYTES,
    PROTECT_REQUEST_REQUEST_SCHEMA, PROTECT_REQUEST_RESULT_SCHEMA,
};
use serde_json::{Map, Value};

const STORE_UNAVAILABLE: &str = "native_protect_request_store_unavailable";
const CACHE_INVALID: &str = "native_protect_request_cache_invalid";
const MATCHES_TOO_LARGE: &str = "native_protect_request_matches_too_large";
/// Encoded size budget for the matched cache rows, half the resident's 2 MiB
/// response limit. Larger matches fail closed with a typed error instead of
/// an unencodable response.
const MATCHED_ADVISORIES_MAX_BYTES: usize = 1024 * 1024;
/// Bound on rewriting one out-of-range number per cached payload.
const OUT_OF_RANGE_REWRITES: u8 = 8;

struct Failure {
    code: &'static str,
    detail: Option<String>,
}

impl From<&'static str> for Failure {
    fn from(code: &'static str) -> Self {
        Self { code, detail: None }
    }
}

pub(crate) fn evaluate_protect_request_op(
    request: &ProtectRequestRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any parsing or store work; an
    // oversized request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, PROTECT_REQUEST_MAX_BYTES)
        .map_err(|_| "native_protect_request_too_large".to_owned())?;
    let result = match evaluate(request) {
        Ok((parsed, verdict)) => ProtectRequestResultV1 {
            schema: PROTECT_REQUEST_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "ok".to_owned(),
            code: "ok".to_owned(),
            detail: None,
            request: Some(parsed),
            verdict: Some(verdict),
        },
        Err(failure) => ProtectRequestResultV1 {
            schema: PROTECT_REQUEST_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "error".to_owned(),
            code: failure.code.to_owned(),
            detail: failure.detail,
            request: None,
            verdict: None,
        },
    };
    // A matched-row cap under 1 MiB can still leave the reason and the parsed
    // request over the resident's 2 MiB response limit. That is a typed
    // refusal, not an untyped transport error.
    match crate::encode_response(&result) {
        Ok(bytes) => Ok(bytes),
        Err(reason) if reason == "native_response_too_large" && result.status == "ok" => {
            crate::encode_response(&ProtectRequestResultV1 {
                schema: result.schema.clone(),
                request_id: result.request_id.clone(),
                request_sha256: result.request_sha256.clone(),
                status: "error".to_owned(),
                code: MATCHES_TOO_LARGE.to_owned(),
                detail: None,
                request: None,
                verdict: None,
            })
        }
        Err(reason) => Err(reason),
    }
}

fn evaluate(
    request: &ProtectRequestRequestV1,
) -> Result<(ProtectParsedRequestV1, ProtectVerdictV1), Failure> {
    if request.schema != PROTECT_REQUEST_REQUEST_SCHEMA {
        return Err("native_protect_request_schema_mismatch".into());
    }
    if request.command.is_empty() {
        return Err("native_protect_request_command_empty".into());
    }
    let parsed = parse_protect_command(&request.command).map_err(|error| match error {
        ProtectParseError::InvalidUrl(message) => Failure {
            code: "native_protect_request_invalid_url",
            detail: Some(message),
        },
        ProtectParseError::UnsupportedPayload => {
            Failure::from("native_protect_request_unsupported_payload")
        }
    })?;
    let rows = match &request.store_path {
        Some(store_path) => cached_advisories(store_path, &request.guard_home)?,
        None => Vec::new(),
    };
    let advisories: Vec<Value> = rows.iter().map(|(_, advisory)| advisory.clone()).collect();
    let cwd = request.cwd.as_deref().map(std::path::Path::new);
    let verdict = evaluate_protect_request_in(&parsed, &advisories, cwd);
    let matched_advisories: Vec<ProtectCachedAdvisoryV1> = verdict
        .matched
        .iter()
        .map(|index| rows[*index].0.clone())
        .collect();
    let encoded_len = serde_json::to_vec(&matched_advisories)
        .map_err(|_| Failure::from(CACHE_INVALID))?
        .len();
    if encoded_len > MATCHED_ADVISORIES_MAX_BYTES {
        return Err(MATCHES_TOO_LARGE.into());
    }
    Ok((
        parsed_request(&parsed),
        ProtectVerdictV1 {
            action: verdict.action.to_owned(),
            reason: verdict.reason,
            risk_signals: verdict.risk_signals,
            matched_advisories,
        },
    ))
}

/// Every dict-shaped `publisher_cache` row, newest first, as the raw row plus
/// the `{"cache_key", "updated_at", **payload}` advisory the matcher reads.
fn cached_advisories(
    store_path: &str,
    guard_home: &str,
) -> Result<Vec<(ProtectCachedAdvisoryV1, Value)>, Failure> {
    let path = require_store_path(store_path, guard_home)
        .map_err(|_| Failure::from("native_protect_request_store_path_invalid"))?;
    let Some(connection) = open_read_only(&path).map_err(|_| Failure::from(STORE_UNAVAILABLE))?
    else {
        return Ok(Vec::new());
    };
    if !table_exists(&connection, "publisher_cache").map_err(|_| STORE_UNAVAILABLE)? {
        return Ok(Vec::new());
    }
    let mut statement = connection
        .prepare(
            "SELECT publisher_key, payload_json, updated_at FROM publisher_cache \
             ORDER BY updated_at DESC",
        )
        .map_err(|_| STORE_UNAVAILABLE)?;
    let mut rows = statement.query([]).map_err(|_| STORE_UNAVAILABLE)?;
    let mut advisories = Vec::new();
    while let Some(row) = rows.next().map_err(|_| STORE_UNAVAILABLE)? {
        let text = |index: usize| -> Result<String, Failure> {
            match row.get_ref(index).map_err(|_| CACHE_INVALID)? {
                rusqlite::types::ValueRef::Text(raw) => std::str::from_utf8(raw)
                    .map(str::to_owned)
                    .map_err(|_| CACHE_INVALID.into()),
                _ => Err(CACHE_INVALID.into()),
            }
        };
        let raw = ProtectCachedAdvisoryV1 {
            cache_key: text(0)?,
            payload_json: text(1)?,
            updated_at: text(2)?,
        };
        let Value::Object(payload) = parse_cache_payload(&raw.payload_json)? else {
            continue;
        };
        let mut advisory = Map::new();
        advisory.insert("cache_key".to_owned(), Value::String(raw.cache_key.clone()));
        advisory.insert(
            "updated_at".to_owned(),
            Value::String(raw.updated_at.clone()),
        );
        advisory.extend(payload);
        advisories.push((raw, Value::Object(advisory)));
    }
    Ok(advisories)
}

/// Python `json.dumps(..., allow_nan=True)` writes bare `NaN`, `Infinity`,
/// and `-Infinity`. Those tokens are not JSON, but one such row must not fail
/// every protect. The token becomes null so string match fields still block a
/// critical advisory. A number serde rejects as out of range is nulled the
/// same way. Invalid JSON still fails the request.
fn parse_cache_payload(raw: &str) -> Result<Value, Failure> {
    let mut candidate = rewrite_non_finite_literals(raw);
    for _ in 0..OUT_OF_RANGE_REWRITES {
        match serde_json::from_str::<Value>(&candidate) {
            Ok(value) => return Ok(value),
            Err(error) if is_number_out_of_range(&error) => {
                if !replace_out_of_range_number(&mut candidate, error.line(), error.column()) {
                    return Err(CACHE_INVALID.into());
                }
            }
            Err(_) => return Err(CACHE_INVALID.into()),
        }
    }
    Err(CACHE_INVALID.into())
}

fn is_number_out_of_range(error: &serde_json::Error) -> bool {
    error.to_string().contains("number out of range")
}

fn rewrite_non_finite_literals(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            let byte = bytes[index];
            let ch = raw[index..].chars().next().expect("index is on a char");
            out.push(ch);
            index += ch.len_utf8();
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        if bytes[index] == b'"' {
            in_string = true;
            out.push('"');
            index += 1;
            continue;
        }
        if let Some(length) = bare_non_finite_len(&bytes[index..]) {
            let before = out.as_bytes().last().copied();
            let after = index + length;
            if ident_boundary(before) && ident_boundary(bytes.get(after).copied()) {
                out.push_str("null");
                index = after;
                continue;
            }
        }
        let ch = raw[index..].chars().next().expect("index is on a char");
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

fn bare_non_finite_len(rest: &[u8]) -> Option<usize> {
    if rest.starts_with(b"+Infinity") || rest.starts_with(b"-Infinity") {
        Some(9)
    } else if rest.starts_with(b"Infinity") {
        Some(8)
    } else if rest.starts_with(b"NaN") {
        Some(3)
    } else {
        None
    }
}

fn ident_boundary(byte: Option<u8>) -> bool {
    match byte {
        Some(byte) => !byte.is_ascii_alphanumeric() && byte != b'_',
        None => true,
    }
}

fn replace_out_of_range_number(raw: &mut String, line: usize, column: usize) -> bool {
    let Some(line_start) = line_start_index(raw, line) else {
        return false;
    };
    // SliceRead reports the next unread byte. The documented column is
    // 1-based. Either index sits in the rejected number or just after it.
    replace_number_touching(raw, line_start + column)
        || replace_number_touching(raw, line_start + column.saturating_sub(1))
}

fn line_start_index(raw: &str, line: usize) -> Option<usize> {
    if line == 0 {
        return None;
    }
    if line == 1 {
        return Some(0);
    }
    let mut current = 1;
    for (index, byte) in raw.bytes().enumerate() {
        if byte == b'\n' {
            current += 1;
            if current == line {
                return Some(index + 1);
            }
        }
    }
    None
}

fn replace_number_touching(raw: &mut String, anchor: usize) -> bool {
    let (start, end) = {
        let bytes = raw.as_bytes();
        if bytes.is_empty() {
            return false;
        }
        let mut probe = anchor.min(bytes.len());
        if probe == bytes.len() || !is_number_byte(bytes[probe]) {
            probe = probe.saturating_sub(1);
            if !is_number_byte(bytes[probe]) {
                probe = probe.saturating_sub(1);
                if !is_number_byte(bytes[probe]) {
                    return false;
                }
            }
        }
        let mut start = probe;
        while start > 0 && is_number_byte(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = probe + 1;
        while end < bytes.len() && is_number_byte(bytes[end]) {
            end += 1;
        }
        if !bytes[start..end].iter().any(|byte| byte.is_ascii_digit()) {
            return false;
        }
        (start, end)
    };
    raw.replace_range(start..end, "null");
    true
}

fn is_number_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'.' | b'e' | b'E' | b'+' | b'-')
}

fn parsed_request(request: &ProtectRequest) -> ProtectParsedRequestV1 {
    ProtectParsedRequestV1 {
        command: request.command.clone(),
        install_kind: request.install_kind.clone(),
        executor: request.executor.clone(),
        package_manager: request.package_manager.clone(),
        harness: request.harness.clone(),
        targets: request.targets.iter().map(target).collect(),
    }
}

fn target(target: &ProtectTarget) -> ProtectTargetV1 {
    ProtectTargetV1 {
        artifact_id: target.artifact_id.clone(),
        artifact_name: target.artifact_name.clone(),
        artifact_type: target.artifact_type.clone(),
        ecosystem: target.ecosystem.clone(),
        package_name: target.package_name.clone(),
        package_url: target.package_url.clone(),
        raw_spec: target.raw_spec.clone(),
        version: target.version.clone(),
        source_url: target.source_url.clone(),
        harness: target.harness.clone(),
    }
}

#[cfg(test)]
#[path = "protect_request_op_tests.rs"]
mod tests;
