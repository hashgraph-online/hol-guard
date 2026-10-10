//! `FalsePositiveRules` — resident op owning the advisory false-positive
//! signals for a runtime action.
//!
//! Pure (no IO): the signals come from the same
//! `FalsePositiveSuppressorDetector` the Rust detector pipeline runs, so there
//! is one rule set. Python was the previous producer and now transports the
//! action fields and renders the answer. Failures are typed `error` results;
//! the caller must treat them as "no false-positive signal", never as a
//! suppression.

use guard_command::detectors::{
    DetectorActionView, DetectorContext, FalsePositiveSuppressorDetector, GuardDetector,
};
use guard_contracts::{
    FalsePositiveRulesRequestV1, FalsePositiveRulesResultV1, FALSE_POSITIVE_RULES_MAX_BYTES,
    FALSE_POSITIVE_RULES_REQUEST_SCHEMA, FALSE_POSITIVE_RULES_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::{json, Map, Value};

use super::context_digest_json::write_canonical_json_with_limit;

const ERR_INVALID: &str = "native_false_positive_rules_invalid";
const ERR_SCHEMA: &str = "native_false_positive_rules_schema_mismatch";
const ERR_TOO_LARGE: &str = "native_false_positive_rules_request_too_large";

/// Digest of the canonical request, matching Python `_canonical_request_sha256`.
///
/// The size bound is applied before and during encoding so a request the
/// resident will reject is never copied or escaped in full.
fn request_digest(request: &FalsePositiveRulesRequestV1) -> Result<String, &'static str> {
    // The ASCII-escaped canonical form is never shorter than the UTF-8 text it
    // encodes, so the raw component bytes are a lower bound on its size.
    let component_bytes = request.command.as_ref().map_or(0, String::len)
        + request.target_paths.iter().map(String::len).sum::<usize>();
    if component_bytes > FALSE_POSITIVE_RULES_MAX_BYTES {
        return Err(ERR_TOO_LARGE);
    }
    let material = serde_json::to_value(request).map_err(|_| ERR_INVALID)?;
    let mut canonical = Vec::with_capacity(512);
    if write_canonical_json_with_limit(&material, &mut canonical, FALSE_POSITIVE_RULES_MAX_BYTES)
        .is_err()
    {
        return Err(if canonical.len() > FALSE_POSITIVE_RULES_MAX_BYTES {
            ERR_TOO_LARGE
        } else {
            ERR_INVALID
        });
    }
    if canonical.len() > FALSE_POSITIVE_RULES_MAX_BYTES {
        return Err(ERR_TOO_LARGE);
    }
    Ok(digest_bytes(&canonical))
}

fn evaluate(request: &FalsePositiveRulesRequestV1) -> Result<Value, &'static str> {
    if request.schema != FALSE_POSITIVE_RULES_REQUEST_SCHEMA {
        return Err(ERR_SCHEMA);
    }
    if request.guard_home.is_empty() {
        return Err(ERR_INVALID);
    }
    let action = DetectorActionView {
        action_type: &request.action_type,
        command: request.command.as_deref(),
        prompt_text: None,
        prompt_excerpt: None,
        mcp_tool: None,
        target_paths: &request.target_paths,
    };
    let empty = Map::new();
    let context = DetectorContext {
        config: &empty,
        workspace: None,
        prior_decisions: &empty,
        threat_intel: &empty,
        redaction_settings: &empty,
        approved_scan_roots: &[],
    };
    let signals: Vec<Value> = FalsePositiveSuppressorDetector
        .detect(&action, &context)
        .iter()
        .map(|signal| signal.to_value())
        .collect();
    Ok(json!({ "signals": signals }))
}

pub(crate) fn evaluate_false_positive_rules(
    request: &FalsePositiveRulesRequestV1,
) -> Result<Vec<u8>, String> {
    // Digest/size failures are this op's own typed error result, not a
    // transport error (which the resident would redact to invalid-json).
    let request_sha256 = match request_digest(request) {
        Ok(digest) => digest,
        Err(code) => {
            return crate::encode_response(&FalsePositiveRulesResultV1 {
                schema: FALSE_POSITIVE_RULES_RESULT_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_sha256: String::new(),
                status: "error".to_owned(),
                code: code.to_owned(),
                payload: None,
            });
        }
    };
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code.to_owned(), None),
    };
    crate::encode_response(&FalsePositiveRulesResultV1 {
        schema: FALSE_POSITIVE_RULES_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

#[cfg(test)]
#[path = "false_positive_rules_op_tests.rs"]
mod tests;
