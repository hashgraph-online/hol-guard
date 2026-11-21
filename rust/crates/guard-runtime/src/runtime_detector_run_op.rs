//! `RuntimeDetectorRun` — resident op owning the default runtime detector run
//! for one action: secret paths, data-flow exfiltration, prompt injection,
//! skill content, supply chain, safe decode, false-positive hints,
//! persistence, Guard bypass and MCP tool risk.
//!
//! Pure (no IO). The detectors come from `guard_command::detectors`, so the
//! registry semantics (id order, disabled ids, category filter, timeout and
//! panic isolation) live in one place. Python transports the action and the
//! registry options and renders the per-detector entries; it adds only the
//! scanner-backed Cisco preflight entries, which are not part of this op. A
//! prompt-analysis, data-flow or supply-chain failure fails the whole run
//! with a typed `error` result, and the caller fails closed.

use std::path::{Path, PathBuf};

use guard_command::detectors::{
    DataFlowExfiltrationDetector, DetectorActionView, DetectorContext, DetectorRegistry,
    FalsePositiveSuppressorDetector, GuardBypassDetector, GuardDetector,
    McpDescriptionDeceptionDetector, McpToolSchemaRiskDetector, NativeSupplyChainRisk,
    PersistenceDetector, PromptInjectionDetector, SafeDecodeDetector, SecretPathDetector,
    SkillRiskDetector, SupplyChainDetector,
};
use guard_command::persistence_rules::NativePersistenceRules;
use guard_command::safe_decode::NativeSafeDecode;
use guard_command::skill_content_risk::NativeSkillProtection;
use guard_contracts::{
    RiskSignalCategory, RuntimeDetectorRunRequestV1, RuntimeDetectorRunResultV1,
    RUNTIME_DETECTOR_RUN_MAX_BYTES, RUNTIME_DETECTOR_RUN_REQUEST_SCHEMA,
    RUNTIME_DETECTOR_RUN_RESULT_SCHEMA,
};
use guard_policy_snapshot::digest_bytes;
use serde_json::{json, Map, Value};

use super::context_digest_json::write_canonical_json_with_limit;

const ERR_INVALID: &str = "native_runtime_detector_run_invalid";
const ERR_SCHEMA: &str = "native_runtime_detector_run_schema_mismatch";
const ERR_TOO_LARGE: &str = "native_runtime_detector_run_request_too_large";

/// Digest of the canonical request, matching Python `_canonical_request_sha256`.
///
/// The size bound is applied before and during encoding so a request the
/// resident will reject is never copied or escaped in full.
fn request_digest(request: &RuntimeDetectorRunRequestV1) -> Result<String, &'static str> {
    // The ASCII-escaped canonical form is never shorter than the UTF-8 text it
    // encodes, so the raw component bytes are a lower bound on its size.
    let action = &request.action;
    let component_bytes = [
        &action.command,
        &action.prompt_text,
        &action.prompt_excerpt,
        &action.mcp_tool,
    ]
    .iter()
    .map(|field| field.as_ref().map_or(0, String::len))
    .sum::<usize>()
        + action.target_paths.iter().map(String::len).sum::<usize>();
    if component_bytes > RUNTIME_DETECTOR_RUN_MAX_BYTES {
        return Err(ERR_TOO_LARGE);
    }
    let material = serde_json::to_value(request).map_err(|_| ERR_INVALID)?;
    let mut canonical = Vec::with_capacity(1024);
    if write_canonical_json_with_limit(&material, &mut canonical, RUNTIME_DETECTOR_RUN_MAX_BYTES)
        .is_err()
    {
        return Err(if canonical.len() > RUNTIME_DETECTOR_RUN_MAX_BYTES {
            ERR_TOO_LARGE
        } else {
            ERR_INVALID
        });
    }
    if canonical.len() > RUNTIME_DETECTOR_RUN_MAX_BYTES {
        return Err(ERR_TOO_LARGE);
    }
    Ok(digest_bytes(&canonical))
}

/// The default detectors minus the scanner-backed Cisco preflight pair.
fn registry() -> DetectorRegistry {
    let detectors: Vec<Box<dyn GuardDetector>> = vec![
        Box::new(FalsePositiveSuppressorDetector),
        Box::new(DataFlowExfiltrationDetector),
        Box::new(GuardBypassDetector),
        Box::new(McpDescriptionDeceptionDetector),
        Box::new(McpToolSchemaRiskDetector),
        Box::new(PersistenceDetector {
            api: NativePersistenceRules,
        }),
        Box::new(PromptInjectionDetector),
        Box::new(SafeDecodeDetector {
            api: NativeSafeDecode,
        }),
        Box::new(SecretPathDetector),
        Box::new(SkillRiskDetector {
            api: NativeSkillProtection,
        }),
        Box::new(SupplyChainDetector {
            api: NativeSupplyChainRisk,
        }),
    ];
    DetectorRegistry::new(detectors, None)
}

/// Parse the category filter. A name no detector uses can never intersect a
/// detector's categories, so it is dropped (an all-unknown filter still
/// filters every detector, as in the Python registry).
fn category_filter(names: Option<&Vec<String>>) -> Option<Vec<RiskSignalCategory>> {
    names.map(|names| {
        names
            .iter()
            .filter_map(|name| RiskSignalCategory::parse(&Value::from(name.as_str())).ok())
            .collect()
    })
}

pub(crate) fn run(request: &RuntimeDetectorRunRequestV1) -> Result<Value, String> {
    if request.schema != RUNTIME_DETECTOR_RUN_REQUEST_SCHEMA {
        return Err(ERR_SCHEMA.to_owned());
    }
    if request.guard_home.is_empty() {
        return Err(ERR_INVALID.to_owned());
    }
    let action = DetectorActionView {
        action_type: &request.action.action_type,
        command: request.action.command.as_deref(),
        prompt_text: request.action.prompt_text.as_deref(),
        prompt_excerpt: request.action.prompt_excerpt.as_deref(),
        mcp_tool: request.action.mcp_tool.as_deref(),
        target_paths: &request.action.target_paths,
    };
    let empty = Map::new();
    let approved_scan_roots: [PathBuf; 0] = [];
    let context = DetectorContext {
        config: &empty,
        workspace: request.workspace.as_deref().map(Path::new),
        prior_decisions: &empty,
        threat_intel: &empty,
        redaction_settings: &empty,
        approved_scan_roots: &approved_scan_roots,
    };
    let disabled: Vec<&str> = request
        .disabled_detector_ids
        .iter()
        .map(String::as_str)
        .collect();
    let categories = category_filter(request.enabled_categories.as_ref());
    let timeout_ms = i64::try_from(request.timeout_ms).unwrap_or(i64::MAX);
    let result = registry().run(
        &action,
        &context,
        timeout_ms,
        &disabled,
        categories.as_deref(),
    )?;
    let mut signals = result.signals.iter();
    let detectors: Vec<Value> = result
        .telemetry
        .iter()
        .zip(&result.signal_counts)
        .map(|(telemetry, count)| {
            let mut entry = telemetry.to_dict();
            let emitted: Vec<Value> = signals
                .by_ref()
                .take(*count)
                .map(|s| s.to_value())
                .collect();
            entry.insert("signals".to_owned(), Value::Array(emitted));
            Value::Object(entry)
        })
        .collect();
    Ok(json!({ "detectors": detectors }))
}

pub(crate) fn evaluate_runtime_detector_run(
    request: &RuntimeDetectorRunRequestV1,
) -> Result<Vec<u8>, String> {
    // Digest/size failures are this op's own typed error result, not a
    // transport error (which the resident would redact to invalid-json).
    let request_sha256 = match request_digest(request) {
        Ok(digest) => digest,
        Err(code) => {
            return crate::encode_response(&RuntimeDetectorRunResultV1 {
                schema: RUNTIME_DETECTOR_RUN_RESULT_SCHEMA.to_owned(),
                request_id: request.request_id.clone(),
                request_sha256: String::new(),
                status: "error".to_owned(),
                code: code.to_owned(),
                payload: None,
            });
        }
    };
    let (status, code, payload) = match run(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&RuntimeDetectorRunResultV1 {
        schema: RUNTIME_DETECTOR_RUN_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

#[cfg(test)]
#[path = "runtime_detector_run_op_tests.rs"]
mod tests;
