//! Semantic, fail-closed parsing of pytest configuration files
//! (`runtime/pytest_config.py`): one parse per file, the first-applicable
//! selection, the per-segment combination and the evidence identity.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::codex_output_py::PyPath;
use crate::sfrs_pytest_config_ini::{parse_ini_section, IniError};
use crate::sfrs_pytest_config_read::read_config_bytes;
use crate::sfrs_pytest_config_toml::{parse_toml, TomlFailure};
use crate::sfrs_pytest_config_value::{
    config_value, json_string, PytestConfigValue, Raw, ValueFailure,
};

pub(crate) const DECODE_ERROR: &str = "pytest_config_decode_error";
pub(crate) const DUPLICATE_KEY: &str = "pytest_config_duplicate_key";
pub(crate) const SYNTAX_ERROR: &str = "pytest_config_syntax_error";
pub(crate) const VALUE_TYPE_INVALID: &str = "pytest_config_value_type_invalid";
pub(crate) const MISSING: &str = "pytest_config_missing";

/// `PytestConfigParseResult`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PytestConfigParseResult {
    pub(crate) source_path: String,
    pub(crate) present: bool,
    pub(crate) value: Option<PytestConfigValue>,
    pub(crate) complete: bool,
    pub(crate) reason_code: Option<String>,
    pub(crate) content_sha256: Option<String>,
}

/// `PytestConfigAssessment`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub(crate) struct PytestConfigAssessment {
    pub(crate) results: Vec<PytestConfigParseResult>,
    pub(crate) complete: bool,
    pub(crate) unsafe_options: bool,
    pub(crate) reason_codes: Vec<String>,
    pub(crate) identity_sha256: Option<String>,
}

fn empty_assessment() -> PytestConfigAssessment {
    PytestConfigAssessment {
        complete: true,
        ..PytestConfigAssessment::default()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn parse_failure(source_path: &str, hash: &str, reason: &str) -> PytestConfigParseResult {
    PytestConfigParseResult {
        source_path: source_path.to_owned(),
        present: true,
        value: None,
        complete: false,
        reason_code: Some(reason.to_owned()),
        content_sha256: Some(hash.to_owned()),
    }
}

/// `parse_pytest_config`.
pub(crate) fn parse_pytest_config(
    workspace_root: &Path,
    relative_path: &str,
) -> PytestConfigParseResult {
    let relative = PyPath::new(relative_path);
    let normalized = relative.to_string();
    let read = read_config_bytes(workspace_root, relative_path);
    let reason = read.reason_code.map(str::to_owned);
    if !read.present {
        return PytestConfigParseResult {
            source_path: normalized,
            present: false,
            value: None,
            complete: reason.is_none(),
            reason_code: reason,
            content_sha256: None,
        };
    }
    let Some(content) = read.content else {
        return PytestConfigParseResult {
            source_path: normalized,
            present: true,
            value: None,
            complete: false,
            reason_code: reason,
            content_sha256: None,
        };
    };
    let hash = sha256_hex(&content);
    let Ok(text) = String::from_utf8(content) else {
        return parse_failure(&normalized, &hash, DECODE_ERROR);
    };
    let is_toml = relative.suffix().to_lowercase() == ".toml";
    let outcome = if is_toml {
        parse_toml(&text, relative.name()).map_err(|failure| match failure {
            TomlFailure::Duplicate => DUPLICATE_KEY,
            TomlFailure::Syntax => SYNTAX_ERROR,
            TomlFailure::Type => VALUE_TYPE_INVALID,
        })
    } else {
        parse_ini(&text, relative.name())
    };
    match outcome {
        Ok(value) => PytestConfigParseResult {
            source_path: normalized,
            present: true,
            value,
            complete: true,
            reason_code: None,
            content_sha256: Some(hash),
        },
        Err(code) => parse_failure(&normalized, &hash, code),
    }
}

/// `_parse_ini`.
fn parse_ini(text: &str, filename: &str) -> Result<Option<PytestConfigValue>, &'static str> {
    let section = if filename == "setup.cfg" {
        "tool:pytest"
    } else {
        "pytest"
    };
    match parse_ini_section(text, section) {
        Err(IniError::Duplicate) => Err(DUPLICATE_KEY),
        Err(IniError::Syntax) => Err(SYNTAX_ERROR),
        Ok(None) => {
            Ok(matches!(filename, "pytest.ini" | ".pytest.ini").then(PytestConfigValue::default))
        }
        Ok(Some(options)) => {
            let raw: BTreeMap<String, Raw> = options
                .into_iter()
                .map(|(key, value)| (key, Raw::Str(value)))
                .collect();
            config_value(&raw)
                .map(Some)
                .map_err(|failure| match failure {
                    ValueFailure::Value => SYNTAX_ERROR,
                    ValueFailure::Type => VALUE_TYPE_INVALID,
                })
        }
    }
}

fn dedupe(paths: &[String]) -> Vec<&str> {
    let mut seen: Vec<&str> = Vec::new();
    for path in paths {
        if !seen.contains(&path.as_str()) {
            seen.push(path);
        }
    }
    seen
}

fn dedupe_reasons(reasons: impl Iterator<Item = String>) -> Vec<String> {
    let mut unique: Vec<String> = Vec::new();
    for reason in reasons {
        if !unique.contains(&reason) {
            unique.push(reason);
        }
    }
    unique
}

/// The JSON identity of a result list (`json.dumps(..., sort_keys=True,
/// separators=(",", ":"))` over the four evidence fields).
fn results_identity(results: &[PytestConfigParseResult]) -> String {
    let optional = |value: &Option<String>| value.as_deref().map_or("null".to_owned(), json_string);
    let items: Vec<String> = results
        .iter()
        .map(|result| {
            format!(
                "{{\"complete\":{},\"content_sha256\":{},\"reason_code\":{},\"source_path\":{}}}",
                result.complete,
                optional(&result.content_sha256),
                optional(&result.reason_code),
                json_string(&result.source_path),
            )
        })
        .collect();
    sha256_hex(format!("[{}]", items.join(",")).as_bytes())
}

/// `_assessment_from_results` (and the tail of `assess_pytest_configs`).
fn assessment_from_results(results: Vec<PytestConfigParseResult>) -> PytestConfigAssessment {
    let reason_codes = dedupe_reasons(results.iter().filter_map(|r| r.reason_code.clone()));
    let complete = results.iter().all(|result| result.complete);
    let unsafe_options = !complete
        || results.iter().any(|result| {
            result
                .value
                .as_ref()
                .is_some_and(|value| value.unsafe_options)
        });
    let identity = results_identity(&results);
    PytestConfigAssessment {
        results,
        complete,
        unsafe_options,
        reason_codes,
        identity_sha256: Some(identity),
    }
}

/// `assess_pytest_configs`.
pub(crate) fn assess_pytest_configs(
    workspace_root: &Path,
    relative_paths: &[String],
    require_present: bool,
) -> PytestConfigAssessment {
    let relevant: Vec<PytestConfigParseResult> = dedupe(relative_paths)
        .into_iter()
        .map(|path| parse_pytest_config(workspace_root, path))
        .map(|result| {
            if require_present && !result.present && result.complete {
                PytestConfigParseResult {
                    source_path: result.source_path,
                    present: false,
                    value: None,
                    complete: false,
                    reason_code: Some(MISSING.to_owned()),
                    content_sha256: None,
                }
            } else {
                result
            }
        })
        .filter(|result| result.present || !result.complete)
        .collect();
    if relevant.is_empty() {
        return empty_assessment();
    }
    assessment_from_results(relevant)
}

/// `assess_selected_pytest_config`.
pub(crate) fn assess_selected_pytest_config(
    workspace_root: &Path,
    relative_paths: &[String],
) -> PytestConfigAssessment {
    let mut fallback_pyproject: Option<PytestConfigParseResult> = None;
    for relative_path in dedupe(relative_paths) {
        let result = parse_pytest_config(workspace_root, relative_path);
        if !result.present {
            continue;
        }
        if !result.complete || result.value.is_some() {
            return assessment_from_results(vec![result]);
        }
        if PyPath::new(relative_path).name() == "pyproject.toml" && fallback_pyproject.is_none() {
            fallback_pyproject = Some(result);
        }
    }
    match fallback_pyproject {
        Some(result) => assessment_from_results(vec![result]),
        None => empty_assessment(),
    }
}

/// `combine_pytest_config_assessments`.
pub(crate) fn combine_pytest_config_assessments(
    assessments: &[PytestConfigAssessment],
) -> PytestConfigAssessment {
    let selected: Vec<&PytestConfigAssessment> = assessments
        .iter()
        .filter(|assessment| {
            !assessment.results.is_empty()
                || !assessment.complete
                || assessment.unsafe_options
                || !assessment.reason_codes.is_empty()
                || assessment.identity_sha256.is_some()
        })
        .collect();
    if selected.is_empty() {
        return empty_assessment();
    }
    let identities: Vec<String> = selected
        .iter()
        .map(|assessment| {
            assessment
                .identity_sha256
                .as_deref()
                .map_or("null".to_owned(), json_string)
        })
        .collect();
    PytestConfigAssessment {
        results: selected.iter().flat_map(|a| a.results.clone()).collect(),
        complete: selected.iter().all(|assessment| assessment.complete),
        unsafe_options: selected.iter().any(|assessment| assessment.unsafe_options),
        reason_codes: dedupe_reasons(selected.iter().flat_map(|a| a.reason_codes.clone())),
        identity_sha256: Some(sha256_hex(format!("[{}]", identities.join(",")).as_bytes())),
    }
}
