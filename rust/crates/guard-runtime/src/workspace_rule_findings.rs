//! `workspace_rule_findings` runner-authority kind: the rule detectors of a
//! workspace assessment. Ported from `workspace_rule_findings` and its
//! detector modules (agent skills, MCP configuration, project hooks, agent
//! plugins, CI workflows, editor tasks and instruction files).
//!
//! Each native rule check replies in the same shape: a schema tag, a status,
//! scan counts, skipped counts, truncation reasons and a bounded list of
//! findings. This kind checks that shape, copies each well-formed finding into
//! the stored finding and records the detector's coverage. A finding that does
//! not match is dropped and leaves the detector incomplete instead of silently
//! complete. Rule findings are dashboard warnings; they never block or ask.
//!
//! Args `{"coverage": {...}, "results": [[detector_id, result_or_null], ...]}`
//! answer `{"findings": [...], "coverage": {...}}`: the well-formed findings of
//! every detector in request order, and the coverage with each detector added
//! in request order. A `null` result is a runtime without the check.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::hermes_printable::is_printable;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

#[path = "workspace_rule_specs.rs"]
mod specs;

use specs::Spec;

type Row = Map<String, Value>;

const SOURCE_KIND: &str = "workspace_source";
const MAX_FINDINGS: usize = 200;
const MAX_PATH_CHARS: usize = 4096;
const MAX_TEXT_CHARS: usize = 1024;
const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];
const CONFIDENCES: [&str; 3] = ["weak", "likely", "strong"];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let mut coverage = args
        .get("coverage")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?
        .clone();
    let results = args
        .get("results")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let mut findings = Vec::new();
    for entry in results {
        let (spec, result) = match entry.as_array().map(Vec::as_slice) {
            Some([Value::String(detector), result]) => {
                (specs::spec(detector).ok_or(ERR_INVALID)?, result)
            }
            _ => return Err(ERR_INVALID),
        };
        findings.extend(projection(spec, result).0);
        coverage = with_coverage(spec, coverage, result);
    }
    Ok(json!({ "findings": findings, "coverage": coverage }))
}

/// Add one rule detector to a run's coverage.
///
/// A runtime without the check leaves the detector not run; a check that
/// could not read every input, or a malformed reply, leaves it incomplete.
/// Both make the run partial. A worktree with nothing to check has no inputs.
fn with_coverage(spec: &Spec, mut coverage: Row, result: &Value) -> Row {
    let mut reasons: Vec<Value> = coverage
        .get("reasons")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut summary = None;
    let status = if result.is_null() {
        reasons.push(json!(format!("detector_not_run:{}", spec.detector)));
        "not_run"
    } else {
        match scan_status(spec, result) {
            None => {
                reasons.push(json!(spec.incomplete_reason));
                "error"
            }
            Some((scanned, truncation)) => {
                let mut status = "complete";
                if !truncation.is_empty() {
                    status = "incomplete";
                    reasons.push(json!(spec.incomplete_reason));
                }
                // A scan that stopped at its own cap lists only some findings.
                let finding_cap = json!("finding_cap");
                if truncation.iter().any(|reason| reason == "max_findings")
                    && !reasons.contains(&finding_cap)
                {
                    reasons.push(finding_cap);
                }
                if status == "complete" && scanned.get(spec.inputs_counter).is_some_and(is_zero) {
                    status = "no_inputs";
                }
                summary = Some(scanned);
                status
            }
        }
    };
    let mut detectors = coverage
        .get("detectors")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    detectors.insert(spec.detector.to_owned(), json!(status));
    let run_status = if reasons.is_empty() {
        "complete"
    } else {
        "partial"
    };
    coverage.insert("status".to_owned(), json!(run_status));
    coverage.insert("reasons".to_owned(), Value::Array(reasons));
    coverage.insert("detectors".to_owned(), Value::Object(detectors));
    if let Some(summary) = summary {
        coverage.insert(spec.summary_key.to_owned(), Value::Object(summary));
    }
    coverage
}

/// The scan summary and truncation reasons of a readable reply, or `None`
/// for an unreadable one.
fn scan_status(spec: &Spec, value: &Value) -> Option<(Row, Vec<String>)> {
    let result = value.as_object()?;
    if result.get("schema").and_then(Value::as_str) != Some(spec.result_schema) {
        return None;
    }
    let status = result.get("status").and_then(Value::as_str);
    // A reply without its findings list cannot show that nothing was found.
    if !matches!(status, Some("complete" | "incomplete"))
        || !result.get("findings").is_some_and(Value::is_array)
    {
        return None;
    }
    let skipped = result.get("skipped").and_then(Value::as_object);
    // A strict reply must carry valid scan counts, its skipped counts and its
    // truncation reasons; otherwise a missing count reads as zero.
    if spec.strict_counts
        && (!spec
            .counters
            .iter()
            .all(|counter| is_count(result.get(*counter)))
            || skipped.is_none()
            || !result
                .get("truncation_reasons")
                .is_some_and(Value::is_array))
    {
        return None;
    }
    let mut reasons = truncation_reasons(result.get("truncation_reasons"));
    if projection(spec, value).1 > 0 {
        reasons.insert("invalid_finding".to_owned());
    }
    let mut reasons: Vec<String> = reasons.into_iter().collect();
    if status == Some("incomplete") && reasons.is_empty() {
        reasons.push("incomplete".to_owned());
    }
    let mut summary: Row = spec
        .counters
        .iter()
        .map(|counter| ((*counter).to_owned(), count(result.get(*counter))))
        .collect();
    let skipped_counts: Row = spec
        .skip_kinds
        .iter()
        .map(|kind| {
            let value = skipped.and_then(|skipped| skipped.get(*kind));
            ((*kind).to_owned(), count(value))
        })
        .collect();
    summary.insert("skipped".to_owned(), Value::Object(skipped_counts));
    summary.insert(
        "truncation_reasons".to_owned(),
        Value::from(reasons.clone()),
    );
    Some((summary, reasons))
}

/// The well-formed findings of a reply, and how many were malformed or past
/// the cap.
fn projection(spec: &Spec, result: &Value) -> (Vec<Value>, usize) {
    let Some(raw) = result.get("findings").and_then(Value::as_array) else {
        return (Vec::new(), 0);
    };
    let kept = &raw[..raw.len().min(MAX_FINDINGS)];
    let findings: Vec<Value> = kept.iter().filter_map(|item| finding(spec, item)).collect();
    let dropped = kept.len() - findings.len() + raw.len().saturating_sub(MAX_FINDINGS);
    (findings, dropped)
}

fn finding(spec: &Spec, item: &Value) -> Option<Value> {
    let item = item.as_object()?;
    let extra = (spec.finding_fields)(item)?;
    let finding_id = item
        .get("finding_id")
        .and_then(Value::as_str)
        .filter(|id| {
            id.len() == 32
                && id
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })?;
    let rule_id = item.get("rule_id").and_then(Value::as_str)?;
    let category = item
        .get("category")
        .and_then(Value::as_str)
        .filter(|category| {
            (1..=32).contains(&category.len())
                && category
                    .bytes()
                    .all(|byte| byte == b'_' || byte.is_ascii_lowercase())
        })?;
    let severity = item
        .get("severity")
        .and_then(Value::as_str)
        .filter(|severity| SEVERITIES.contains(severity))?;
    let confidence = item
        .get("confidence")
        .and_then(Value::as_str)
        .filter(|confidence| CONFIDENCES.contains(confidence))?;
    let title = rule_text(item.get("title"))?;
    let reason = rule_text(item.get("reason"))?;
    let hint = match item.get("false_positive_hint") {
        None | Some(Value::Null) => None,
        hint => Some(rule_text(hint)?),
    };
    let mut out: Row = [
        ("finding_id", json!(finding_id)),
        ("source_kind", json!(SOURCE_KIND)),
        ("detector", json!(spec.detector)),
        ("severity", json!(severity)),
        ("decision", json!("warn")),
        ("ecosystem", Value::Null),
        ("package_name", Value::Null),
        ("package_version", Value::Null),
        ("fix_version", Value::Null),
        ("rule_ids", json!([rule_id])),
        ("advisory_ids", json!([])),
        ("path", item.get("path").cloned().unwrap_or(Value::Null)),
        ("line", Value::Null),
        ("category", json!(category)),
        ("confidence", json!(confidence)),
        ("title", json!(title)),
        ("reason", json!(reason)),
        ("false_positive_hint", json!(hint)),
        ("validation_state", json!("unvalidated")),
        ("lifecycle_state", json!("open")),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect();
    out.extend(extra);
    Some(Value::Object(out))
}

/// A normalized root-relative path, never one that leaves the root.
fn relative_path(value: Option<&Value>) -> Option<&str> {
    let path = value?.as_str()?;
    let bounded = path.chars().count() <= MAX_PATH_CHARS && !path.contains(['\0', '\\']);
    (bounded
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
        && path
            .split('/')
            .next()
            .is_some_and(|first| !first.ends_with(':')))
    .then_some(path)
}

/// One bounded printable line.
fn rule_text(value: Option<&Value>) -> Option<&str> {
    let text = value?.as_str()?;
    ((1..=MAX_TEXT_CHARS).contains(&text.chars().count()) && text.chars().all(is_printable))
        .then_some(text)
}

/// A Python `int` that is not a bool and not negative: a JSON integer
/// without sign, fraction or exponent, of any size.
fn is_count(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Number(number)) => {
            let text = number.to_string();
            !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit())
        }
        _ => false,
    }
}

fn count(value: Option<&Value>) -> Value {
    match value {
        Some(value) if is_count(Some(value)) => value.clone(),
        _ => json!(0),
    }
}

fn is_zero(value: &Value) -> bool {
    value.to_string().bytes().all(|byte| byte == b'0')
}

/// The well-formed truncation reasons, sorted and without repeats.
fn truncation_reasons(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|reason| {
            (1..=40).contains(&reason.len())
                && reason
                    .bytes()
                    .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
#[path = "workspace_rule_findings_tests.rs"]
mod tests;
