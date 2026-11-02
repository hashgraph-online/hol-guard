//! `workspace_runtime_findings` runner-authority kind: the runtime part of a
//! workspace assessment. Ported from `workspace_runtime_findings`:
//! `runtime_identity_digest`, `project_runtime_findings` and
//! `with_runtime_coverage`.
//!
//! Python still probes the runtimes and keeps the per-worktree probe cache,
//! and ships the runtime posture with an `op`:
//!
//! - `identity_digest` with `posture` answers `{"digest"}`: a digest of which
//!   executables the configured tools would launch and what they are, or
//!   `null` when the posture is unavailable. Advisories are left out, since the
//!   cached bundle's own digest already queues a reassessment when it changes.
//! - `findings` with `worktree_key` and `posture` answers `{"findings",
//!   "truncated"}`: one observation-only finding per advisory and matched
//!   executable path, the known-exploited and most severe first, capped.
//! - `coverage` with `coverage` and `posture` (possibly `null`) answers
//!   `{"coverage"}`: the run's coverage with the runtime detector added.
//!
//! Values are read the way the Python module read them, through `str()`,
//! `is True` and truthiness, so digests and finding ids stay the same.

use std::collections::{HashMap, HashSet};

use guard_contracts::write_json_string;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::approval_queue_identity_op::{is_truthy, py_str};
use crate::daemon_lifecycle_text::py_strip;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const DETECTOR: &str = "runtime_identity_v1";
const SOURCE_KIND: &str = "agent_inventory";
const MAX_FINDINGS: usize = 50;
const MAX_TEXT_CHARS: usize = 256;
const FINDING_VERDICTS: [&str; 3] = ["affected", "restart_required", "fix_unverified"];
const SEVERITY_RANK: [&str; 5] = ["critical", "high", "medium", "low", "info"];

type Row = Map<String, Value>;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let posture = match args.get("posture").ok_or(ERR_INVALID)? {
        Value::Null => None,
        Value::Object(posture) => Some(posture),
        _ => return Err(ERR_INVALID),
    };
    match args.get("op").and_then(Value::as_str).ok_or(ERR_INVALID)? {
        "identity_digest" => Ok(json!({ "digest": identity_digest(posture.ok_or(ERR_INVALID)?) })),
        "findings" => {
            let worktree_key = args
                .get("worktree_key")
                .and_then(Value::as_str)
                .ok_or(ERR_INVALID)?;
            let (findings, truncated) = findings(worktree_key, posture.ok_or(ERR_INVALID)?);
            Ok(json!({ "findings": findings, "truncated": truncated }))
        }
        "coverage" => {
            let coverage = args
                .get("coverage")
                .and_then(Value::as_object)
                .ok_or(ERR_INVALID)?;
            Ok(json!({ "coverage": with_coverage(coverage, posture) }))
        }
        _ => Err(ERR_INVALID),
    }
}

fn identity_digest(posture: &Row) -> Option<String> {
    if is_unavailable(posture) {
        return None;
    }
    let mut runtimes: Vec<Vec<String>> = rows(posture.get("runtimes"))
        .map(|row| {
            [
                "path",
                "location_state",
                "family",
                "version",
                "executable_sha256",
            ]
            .into_iter()
            .map(|key| text_of(row.get(key)))
            .collect()
        })
        .collect();
    runtimes.sort();
    let mut unresolved: Vec<Vec<String>> = rows(posture.get("unresolved_launches"))
        .map(|row| {
            ["harness", "server", "command"]
                .into_iter()
                .map(|key| text_of(row.get(key)))
                .collect()
        })
        .collect();
    unresolved.sort();
    let mut skipped: Vec<String> = items(posture.get("skipped_harnesses"))
        .iter()
        .map(|item| text_of(Some(item)))
        .collect();
    skipped.sort();
    // `json.dumps(identity, separators=(",", ":"))`, keys in insertion order.
    let mut out = b"guard.workspace-runtimes.v1\0{\"status\":".to_vec();
    write_json_string(&text_of(posture.get("status")), &mut out);
    out.extend_from_slice(b",\"candidate_limit_reached\":");
    out.extend_from_slice(if is_true(posture.get("candidate_limit_reached")) {
        b"true"
    } else {
        b"false"
    });
    out.extend_from_slice(b",\"runtimes\":");
    write_table(&runtimes, &mut out);
    out.extend_from_slice(b",\"unresolved\":");
    write_table(&unresolved, &mut out);
    out.extend_from_slice(b",\"skipped\":");
    write_strings(&skipped, &mut out);
    // A process left running on a replaced build, and its exit, change what a
    // run reports; processes running the build on disk do not.
    let stale = stale_instances(posture);
    if !stale.is_empty() {
        out.extend_from_slice(b",\"stale_instances\":");
        write_table(&stale, &mut out);
    }
    out.push(b'}');
    Some(hex::encode(Sha256::digest(&out)))
}

/// Byte-identical runtimes at different paths share one artifact, so every
/// path of a matched artifact gets its own finding. A process still running an
/// affected build is reported at the path it was launched from, even once a
/// fixed build sits there.
fn findings(worktree_key: &str, posture: &Row) -> (Vec<Value>, bool) {
    let mut by_artifact: HashMap<&str, Vec<&Row>> = HashMap::new();
    for row in rows(posture.get("runtimes")) {
        if let Some(Value::String(artifact_id)) = row.get("artifact_id") {
            by_artifact
                .entry(artifact_id.as_str())
                .or_default()
                .push(row);
        }
    }
    let locations = by_location(posture);
    let instances = instance_rows(posture);
    let mut seen = HashSet::new();
    let mut findings: Vec<Value> = Vec::new();
    for advisory in rows(posture.get("advisories")) {
        let Some(advisory_id) = text(advisory.get("advisory_id")) else {
            continue;
        };
        let Some(verdict) = advisory
            .get("verdict")
            .and_then(Value::as_str)
            .filter(|verdict| FINDING_VERDICTS.contains(verdict))
        else {
            continue;
        };
        let severity = severity_of(advisory.get("severity"));
        let mut targets: Vec<(&Row, Option<&Value>)> = Vec::new();
        for artifact_id in items(advisory.get("affected_artifact_ids")) {
            if let Some(matched) = by_artifact.get(text_of(Some(artifact_id)).as_str()) {
                targets.extend(matched.iter().map(|&row| (row, row.get("version"))));
            }
        }
        for instance_id in items(advisory.get("affected_instance_ids")) {
            // `{row.get("instance_id"): row}`: the last row with that id wins.
            let Some(instance) = instances
                .iter()
                .rev()
                .find(|row| row.get("instance_id").unwrap_or(&Value::Null) == instance_id)
            else {
                continue;
            };
            let location = text(instance.get("location_id"))
                .and_then(|location_id| locations.get(location_id.as_str()).copied());
            if let Some(location) = location {
                targets.push((location, instance.get("version")));
            }
        }
        for (row, version) in targets {
            let path = text_of(row.get("path"));
            let material = [
                "guard.workspace-finding.v1",
                worktree_key,
                "runtime",
                &advisory_id,
                &path,
            ]
            .join("\0");
            let finding_id = hex::encode(Sha256::digest(material.as_bytes()))[..32].to_owned();
            if !seen.insert(finding_id.clone()) {
                continue;
            }
            findings.push(json!({
                "finding_id": finding_id,
                "source_kind": SOURCE_KIND,
                "detector": DETECTOR,
                "severity": severity,
                // Observation only: a runtime finding never blocks anything.
                "decision": "warn",
                "ecosystem": null,
                "package_name": null,
                "runtime_family": text(row.get("family")),
                "runtime_version": text(version),
                "path": path,
                "rule_ids": [verdict],
                "advisory_ids": [advisory_id],
                "title": text(advisory.get("title")),
                "known_exploited": is_true(advisory.get("known_exploited")),
                "validation_state": "confirmed",
                "lifecycle_state": "open",
            }));
        }
    }
    findings.sort_by_cached_key(sort_key);
    let truncated = findings.len() > MAX_FINDINGS;
    findings.truncate(MAX_FINDINGS);
    (findings, truncated)
}

/// `(not known_exploited, severity rank, str(advisory_ids), path)`.
fn sort_key(finding: &Value) -> (bool, usize, String, String) {
    let severity = finding["severity"].as_str().unwrap_or_default();
    let advisory_id = finding["advisory_ids"][0].as_str().unwrap_or_default();
    (
        finding["known_exploited"] != Value::Bool(true),
        severity_rank(severity).unwrap_or(SEVERITY_RANK.len()),
        format!("[{}]", py_repr(advisory_id)),
        finding["path"].as_str().unwrap_or_default().to_owned(),
    )
}

/// Runtimes the advisories could not be checked against, or a harness whose
/// configuration could not be read, leave the detector incomplete and the run
/// partial, as does a configured launch Guard could not resolve or identify.
/// A workspace whose tools launch nothing has no runtime inputs.
fn with_coverage(coverage: &Row, posture: Option<&Row>) -> Value {
    let mut reasons: Vec<Value> = items(coverage.get("reasons")).to_vec();
    let status = match posture.filter(|posture| !is_unavailable(posture)) {
        None => {
            reasons.push(json!(format!("detector_not_run:{DETECTOR}")));
            "not_run"
        }
        Some(posture) => {
            let runtimes: Vec<&Row> = rows(posture.get("runtimes")).collect();
            let unresolved = rows(posture.get("unresolved_launches")).next().is_some();
            let mut gaps = Vec::new();
            if posture.get("status").and_then(Value::as_str) != Some("ok")
                || unresolved
                || runtimes.iter().any(|row| {
                    !matches!(row.get("artifact_id"), Some(Value::String(_)))
                        || row.get("family").is_none_or(Value::is_null)
                })
                || rows(posture.get("advisories"))
                    .any(|row| row.get("verdict").and_then(Value::as_str) == Some("unknown"))
            {
                gaps.push("runtimes_incomplete");
            }
            // A process Guard could not name, one past the limit, or processes
            // the assessment left out may still run an affected build.
            if let Some(Value::Object(instances)) = posture.get("instances") {
                if is_true(instances.get("enumerated"))
                    && (is_true(instances.get("limit_reached"))
                        || instances.get("unbound_processes").is_some_and(is_truthy)
                        || instances.get("assessed") == Some(&Value::Bool(false)))
                {
                    gaps.push("runtime_instances_incomplete");
                }
            }
            let available = posture
                .get("coverage")
                .and_then(Value::as_object)
                .is_some_and(|coverage| is_true(coverage.get("advisories_available")));
            if !runtimes.is_empty() && !available {
                gaps.push("runtime_advisories_unavailable");
            }
            let status = if !gaps.is_empty() {
                "incomplete"
            } else if !runtimes.is_empty() || unresolved {
                "complete"
            } else {
                "no_inputs"
            };
            reasons.extend(gaps.into_iter().map(Value::from));
            status
        }
    };
    let mut detectors = coverage
        .get("detectors")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    detectors.insert(DETECTOR.to_owned(), json!(status));
    let mut merged = coverage.clone();
    merged.insert(
        "status".to_owned(),
        json!(if reasons.is_empty() {
            "complete"
        } else {
            "partial"
        }),
    );
    merged.insert("reasons".to_owned(), Value::Array(reasons));
    merged.insert("detectors".to_owned(), Value::Object(detectors));
    merged.insert(
        "runtimes".to_owned(),
        json!({
            "digest": posture.and_then(identity_digest),
            "runtime_count": posture.map_or(0, |posture| rows(posture.get("runtimes")).count()),
        }),
    );
    Value::Object(merged)
}

fn stale_instances(posture: &Row) -> Vec<Vec<String>> {
    let locations = by_location(posture);
    let mut stale: Vec<Vec<String>> = instance_rows(posture)
        .into_iter()
        .filter_map(|row| {
            let location = locations.get(text_of(row.get("location_id")).as_str())?;
            let running = row.get("state").and_then(Value::as_str) == Some("running");
            let artifact_id = row.get("artifact_id").unwrap_or(&Value::Null);
            (running && artifact_id != location.get("artifact_id").unwrap_or(&Value::Null))
                .then(|| vec![text_of(location.get("path")), text_of(Some(artifact_id))])
        })
        .collect();
    stale.sort();
    stale
}

/// Runtime rows by `location_id`; the last row with an id wins.
fn by_location(posture: &Row) -> HashMap<&str, &Row> {
    rows(posture.get("runtimes"))
        .filter_map(|row| match row.get("location_id") {
            Some(Value::String(location_id)) => Some((location_id.as_str(), row)),
            _ => None,
        })
        .collect()
}

fn instance_rows(posture: &Row) -> Vec<&Row> {
    match posture.get("instances") {
        Some(Value::Object(instances)) => rows(instances.get("rows")).collect(),
        _ => Vec::new(),
    }
}

fn is_unavailable(posture: &Row) -> bool {
    posture.get("status").and_then(Value::as_str) == Some("unavailable")
}

fn rows(value: Option<&Value>) -> impl Iterator<Item = &Row> {
    items(value).iter().filter_map(Value::as_object)
}

fn items(value: Option<&Value>) -> &[Value] {
    match value {
        Some(Value::Array(items)) => items,
        _ => &[],
    }
}

fn is_true(value: Option<&Value>) -> bool {
    value == Some(&Value::Bool(true))
}

/// `str(value)`, with a missing value read as `None`.
fn text_of(value: Option<&Value>) -> String {
    let value = value.unwrap_or(&Value::Null);
    py_str(value).unwrap_or_else(|| value.to_string())
}

/// A stripped string of at most 256 characters, or nothing.
fn text(value: Option<&Value>) -> Option<String> {
    let stripped = py_strip(value?.as_str()?);
    (!stripped.is_empty()).then(|| stripped.chars().take(MAX_TEXT_CHARS).collect())
}

/// `str(severity or "").lower()`, kept only when it names a known rank.
fn severity_of(value: Option<&Value>) -> &'static str {
    let raw = match value {
        Some(Value::String(severity)) => severity.to_lowercase(),
        Some(other) if is_truthy(other) => text_of(Some(other)).to_lowercase(),
        _ => String::new(),
    };
    severity_rank(&raw).map_or("unknown", |rank| SEVERITY_RANK[rank])
}

fn severity_rank(severity: &str) -> Option<usize> {
    SEVERITY_RANK.iter().position(|known| *known == severity)
}

/// `repr()` of a string: single quotes unless only double quotes avoid an
/// escape, with backslash, quote and control escapes. Other non-ASCII
/// characters are kept, as CPython keeps every printable one.
fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ if character == quote => {
                out.push('\\');
                out.push(quote);
            }
            _ if character.is_control() => {
                let code = u32::from(character);
                if code <= 0xff {
                    out.push_str(&format!("\\x{code:02x}"));
                } else {
                    out.push_str(&format!("\\u{code:04x}"));
                }
            }
            _ => out.push(character),
        }
    }
    out.push(quote);
    out
}

fn write_strings(values: &[String], out: &mut Vec<u8>) {
    out.push(b'[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        write_json_string(value, out);
    }
    out.push(b']');
}

fn write_table(rows: &[Vec<String>], out: &mut Vec<u8>) {
    out.push(b'[');
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        write_strings(row, out);
    }
    out.push(b']');
}

#[cfg(test)]
#[path = "workspace_runtime_findings_tests.rs"]
mod tests;
