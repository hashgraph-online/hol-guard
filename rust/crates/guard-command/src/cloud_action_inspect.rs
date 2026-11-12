//! Deterministic content inspection for hosted cloud actions.
//!
//! `cloud-action inspect` reads one request per line and answers what the
//! native detectors found in an action's arguments and result: credentials
//! (the `guard-scanner` secret rules, base64 payloads included), a
//! prompt-injection signal in result text, and a small set of personal-data
//! shapes used only as sensitivity hints. It never decides; the evaluator and
//! the gateway act on what it reports.
//!
//! A finding names where it was found (the source and a JSON Pointer) and
//! which rule matched. It never carries matched bytes: a credential is located
//! by redaction spans, and a key that holds one is reported as its parent.
//! Inspection is total within its bounds; anything past them is refused, and a
//! refused or incomplete inspection tells the caller nothing is known.

use std::collections::BTreeSet;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use guard_contracts::{FindingV2, PiiKindV2, SensitivityV2};
use guard_scanner::secret_detection::{encoded_payload_spans, scan_secret_text, ENCODED_REASON};
use regex::Regex;
use serde_json::{json, Value};

use crate::cloud_action_binding::valid_label;
use crate::cloud_action_canonical::parse_strict;
use crate::cloud_action_inspect_pii::pii_kinds;
use crate::prompt_analysis::detect_prompt_injection_requests;

pub const INSPECT_REQUEST_SCHEMA: &str = "guard.cloud-action-inspection.v1";
pub const INSPECT_RESULT_SCHEMA: &str = "guard.cloud-action-inspection-result.v1";
pub const INSPECTOR_VERSION: u16 = 1;
/// Largest request line `inspect` reads.
pub const MAX_INSPECT_BYTES: usize = 2 * 1024 * 1024;
/// Most string and number values inspected in one request.
pub const MAX_INSPECT_VALUES: usize = 20_000;
/// Wall-clock budget for one request.
pub const INSPECT_DEADLINE: Duration = Duration::from_millis(1_500);
const MAX_FINDINGS: usize = 128;
const MAX_REDACTIONS: usize = 512;
const INJECTION_MIN_CHARS: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Arguments,
    Result,
}

impl Source {
    const fn label(self) -> &'static str {
        match self {
            Self::Arguments => "arguments",
            Self::Result => "result",
        }
    }
}

/// One inspected value: the text a detector reads and where it sits.
struct Leaf<'a> {
    source: Source,
    pointer: String,
    text: std::borrow::Cow<'a, str>,
    /// A key at this pointer held a credential, so the whole value is redacted.
    key: bool,
}

#[derive(Default)]
struct Report {
    findings: Vec<Value>,
    facts: BTreeSet<FindingV2>,
    pii: BTreeSet<PiiKindV2>,
    redactions: Vec<Value>,
    complete: bool,
}

impl Report {
    fn finding(&mut self, finding: Value) {
        if self.findings.len() < MAX_FINDINGS {
            self.findings.push(finding);
        } else {
            self.complete = false;
        }
    }

    fn redact(&mut self, leaf: &Leaf<'_>, span: Option<(usize, usize)>) {
        if self.redactions.len() >= MAX_REDACTIONS {
            // A result whose credentials cannot all be located must not be
            // delivered as if they were.
            self.complete = false;
            return;
        }
        let span = span.map(|(start, end)| {
            json!({
                "utf8": [start, end],
                "utf16": [utf16_offset(&leaf.text, start), utf16_offset(&leaf.text, end)],
            })
        });
        self.redactions.push(json!({
            "source": leaf.source.label(),
            "path": leaf.pointer,
            "span": span,
        }));
    }
}

/// Inspect one request line and answer one result value.
pub fn inspect(line: &[u8]) -> Value {
    inspect_until(line, Instant::now() + INSPECT_DEADLINE)
}

/// [`inspect`] with an explicit deadline.
pub fn inspect_until(line: &[u8], deadline: Instant) -> Value {
    if line.len() > MAX_INSPECT_BYTES {
        return inspect_error(None, "limit");
    }
    let parsed = match parse_strict(line) {
        Ok(value) => value,
        Err(error) => return inspect_error(None, error.code()),
    };
    let request_id = parsed
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|id| valid_label(id))
        .map(str::to_owned);
    let id = request_id.as_deref();
    if parsed.get("schema").and_then(Value::as_str) != Some(INSPECT_REQUEST_SCHEMA) {
        return inspect_error(id, "unsupported_version");
    }
    let Some(object) = parsed.as_object() else {
        return inspect_error(id, "invalid_request");
    };
    let known = ["schema", "request_id", "arguments", "result"];
    if request_id.is_none()
        || object.keys().any(|key| !known.contains(&key.as_str()))
        || !object.contains_key("arguments")
        || !object.contains_key("result")
    {
        return inspect_error(id, "invalid_request");
    }
    let mut leaves = Vec::new();
    for (source, value) in [
        (Source::Arguments, &object["arguments"]),
        (Source::Result, &object["result"]),
    ] {
        if collect(source, value, &mut leaves).is_err() {
            return inspect_error(id, "limit");
        }
    }
    let mut report = Report {
        complete: true,
        ..Report::default()
    };
    for source in [Source::Arguments, Source::Result] {
        if Instant::now() >= deadline {
            return inspect_error(id, "deadline");
        }
        inspect_source(source, &leaves, &mut report);
    }
    for leaf in leaves.iter().filter(|leaf| leaf.source == Source::Result) {
        if Instant::now() >= deadline {
            return inspect_error(id, "deadline");
        }
        if !leaf.key
            && leaf.text.chars().count() >= INJECTION_MIN_CHARS
            && injection_signal(&leaf.text)
        {
            report.facts.insert(FindingV2::InjectionSignalInResult);
            report.finding(json!({
                "kind": "injection_signal",
                "source": leaf.source.label(),
                "path": leaf.pointer,
                "signal": "prompt_injection_intent",
            }));
        }
    }
    if Instant::now() >= deadline {
        return inspect_error(id, "deadline");
    }
    let mut sensitivity = BTreeSet::new();
    if !report.pii.is_empty() {
        sensitivity.insert(SensitivityV2::Personal);
    }
    if report.facts.contains(&FindingV2::SecretInArguments)
        || report.facts.contains(&FindingV2::SecretInResult)
    {
        sensitivity.insert(SensitivityV2::Secret);
    }
    json!({
        "schema": INSPECT_RESULT_SCHEMA,
        "request_id": request_id,
        "error": null,
        "complete": report.complete,
        "findings": report.findings,
        "fact_findings": report.facts,
        "pii_kinds": report.pii,
        "sensitivity_hints": sensitivity,
        "redactions": report.redactions,
        "provenance": provenance(),
    })
}

/// A refusal: nothing was inspected, so nothing is known.
pub fn inspect_error(request_id: Option<&str>, code: &str) -> Value {
    json!({
        "schema": INSPECT_RESULT_SCHEMA,
        "request_id": request_id,
        "error": {"code": code},
        "complete": false,
        "findings": [],
        "fact_findings": [],
        "pii_kinds": [],
        "sensitivity_hints": [],
        "redactions": [],
        "provenance": provenance(),
    })
}

fn provenance() -> Value {
    json!({
        "inspector_version": INSPECTOR_VERSION,
        "secret_detector_version": guard_scanner::secret_detection::detector_version(),
    })
}

fn collect<'a>(source: Source, root: &'a Value, leaves: &mut Vec<Leaf<'a>>) -> Result<(), ()> {
    let mut stack: Vec<(String, &'a Value)> = vec![(String::new(), root)];
    while let Some((pointer, value)) = stack.pop() {
        let text = match value {
            Value::String(text) => std::borrow::Cow::Borrowed(text.as_str()),
            Value::Number(number) => std::borrow::Cow::Owned(number.to_string()),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate().rev() {
                    stack.push((format!("{pointer}/{index}"), item));
                }
                continue;
            }
            Value::Object(map) => {
                for (key, item) in map.iter().rev() {
                    if holds_secret(key) {
                        // Never echo the key; the parent value goes whole.
                        push(leaves, source, pointer.clone(), "".into(), true)?;
                        continue;
                    }
                    stack.push((format!("{pointer}/{}", escape_pointer(key)), item));
                }
                continue;
            }
            Value::Null | Value::Bool(_) => continue,
        };
        push(leaves, source, pointer, text, false)?;
    }
    Ok(())
}

fn push<'a>(
    leaves: &mut Vec<Leaf<'a>>,
    source: Source,
    pointer: String,
    text: std::borrow::Cow<'a, str>,
    key: bool,
) -> Result<(), ()> {
    if leaves.len() >= MAX_INSPECT_VALUES {
        return Err(());
    }
    leaves.push(Leaf {
        source,
        pointer,
        text,
        key,
    });
    Ok(())
}

/// Keys shorter than this cannot hold any provider credential format.
const MIN_SECRET_KEY_CHARS: usize = 16;

fn holds_secret(key: &str) -> bool {
    key.len() >= MIN_SECRET_KEY_CHARS && confident_secrets(key)
}

/// Whether `text` holds a credential worth acting on. Low-confidence entropy
/// guesses do not count, because a secret in outbound arguments blocks the
/// action.
fn confident_secrets(text: &str) -> bool {
    let mut summary = scan_secret_text(text, "", "cloud_action", None, 4);
    let found = summary
        .findings
        .iter()
        .any(|finding| finding.confidence != "low");
    for finding in &mut summary.findings {
        finding.scrub_candidate();
    }
    found
}

/// Separates values in the joined text a source is scanned as. A blank line
/// ends every line-based and wrapped-payload reading, so nothing a detector
/// matches runs from one value into the next.
const VALUE_SEPARATOR: &str = "\n\n";
/// Credential findings read from one source's joined text.
const MAX_SECRETS_PER_SOURCE: usize = 256;

/// Credentials and personal data for one source. The detectors read every
/// value of the source at once, joined, and each credential found is then
/// located in the values that hold it.
fn inspect_source(source: Source, leaves: &[Leaf<'_>], report: &mut Report) {
    let secret_fact = match source {
        Source::Arguments => FindingV2::SecretInArguments,
        Source::Result => FindingV2::SecretInResult,
    };
    let values: Vec<&Leaf<'_>> = leaves.iter().filter(|leaf| leaf.source == source).collect();
    for leaf in values.iter().filter(|leaf| leaf.key) {
        report.facts.insert(secret_fact);
        report.finding(secret_finding(
            leaf,
            "secret_in_key",
            "credential",
            "high",
            "high",
        ));
        report.redact(leaf, None);
    }
    let texts: Vec<&Leaf<'_>> = values.into_iter().filter(|leaf| !leaf.key).collect();
    if texts.is_empty() {
        return;
    }
    let joined = texts
        .iter()
        .map(|leaf| leaf.text.as_ref())
        .collect::<Vec<_>>()
        .join(VALUE_SEPARATOR);
    report.pii.extend(pii_kinds(&joined));
    let mut summary = scan_secret_text(&joined, "", "cloud_action", None, MAX_SECRETS_PER_SOURCE);
    drop(joined);
    if summary.findings.len() >= MAX_SECRETS_PER_SOURCE {
        report.complete = false;
    }
    summary
        .findings
        .retain(|finding| finding.confidence != "low");
    let mut spans: Vec<Vec<(usize, usize)>> = vec![Vec::new(); texts.len()];
    let mut seen = BTreeSet::new();
    for mut finding in summary.findings {
        report.facts.insert(secret_fact);
        let candidate = finding.candidate.as_str();
        let encoded = finding.context_reasons.contains(&ENCODED_REASON);
        let mut located = false;
        for (index, leaf) in texts.iter().enumerate() {
            let text = leaf.text.as_ref();
            let before = spans[index].len();
            spans[index].extend(
                text.match_indices(candidate)
                    .map(|(start, matched)| (start, start + matched.len())),
            );
            if encoded && spans[index].len() == before {
                spans[index].extend(encoded_payload_spans(text, candidate));
            }
            if spans[index].len() > before {
                located = true;
                if seen.insert((index, finding.rule_id)) {
                    report.finding(secret_finding(
                        leaf,
                        finding.rule_id,
                        finding.family,
                        finding.severity,
                        finding.confidence,
                    ));
                }
            }
        }
        // A credential no single value holds cannot be redacted in place.
        if !located {
            report.complete = false;
        }
        finding.scrub_candidate();
    }
    for (leaf, leaf_spans) in texts.iter().zip(spans) {
        for span in merge(leaf_spans) {
            report.redact(leaf, Some(span));
        }
    }
}

fn secret_finding(
    leaf: &Leaf<'_>,
    rule_id: &str,
    family: &str,
    severity: &str,
    confidence: &str,
) -> Value {
    json!({
        "kind": "secret",
        "source": leaf.source.label(),
        "path": leaf.pointer,
        "rule_id": rule_id,
        "family": family,
        "severity": severity,
        "confidence": confidence,
    })
}

/// Words every injection pattern below needs; text without one is skipped.
static INJECTION_PREFILTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)ignor|disregard|forget|overrid|tell|notify|inform|alert|hide|when\s+you")
        .expect("injection prefilter")
});

/// Instructions aimed at whoever reads a tool result. Prompt-side detection
/// reads what a user typed; a result is written by someone else, so an
/// instruction there to drop earlier instructions is the signal itself.
static RESULT_INJECTION: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:(?:all|any|every|the|your|my|these|those|of)\s+){0,3}(?:previous|prior|earlier|above|preceding|original|system|initial)\s+(?:instructions?|prompts?|directions?|directives?|rules?)\b",
        r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+|your\s+)?(?:instructions?|directions?)\s+(?:above|before)\b",
        r"(?i)\b(?:ignore|disregard)\s+everything\s+(?:above|before)\b",
        r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:the\s+|your\s+)?(?:system\s+prompt|instructions|training)\b",
        r"(?i)\bwhen\s+you\s+(?:read|access|open|process|summari[sz]e)\s+.{0,60}(?:also|then|and)\s+(?:send|post|upload|forward)\b",
    ]
    .into_iter()
    .map(|pattern| Regex::new(pattern).expect("result injection pattern"))
    .collect()
});

/// A signal only, never a verdict: the native prompt-injection detection plus
/// the result patterns. A detector error counts as a signal so a crafted text
/// cannot hide behind it.
fn injection_signal(text: &str) -> bool {
    if !INJECTION_PREFILTER.is_match(text) {
        return false;
    }
    if RESULT_INJECTION
        .iter()
        .any(|pattern| pattern.is_match(text))
    {
        return true;
    }
    match detect_prompt_injection_requests(text) {
        Ok(requests) => requests
            .iter()
            .any(|request| request.request_class == "prompt_injection_intent"),
        Err(_) => true,
    }
}

fn merge(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn escape_pointer(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn utf16_offset(text: &str, byte: usize) -> usize {
    text.get(..byte)
        .map_or(0, |prefix| prefix.encode_utf16().count())
}
