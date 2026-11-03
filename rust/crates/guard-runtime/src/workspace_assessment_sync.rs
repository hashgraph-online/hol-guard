//! `workspace_assessment_build` and `workspace_assessment_fit`
//! runner-authority kinds: the workspace assessment summary for the receipts
//! sync context.
//!
//! Guard Cloud gets one bounded summary per admitted worktree: its status, the
//! latest assessed run's coverage, and the package-coordinate findings that
//! run observed. Local keys are plain digests of absolute paths, so every
//! identifier that leaves the machine is re-keyed with the per-install secret;
//! roots, commits and file names never do. The summary is sent again only when
//! it changes or a day has passed.
//!
//! Python reads the store and answers, in matching order, the selected
//! worktrees, each one's newest run and its newest assessed run. Sizes and the
//! digest are those CPython's `json.dumps` gives, so a summary built here
//! matches the one the earlier Python build recorded as delivered.

use guard_runtime_pyjson::float_repr;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::cloud_request_text::py_truthy;
use crate::guard_store_json::{py_prefix, py_str};
use crate::guard_store_local_cli::parse_utc;
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const SCHEMA_VERSION: &str = "guard.workspace-assessment-sync.v1";
/// Python selects at most 50 worktrees; anything past this is refused.
const MAX_INPUT_WORKTREES: usize = 1000;
const MAX_FINDINGS_PER_WORKTREE: usize = 100;
const RESEND_AFTER_MICROS: i64 = 24 * 60 * 60 * 1_000_000;
/// `RUNTIME_SOURCE_KIND`: findings Guard read from the agent inventory.
const RUNTIME_SOURCE_KIND: &str = "agent_inventory";
const FINDING_FIELDS: [(&str, &str); 10] = [
    ("source_kind", "sourceKind"),
    ("detector", "detector"),
    ("severity", "severity"),
    ("decision", "decision"),
    ("ecosystem", "ecosystem"),
    ("package_name", "packageName"),
    ("package_version", "packageVersion"),
    ("fix_version", "fixVersion"),
    ("validation_state", "validationState"),
    ("lifecycle_state", "lifecycleState"),
];

/// `keyed_digest`: an HMAC under the per-install secret, so guessable paths
/// cannot be reversed by a dictionary search.
fn keyed_digest(key: &[u8], text: &str) -> String {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(text.as_bytes());
    format!("sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

/// `str(value)`, as the summary reads every identifier and label.
fn text(value: Option<&Value>) -> String {
    py_str(value.unwrap_or(&Value::Null)).unwrap_or_default()
}

fn list(value: Option<&Value>) -> &[Value] {
    value.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// `[str(item)[:width] for item in value][:count]`.
fn labels(value: Option<&Value>, width: usize, count: usize) -> Value {
    list(value)
        .iter()
        .take(count)
        .map(|item| Value::from(py_prefix(&text(Some(item)), width)))
        .collect()
}

/// `_generation`: a non-negative integer, else 0.
fn generation(value: Option<&Value>) -> Value {
    Value::from(value.and_then(Value::as_u64).unwrap_or(0))
}

/// `_iso`: milliseconds since the epoch as UTC ISO-8601 with a `Z` suffix.
/// Only a non-negative integer converts; one past the calendar fails the
/// build, as `datetime.fromtimestamp` raised.
fn iso(value: Option<&Value>) -> Result<Value, &'static str> {
    let Some(millis) = value.and_then(Value::as_u64) else {
        return Ok(Value::Null);
    };
    i64::try_from(millis)
        .ok()
        .and_then(|millis| millis.checked_mul(1000))
        .and_then(|micros| micros_to_utc_isoformat(micros, "Z"))
        .map(Value::from)
        .ok_or(ERR_INVALID)
}

/// `worktree_status`.
fn status(worktree: &Value, latest: &Value, assessed: &Value) -> &'static str {
    if worktree.get("paused").is_some_and(py_truthy) {
        return "paused";
    }
    match latest.get("state").and_then(Value::as_str) {
        Some("running") => return "running",
        Some("queued") => return "queued",
        Some("failed") => return "failed",
        _ => {}
    }
    if assessed.is_null() {
        return "pending";
    }
    if worktree.get("stale").is_some_and(py_truthy) {
        return "stale";
    }
    if assessed.get("state").and_then(Value::as_str) == Some("partial") {
        "partial"
    } else {
        "fresh"
    }
}

fn finding(item: &Map<String, Value>, key: &[u8]) -> Value {
    let mut finding = Map::new();
    finding.insert(
        "findingKey".to_owned(),
        Value::from(keyed_digest(
            key,
            &format!("guard.workspace.finding\0{}", text(item.get("finding_id"))),
        )),
    );
    for (source, target) in FINDING_FIELDS {
        let value = match item.get(source) {
            Some(Value::String(value)) => Value::from(py_prefix(value, 256)),
            _ => Value::Null,
        };
        finding.insert(target.to_owned(), value);
    }
    // The digest fleet posture reports for the same runtime path, so Cloud can
    // match the two. It is keyed like every other identifier here; the path
    // itself stays on this machine.
    if item.get("source_kind").and_then(Value::as_str) == Some(RUNTIME_SOURCE_KIND) {
        if let Some(path) = item
            .get("path")
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty())
        {
            finding.insert(
                "locationHash".to_owned(),
                Value::from(keyed_digest(key, path)),
            );
        }
    }
    finding.insert("ruleIds".to_owned(), labels(item.get("rule_ids"), 128, 32));
    finding.insert(
        "advisoryIds".to_owned(),
        labels(item.get("advisory_ids"), 256, 32),
    );
    Value::Object(finding)
}

fn assessment(run: &Value, key: &[u8]) -> Result<Value, &'static str> {
    let empty = Map::new();
    let coverage = run
        .get("coverage")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let detectors: Map<String, Value> = coverage
        .get("detectors")
        .and_then(Value::as_object)
        .map(|detectors| {
            detectors
                .iter()
                .map(|(name, state)| {
                    (
                        py_prefix(name, 64),
                        Value::from(py_prefix(&text(Some(state)), 32)),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let run_id = run.get("run_id").ok_or(ERR_INVALID)?;
    // The stored digest mixes in root-derived keys and Git identity; it is
    // re-keyed like the rest. The contract carries this one as bare hex.
    let snapshot = keyed_digest(
        key,
        &format!(
            "guard.workspace.snapshot\0{}",
            text(run.get("snapshot_digest"))
        ),
    );
    let coverage_status = if coverage.get("status").and_then(Value::as_str) == Some("complete") {
        "complete"
    } else {
        "partial"
    };
    Ok(json!({
        "runKey": keyed_digest(key, &format!("guard.workspace.run\0{}", text(Some(run_id)))),
        "kind": run.get("kind").cloned().unwrap_or(Value::Null),
        "trigger": run.get("trigger_kind").cloned().unwrap_or(Value::Null),
        "state": run.get("state").cloned().unwrap_or(Value::Null),
        "snapshotDigest": snapshot.strip_prefix("sha256:").unwrap_or(&snapshot),
        "coverage": {
            "status": coverage_status,
            "reasons": labels(coverage.get("reasons"), 128, 32),
            "detectors": detectors,
        },
        "startedAt": iso(run.get("started_at_ms"))?,
        "finishedAt": iso(run.get("finished_at_ms"))?,
    }))
}

/// `_worktree_entry`.
fn worktree_entry(
    worktree: &Value,
    latest: &Value,
    assessed: &Value,
    key: &[u8],
) -> Result<Value, &'static str> {
    let codebase = worktree.get("codebase_key").ok_or(ERR_INVALID)?;
    let tree = worktree.get("worktree_key").ok_or(ERR_INVALID)?;
    let mut entry = json!({
        "codebaseKey": keyed_digest(key, &format!("guard.workspace.codebase\0{}", text(Some(codebase)))),
        "worktreeKey": keyed_digest(key, &format!("guard.workspace.worktree\0{}", text(Some(tree)))),
        "status": status(worktree, latest, assessed),
        "dirtyGeneration": generation(worktree.get("dirty_generation")),
        "lastCompletedGeneration": generation(worktree.get("last_completed_generation")),
        "assessment": null,
        "findings": [],
        "findingsTruncated": false,
    });
    if assessed.is_null() {
        return Ok(entry);
    }
    entry["assessment"] = assessment(assessed, key)?;
    // A finding carried from an earlier run was not observed by this one.
    // Cloud already holds it from the run that did, and a partial run never
    // closes it, so sending it again would only make it look freshly seen.
    let findings: Vec<&Map<String, Value>> = list(assessed.get("findings"))
        .iter()
        .filter_map(Value::as_object)
        .filter(|item| !item.get("carried_from_run_id").is_some_and(py_truthy))
        .collect();
    let capped = findings.len() > MAX_FINDINGS_PER_WORKTREE;
    let reasons = assessed
        .get("coverage")
        .and_then(|coverage| coverage.get("reasons"));
    let hit_cap = list(reasons)
        .iter()
        .any(|reason| reason.as_str() == Some("finding_cap"));
    entry["findings"] = findings
        .into_iter()
        .take(MAX_FINDINGS_PER_WORKTREE)
        .map(|item| finding(item, key))
        .collect();
    entry["findingsTruncated"] = Value::Bool(capped || hit_cap);
    Ok(entry)
}

/// A JSON string as CPython's `json.dumps` writes it with `ensure_ascii`:
/// DEL and everything above it as lowercase `\uXXXX`, surrogate pairs past
/// the BMP.
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            _ => {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out.push('"');
}

fn write_number(number: &Number, out: &mut String) {
    match number.as_f64().filter(|_| number.is_f64()) {
        Some(float) => out.push_str(&float_repr(float)),
        None => out.push_str(&number.to_string()),
    }
}

/// CPython `json.dumps(value, sort_keys=True, separators=separators)` with
/// `ensure_ascii`; key order never changes a size.
fn write_json(value: &Value, separators: (&str, &str), out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(number, out),
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(separators.0);
                }
                write_json(item, separators, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push_str(separators.0);
                }
                write_string(key, out);
                out.push_str(separators.1);
                write_json(&map[key], separators, out);
            }
            out.push('}');
        }
    }
}

/// `len(json.dumps(value).encode("utf-8"))` with the default separators.
fn dumps_len(value: &Value) -> usize {
    let mut out = String::new();
    write_json(value, (", ", ": "), &mut out);
    out.len()
}

/// `_digest`: SHA-256 of the sorted, compact entries.
fn digest(entries: &[Value]) -> String {
    let mut out = String::new();
    write_json(&Value::Array(entries.to_vec()), (",", ":"), &mut out);
    hex::encode(Sha256::digest(out.as_bytes()))
}

fn findings_len(entry: &Value) -> usize {
    entry
        .get("findings")
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

/// `_coverage`: an entry's coverage when it has a reasons list and a
/// detector map.
fn coverage_mut(entry: &mut Value) -> Option<&mut Map<String, Value>> {
    let coverage = entry
        .get_mut("assessment")?
        .get_mut("coverage")?
        .as_object_mut()?;
    (coverage.get("reasons").is_some_and(Value::is_array)
        && coverage.get("detectors").is_some_and(Value::is_object))
    .then_some(coverage)
}

fn field_len(entry: &mut Value, field: &str) -> Option<usize> {
    match coverage_mut(entry)?.get(field)? {
        Value::Array(items) => Some(items.len()),
        Value::Object(map) => Some(map.len()),
        _ => Some(0),
    }
}

/// The summary's entries, with each one's serialized size kept current.
struct Budget {
    /// The payload's size with an empty `worktrees` list, less that `[]`.
    base: usize,
    entries: Vec<Value>,
    sizes: Vec<usize>,
}

impl Budget {
    fn new(payload: &Map<String, Value>, entries: Vec<Value>) -> Self {
        let mut shell = payload.clone();
        shell.insert("worktrees".to_owned(), Value::Array(Vec::new()));
        let sizes = entries.iter().map(dumps_len).collect();
        Self {
            base: dumps_len(&Value::Object(shell)) - 2,
            entries,
            sizes,
        }
    }

    fn size(&self) -> usize {
        let separators = 2 * self.sizes.len().saturating_sub(1);
        self.base + 2 + self.sizes.iter().sum::<usize>() + separators
    }

    fn truncated(&mut self, index: usize) {
        self.entries[index]["findingsTruncated"] = Value::Bool(true);
        self.sizes[index] = dumps_len(&self.entries[index]);
    }

    /// `_fit_budget`: shrink the entries until the payload fits `limit`.
    ///
    /// Findings go first, lowest-ranked first. Coverage reasons and detector
    /// states follow, and trailing worktrees are dropped last. Any entry that
    /// loses findings or coverage detail is flagged `findingsTruncated` so the
    /// receiver never closes findings against it. The caller checks the final
    /// size: an empty list may still not fit.
    fn fit(&mut self, limit: usize) {
        while self.size() > limit {
            if let Some(index) =
                first_max(self.entries.iter().map(|entry| Some(findings_len(entry))))
            {
                if let Some(findings) = self.entries[index]
                    .get_mut("findings")
                    .and_then(Value::as_array_mut)
                    .filter(|findings| !findings.is_empty())
                {
                    let drop = (findings.len() / 4).max(1);
                    findings.truncate(findings.len() - drop);
                    self.truncated(index);
                    continue;
                }
            }
            if self.trim_coverage() {
                continue;
            }
            if self.entries.pop().is_none() {
                return;
            }
            self.sizes.pop();
        }
    }

    /// `_trim_coverage`: halve the longest reasons list, then the largest
    /// detector map. False when both are empty. A detector map keeps its
    /// first half in key order.
    fn trim_coverage(&mut self) -> bool {
        for field in ["reasons", "detectors"] {
            let lengths: Vec<Option<usize>> = self
                .entries
                .iter_mut()
                .map(|entry| field_len(entry, field))
                .collect();
            let Some(index) = first_max(lengths.into_iter()) else {
                continue;
            };
            let Some(coverage) = coverage_mut(&mut self.entries[index]) else {
                continue;
            };
            let Some(values) = coverage.get_mut(field) else {
                continue;
            };
            match values {
                Value::Array(items) if !items.is_empty() => items.truncate(items.len() / 2),
                Value::Object(map) if !map.is_empty() => {
                    let half = map.len() / 2;
                    *map = std::mem::take(map).into_iter().take(half).collect();
                }
                _ => continue,
            }
            self.truncated(index);
            return true;
        }
        false
    }
}

/// The first index holding the largest value, as Python's `max` picks it;
/// `None` entries take no part.
fn first_max(values: impl Iterator<Item = Option<usize>>) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None;
    for (index, value) in values.enumerate() {
        if let Some(value) = value {
            if best.is_none_or(|(_, largest)| value > largest) {
                best = Some((index, value));
            }
        }
    }
    best.map(|(index, _)| index)
}

/// `_due`: a changed summary is sent now, an unchanged one after a day.
fn due(delivery: Option<&Value>, digest: &str, now: &str) -> bool {
    let Some(delivery) = delivery.filter(|delivery| delivery.is_object()) else {
        return true;
    };
    if delivery.get("digest").and_then(Value::as_str) != Some(digest) {
        return true;
    }
    let sent = delivery
        .get("sent_at")
        .filter(|value| value.is_string())
        .and_then(parse_utc);
    match (sent, parse_utc(&Value::from(now))) {
        (Some(sent), Some(current)) => current - sent >= RESEND_AFTER_MICROS,
        _ => true,
    }
}

fn max_bytes(args: &Map<String, Value>) -> Result<usize, &'static str> {
    let value = args.get("max_bytes").ok_or(ERR_INVALID)?;
    if let Some(bytes) = value.as_u64() {
        return Ok(usize::try_from(bytes).unwrap_or(usize::MAX));
    }
    // A request whose other parts already overrun leaves no room at all.
    value.as_i64().map(|_| 0).ok_or(ERR_INVALID)
}

fn aligned<'a>(
    args: &'a Map<String, Value>,
    key: &str,
    len: usize,
) -> Result<&'a [Value], &'static str> {
    let values = args.get(key).and_then(Value::as_array).ok_or(ERR_INVALID)?;
    if values.len() != len {
        return Err(ERR_INVALID);
    }
    Ok(values)
}

fn answer(mut payload: Map<String, Value>, budget: Budget, digest: String) -> Value {
    payload.insert("worktrees".to_owned(), Value::Array(budget.entries));
    json!({ "payload": payload, "digest": digest })
}

/// `build_workspace_assessment_sync`: the summary to send, or a null payload
/// when nothing fits or nothing changed.
fn build(args: &Map<String, Value>) -> KindResult {
    let key = args
        .get("hash_key")
        .and_then(Value::as_str)
        .filter(|key| key.len() >= 32)
        .ok_or(ERR_INVALID)?
        .as_bytes();
    let now = args.get("now").and_then(Value::as_str).ok_or(ERR_INVALID)?;
    let worktrees = args
        .get("worktrees")
        .and_then(Value::as_array)
        .filter(|worktrees| worktrees.len() <= MAX_INPUT_WORKTREES)
        .ok_or(ERR_INVALID)?;
    let latest = aligned(args, "latest_runs", worktrees.len())?;
    let assessed = aligned(args, "assessed_runs", worktrees.len())?;
    let limit = max_bytes(args)?;
    let entries = worktrees
        .iter()
        .zip(latest)
        .zip(assessed)
        .map(|((worktree, latest), assessed)| worktree_entry(worktree, latest, assessed, key))
        .collect::<Result<Vec<_>, _>>()?;
    let mut payload = Map::new();
    payload.insert("schemaVersion".to_owned(), Value::from(SCHEMA_VERSION));
    payload.insert("generatedAt".to_owned(), Value::from(now));
    let mut budget = Budget::new(&payload, entries);
    budget.fit(limit);
    if budget.entries.is_empty() {
        return Ok(json!({ "payload": null }));
    }
    let digest = digest(&budget.entries);
    if !due(args.get("delivery"), &digest, now) {
        return Ok(json!({ "payload": null }));
    }
    Ok(answer(payload, budget, digest))
}

/// `fit_workspace_assessment_to_request`: a copy whose serialized payload
/// fits `max_bytes`, or a null payload if it cannot.
///
/// The digest is that of what this request carries. When anything was
/// trimmed it no longer matches the full summary, so the next sync sends the
/// full summary again instead of treating the trimmed delivery as current for
/// a day.
fn fit(args: &Map<String, Value>) -> KindResult {
    let mut payload = args
        .get("payload")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?
        .clone();
    let limit = max_bytes(args)?;
    let Some(Value::Array(entries)) = payload.remove("worktrees") else {
        return Ok(json!({ "payload": null }));
    };
    let mut budget = Budget::new(&payload, entries);
    budget.fit(limit);
    if budget.entries.is_empty() || budget.size() > limit {
        return Ok(json!({ "payload": null }));
    }
    let digest = digest(&budget.entries);
    Ok(answer(payload, budget, digest))
}

pub(crate) fn dispatch(kind: &str, args: &Value) -> KindResult {
    let args = args_object(args)?;
    match kind {
        "workspace_assessment_build" => build(args),
        "workspace_assessment_fit" => fit(args),
        _ => Err(ERR_INVALID),
    }
}

#[cfg(test)]
#[path = "workspace_assessment_sync_tests.rs"]
mod tests;
