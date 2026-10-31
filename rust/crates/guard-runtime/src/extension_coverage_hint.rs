//! Queue-time coverage hint: which extension governs which step of a paused
//! command.
//!
//! The allow hint answers whether enabling a few permissions would let the
//! whole command run, and stays silent whenever the answer is no. This hint
//! answers the weaker question the review screen still needs: which extension
//! matched which step. It is read straight out of the evidence the review
//! already returned, costs no re-review and promises nothing. It carries
//! catalog identifiers and the matched executable basename only.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

pub(crate) const EXTENSION_COVERAGE_HINT_SCHEMA: &str = "guard.extension-coverage-hint.v1";
// A stored coverage hint describes a shell command, which the parser already
// bounds well below these limits; they only stop a malformed payload growing.
const MAX_COVERED_SEGMENTS: usize = 24;
const MAX_SEGMENT_IDS: usize = 12;
const MAX_SEGMENT_TOTAL: usize = 256;
const MAX_SEGMENT_INDEX: u64 = 255;
const ID_KEYS: [&str; 3] = ["extension_ids", "rule_ids", "permission_ids"];

/// One covered step, keyed by its segment index.
#[derive(Default)]
struct Segment {
    executable: Option<String>,
    ids: [Vec<String>; 3],
}

impl Segment {
    fn record(&mut self, executable: Option<&str>, key: usize, value: Option<&str>) {
        if self.executable.is_none() {
            self.executable = executable.map(str::to_owned);
        }
        if let Some(value) = value {
            if !self.ids[key].iter().any(|id| id == value) {
                self.ids[key].push(value.to_owned());
            }
        }
    }
}

/// `_segment_index`: an integer step index in range, never a bool or float.
fn segment_index(value: Option<&Value>) -> Option<u64> {
    value
        .and_then(Value::as_u64)
        .filter(|index| *index <= MAX_SEGMENT_INDEX)
}

/// `_CATALOG_ID`: `command\.[A-Za-z0-9._-]{1,248}`.
fn catalog_id(value: Option<&Value>) -> Option<&str> {
    let text = value?.as_str()?;
    let rest = text.strip_prefix("command.")?;
    ((1..=248).contains(&rest.len())
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    .then_some(text)
}

/// `_EXECUTABLE`: `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}`.
fn executable(value: Option<&Value>) -> Option<&str> {
    let text = value?.as_str()?;
    let mut bytes = text.bytes();
    let first = bytes.next()?;
    (text.len() <= 64
        && first.is_ascii_alphanumeric()
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')))
    .then_some(text)
}

/// `_DIGEST`: 64 lowercase hex characters.
fn digest(value: Option<&Value>) -> Option<&str> {
    let text = value?.as_str()?;
    (text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(text)
}

/// `_evidence_segments`: the segment indexes an observation matched, with the
/// executable each named.
fn evidence_segments(observation: &Map<String, Value>) -> BTreeMap<u64, Option<&str>> {
    let mut found: BTreeMap<u64, Option<&str>> = BTreeMap::new();
    for raw in observation
        .get("effective_segment_indexes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(index) = segment_index(Some(raw)) {
            found.entry(index).or_insert(None);
        }
    }
    for entry in observation
        .get("matcher_evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
    {
        let Some(index) = segment_index(entry.get("segment_index")) else {
            continue;
        };
        let named = executable(entry.get("executable"));
        let slot = found.entry(index).or_insert(None);
        if slot.is_none() {
            *slot = named;
        }
    }
    found
}

/// `_segment_total`: how many steps the command has, when the review
/// modelled them. Covered steps alone cannot tell a one-step command from the
/// first step of three.
fn segment_total(result: &Map<String, Value>) -> Option<usize> {
    let total = result
        .get("command_model")?
        .as_object()?
        .get("segments")?
        .as_array()?
        .len();
    (0 < total && total <= MAX_SEGMENT_TOTAL).then_some(total)
}

/// Which extension matched which step of `result`, or `None` when no extension
/// observed the command at all.
pub(crate) fn compute(result: &Map<String, Value>) -> Option<Value> {
    let evidence = result.get("command_extensions")?.as_object()?;
    if evidence.get("evaluation_error").is_some_and(truthy) {
        return None;
    }
    let catalog_digest = digest(evidence.get("binding")?.get("catalog_digest"))?;
    let mut segments: BTreeMap<u64, Segment> = BTreeMap::new();
    for (source, owned_key, id_key) in [
        ("observations", "rule_id", 1),
        ("permission_observations", "permission_id", 2),
    ] {
        for observation in evidence
            .get(source)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
        {
            let Some(extension_id) = catalog_id(observation.get("extension_id")) else {
                continue;
            };
            let owned = catalog_id(observation.get(owned_key));
            for (index, named) in evidence_segments(observation) {
                let segment = segments.entry(index).or_default();
                segment.record(named, 0, Some(extension_id));
                segment.record(named, id_key, owned);
            }
        }
    }
    let last = *segments.keys().next_back()?;
    if segments.len() > MAX_COVERED_SEGMENTS
        || segments
            .values()
            .any(|segment| segment.ids.iter().any(|ids| ids.len() > MAX_SEGMENT_IDS))
    {
        return None;
    }
    let mut hint = json!({
        "schema": EXTENSION_COVERAGE_HINT_SCHEMA,
        "catalog_digest": catalog_digest,
        "segments": segments
            .into_iter()
            .map(|(index, segment)| {
                let mut fields = Map::new();
                fields.insert("index".to_owned(), json!(index));
                fields.insert("executable".to_owned(), json!(segment.executable));
                for (key, ids) in ID_KEYS.iter().zip(segment.ids) {
                    fields.insert((*key).to_owned(), json!(ids));
                }
                Value::Object(fields)
            })
            .collect::<Vec<_>>(),
    });
    if let Some(total) = segment_total(result) {
        // A total that cannot hold every covered step was measured on another
        // command, so the hint it came with describes nothing this one did.
        if u64::try_from(total).map_or(true, |total| last >= total) {
            return None;
        }
        hint["segment_total"] = json!(total);
    }
    Some(hint)
}

/// `with_extension_coverage`: carry `coverage` on `hint`, or alone when there
/// is no settling hint.
pub(crate) fn with_coverage(hint: Option<Value>, coverage: Option<Value>) -> Option<Value> {
    match (hint, coverage) {
        (hint, None) => hint,
        (None, coverage) => coverage,
        (Some(mut hint), Some(coverage)) => {
            hint.as_object_mut()?
                .insert("coverage".to_owned(), coverage);
            Some(hint)
        }
    }
}

/// Python truthiness for a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

#[cfg(test)]
#[path = "extension_coverage_hint_tests.rs"]
mod tests;
