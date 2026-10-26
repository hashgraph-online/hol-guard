use super::*;

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

/// `round()` — Python banker's rounding (round-half-to-even) to integer.
pub(super) fn py_round(value: f64) -> i64 {
    if !value.is_finite() {
        return 0;
    }
    let floor = value.floor();
    let diff = value - floor;
    let base = floor as i64;
    if diff < 0.5 {
        base
    } else if diff > 0.5 {
        base + 1
    } else if base % 2 == 0 {
        base
    } else {
        base + 1
    }
}

/// `getattr(artifact, key, None)` returning a `&str` for a JSON object mirror.
pub(super) fn a_str<'a>(artifact: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    artifact.get(key).and_then(Value::as_str)
}

/// `metadata.get(key)` → non-empty `str` or `None` (`_metadata_string`).
pub(super) fn meta_str<'a>(metadata: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    metadata
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

pub(super) fn run_meta(run: &Map<String, Value>) -> Option<&Map<String, Value>> {
    run.get("metadata").and_then(Value::as_object)
}

pub(super) fn run_findings(run: &Map<String, Value>) -> &[Value] {
    run.get("findings")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// `getattr(finding, key, None)` on a finding `Map`.
pub(super) fn finding_str<'a>(finding: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    finding.get(key).and_then(Value::as_str)
}

/// `_metadata_string(metadata, key)`
pub fn _metadata_string<'a>(metadata: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    meta_str(metadata, key)
}
