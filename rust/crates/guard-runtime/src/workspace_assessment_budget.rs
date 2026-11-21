//! The byte budget of the workspace assessment summary: entries shrink,
//! findings first, until the payload's CPython `json.dumps` size fits.

use serde_json::{Map, Value};

use crate::guard_store_json::dumps_default;

/// `len(json.dumps(value).encode("utf-8"))` with the default separators;
/// key order never changes a size.
pub(super) fn dumps_len(value: &Value) -> usize {
    dumps_default(value).map_or(usize::MAX, |text| text.len())
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
pub(super) struct Budget {
    /// The payload's size with an empty `worktrees` list, less that `[]`.
    base: usize,
    pub(super) entries: Vec<Value>,
    sizes: Vec<usize>,
}

impl Budget {
    pub(super) fn new(payload: &Map<String, Value>, entries: Vec<Value>) -> Self {
        let mut shell = payload.clone();
        shell.insert("worktrees".to_owned(), Value::Array(Vec::new()));
        let sizes = entries.iter().map(dumps_len).collect();
        Self {
            base: dumps_len(&Value::Object(shell)) - 2,
            entries,
            sizes,
        }
    }

    pub(super) fn size(&self) -> usize {
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
    pub(super) fn fit(&mut self, limit: usize) {
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
