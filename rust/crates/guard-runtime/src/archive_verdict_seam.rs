//! Maps the caller-reported archive inspection verdict onto the shape the
//! evaluation expects from its native-archive seam.
//!
//! The caller downloads the blob and runs the sandboxed offline inspector; the
//! resident only reads back the verdict recorded for the digest it was handed.
//! A missing, unknown-status or oversized verdict is treated as no verdict, so
//! the archive stays uninspected.

use serde_json::{Map, Value};

const MAX_VERDICT_TEXT_BYTES: usize = 512;

/// The verdict the caller reported for `expected_sha256`, as the evaluation's
/// inspection result, or `None` when there is none or it is not well formed.
pub(crate) fn reported_archive_verdict(expected_sha256: &str) -> Option<Map<String, Value>> {
    let verdict = guard_command::egress_broker::supplied_inspection(expected_sha256)?;
    if !matches!(verdict.status.as_str(), "clean" | "blocked" | "incomplete")
        || ![&verdict.code, &verdict.message, &verdict.severity]
            .iter()
            .all(|text| text.len() <= MAX_VERDICT_TEXT_BYTES)
    {
        return None;
    }
    let mut result = Map::new();
    result.insert("status".into(), Value::String(verdict.status));
    result.insert("code".into(), Value::String(verdict.code));
    result.insert("message".into(), Value::String(verdict.message));
    result.insert("severity".into(), Value::String(verdict.severity));
    result.insert("sha256".into(), Value::String(expected_sha256.to_owned()));
    Some(result)
}
