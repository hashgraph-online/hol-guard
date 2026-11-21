//! `GET /v1/evidence/export`, answered as the daemon answers it: up to
//! 10,000 evidence rows without details, redacted as
//! `store_evidence.export_evidence_payload` redacts them, written as
//! `export_evidence_json` or `export_evidence_csv` writes them.

use serde_json::{json, Value};

use super::super::super::http::query_value;
use super::{page_items, NativeReads, ReadConfig, FIELDS};

/// `store_evidence.EXPORT_PRIVACY_WARNING`.
const PRIVACY_WARNING: &str = "Evidence exports redact detector details, local user paths, and token-like values. Review the file before sharing it outside your team.";
const EXPORT_LIMIT: i64 = 10_000;

/// What the route writes: an export body with its content type, or the
/// daemon's JSON error.
#[derive(Debug, PartialEq)]
pub(in crate::daemon_edge) enum Export {
    Body(&'static str, String),
    Error(u16, Value),
}

/// The daemon's answer, or `None` when it would read the request or a row
/// differently, or names no home to shorten paths against.
pub(in crate::daemon_edge) fn export(
    query: &str,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<Export> {
    let format = query_value(query, "format").ok()?;
    let csv = match format.as_deref().unwrap_or("json") {
        "json" => false,
        "csv" => true,
        _ => {
            return Some(Export::Error(
                400,
                json!({"error": "invalid_export_format"}),
            ))
        }
    };
    let home = config.user_home.as_deref()?;
    let args = json!({
        "harness": null,
        "category": null,
        "severity": null,
        "request_id": null,
        "action_identity": null,
        "before_cursor": null,
        "include_details": false,
    });
    let items = page_items(args, EXPORT_LIMIT, home, config, reads)?;
    let exported_at = now()?;
    Some(if csv {
        Export::Body("text/csv; charset=utf-8", csv_text(&exported_at, &items)?)
    } else {
        Export::Body("application/json", json_text(&exported_at, &items)?)
    })
}

/// `_now_iso()`: UTC with microseconds, always written, and a `Z` suffix.
fn now() -> Option<String> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    let text =
        crate::policy_bundle_time::micros_to_utc_isoformat(i64::try_from(micros).ok()?, "Z")?;
    Some(match text.contains('.') {
        true => text,
        false => text.replacen('Z', ".000000Z", 1),
    })
}

/// A scalar as Python's `json.dumps` writes it. Every text value reaching
/// here is plain ASCII, which both write alike. A float Python would write
/// in exponent form is left to the daemon.
fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::Number(number) => {
            let text = number.to_string();
            (!text.contains(['e', 'E'])).then_some(text)
        }
        Value::String(_) | Value::Null | Value::Bool(_) => serde_json::to_string(value).ok(),
        Value::Array(_) | Value::Object(_) => None,
    }
}

/// `json.dumps(export_evidence_payload(...), indent=2)`.
pub(in crate::daemon_edge) fn json_text(exported_at: &str, items: &[Value]) -> Option<String> {
    let quote = |text: &str| serde_json::to_string(text).ok();
    let mut out = String::from("{\n");
    out.push_str(&format!("  \"exported_at\": {},\n", quote(exported_at)?));
    out.push_str(&format!(
        "  \"privacy_warning\": {},\n",
        quote(PRIVACY_WARNING)?
    ));
    out.push_str(
        "  \"redaction\": {\n    \"details\": \"omitted\",\n    \"local_paths\": \"redacted\",\n    \"token_like_values\": \"redacted\"\n  },\n",
    );
    out.push_str(&format!("  \"total_rows\": {},\n", items.len()));
    if items.is_empty() {
        out.push_str("  \"items\": []\n}");
        return Some(out);
    }
    out.push_str("  \"items\": [\n");
    for (index, item) in items.iter().enumerate() {
        out.push_str("    {\n");
        for (position, field) in FIELDS.iter().enumerate() {
            let separator = if position + 1 < FIELDS.len() { "," } else { "" };
            out.push_str(&format!(
                "      \"{field}\": {}{separator}\n",
                scalar(item.get(*field)?)?
            ));
        }
        out.push_str(if index + 1 < items.len() {
            "    },\n"
        } else {
            "    }\n"
        });
    }
    out.push_str("  ]\n}");
    Some(out)
}

/// `export_evidence_csv`: `csv.writer` rows ending in `\r\n`, each text cell
/// that a spreadsheet would read as a formula prefixed with `'`.
pub(in crate::daemon_edge) fn csv_text(exported_at: &str, items: &[Value]) -> Option<String> {
    let mut out = String::new();
    row(
        &mut out,
        &["privacy_warning".into(), PRIVACY_WARNING.into()],
    );
    row(&mut out, &["exported_at".into(), exported_at.into()]);
    row(&mut out, &["total_rows".into(), items.len().to_string()]);
    out.push_str("\r\n");
    row(
        &mut out,
        &FIELDS
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<Vec<_>>(),
    );
    for item in items {
        let mut cells = Vec::with_capacity(FIELDS.len());
        for field in FIELDS {
            cells.push(match item.get(field)? {
                Value::Null => String::new(),
                Value::String(text) if text.starts_with(['=', '+', '-', '@', '\t', '\r', '\n']) => {
                    format!("'{text}")
                }
                Value::String(text) => text.clone(),
                value @ Value::Number(_) => scalar(value)?,
                _ => return None,
            });
        }
        row(&mut out, &cells);
    }
    Some(out)
}

/// One `csv.writer` row with the default dialect's minimal quoting.
fn row(out: &mut String, cells: &[String]) {
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        if cell.contains([',', '"', '\r', '\n']) {
            out.push('"');
            out.push_str(&cell.replace('"', "\"\""));
            out.push('"');
        } else {
            out.push_str(cell);
        }
    }
    out.push_str("\r\n");
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_evidence_export_tests.rs"]
mod tests;
