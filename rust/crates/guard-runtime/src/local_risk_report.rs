//! `local-risk-report --stdin`: the privacy-safe local Guard risk report
//! (`local_risk_report.py` before the report moved here).
//!
//! The report is intentionally coarse. It summarizes protection posture from
//! a few counters in the local status payload and never serializes prompts,
//! commands, source code, findings, file paths, hostnames, usernames,
//! secrets, tokens, raw receipts or workspace contents. Its integrity digest
//! is SHA-256 over the canonical report without the digest.

use std::collections::BTreeSet;
use std::io::Read;

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_json::{dumps_sorted, py_str};

const COMMAND: &str = "local-risk-report";
const SCHEMA: &str = "local-risk-report.v1";
const REPORT_SCHEMA_VERSION: &str = "guard-local-risk-report/v1";
const MAX_REQUEST_BYTES: u64 = 4 * 1024 * 1024;
const LIMITATION: &str = "This is a local posture summary, not a certification or proof that \
     every attack is blocked. Coverage depends on the installed Guard version, harness, event \
     surface, policy, and runtime state.";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    /// The local status payload `hol-guard status` builds.
    status: Map<String, Value>,
    guard_version: String,
    /// `html` renders the page; anything else is the JSON report.
    format: String,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "local_risk_report_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("local_risk_report_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "local_risk_report_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("local_risk_report_request_invalid".to_owned());
    }
    let report = build_report(&request.status, &request.guard_version)
        .ok_or_else(|| "local_risk_report_response_unencodable".to_owned())?;
    let body = if request.format == "html" {
        render_html(&report)
    } else {
        report_json(&report)
    }
    .ok_or_else(|| "local_risk_report_response_unencodable".to_owned())?;
    serde_json::to_vec(&json!({ "body": body }))
        .map_err(|_| "local_risk_report_response_unencodable".to_owned())
}

/// The report as a JSON object, `integrity_sha256` included.
fn build_report(status: &Map<String, Value>, guard_version: &str) -> Option<Map<String, Value>> {
    let field = |name: &str| status.get(name).unwrap_or(&Value::Null);
    let harnesses: Vec<&Map<String, Value>> = match field("harnesses") {
        Value::Array(items) => items.iter().filter_map(Value::as_object).collect(),
        _ => Vec::new(),
    };
    let installed: BTreeSet<&str> = harnesses
        .iter()
        .filter(|item| item.get("installed") == Some(&Value::Bool(true)))
        .filter_map(|item| item.get("harness").and_then(Value::as_str))
        .collect();
    let managed = nonnegative_int(field("managed_harnesses"));
    let review_items: u128 = harnesses
        .iter()
        .map(|item| nonnegative_int(item.get("review_count").unwrap_or(&Value::Null)))
        .sum();
    let pending = nonnegative_int(field("pending_approvals"));
    let receipts = nonnegative_int(field("receipt_count"));
    let runtime_active = field("runtime_status").as_str() == Some("active");
    let sync_configured = truthy(field("sync_configured"));

    let checks = [
        if runtime_active {
            check(
                "runtime",
                "pass",
                "Local Guard runtime is active.".to_owned(),
            )
        } else {
            check(
                "runtime",
                "fail",
                "Local Guard runtime is not active.".to_owned(),
            )
        },
        if managed > 0 {
            check(
                "managed_harnesses",
                "pass",
                format!("{managed} detected harness(es) are managed by Guard."),
            )
        } else {
            check(
                "managed_harnesses",
                "review",
                "No detected harness is currently managed by Guard.".to_owned(),
            )
        },
        if review_items > 0 {
            check(
                "configuration_review",
                "review",
                format!("{review_items} managed artifact change(s) need review."),
            )
        } else {
            check(
                "configuration_review",
                "pass",
                "No managed artifact changes are waiting for review.".to_owned(),
            )
        },
        if pending > 0 {
            check(
                "pending_approvals",
                "review",
                format!("{pending} action(s) are waiting for approval."),
            )
        } else {
            check(
                "pending_approvals",
                "pass",
                "No actions are waiting for approval.".to_owned(),
            )
        },
    ];
    let status_of = |check: &Value| check["status"].as_str().unwrap_or_default().to_owned();
    let risk_band = if checks.iter().any(|check| status_of(check) == "fail") {
        "high"
    } else if checks.iter().any(|check| status_of(check) == "review") {
        "review"
    } else {
        "low"
    };
    let generated_at = match field("generated_at") {
        value if !truthy(value) => String::new(),
        value => py_str(value)?,
    };
    let mut report = Map::new();
    report.insert("schema_version".to_owned(), json!(REPORT_SCHEMA_VERSION));
    report.insert("generated_at".to_owned(), json!(generated_at));
    report.insert("guard_version".to_owned(), json!(guard_version));
    report.insert("risk_band".to_owned(), json!(risk_band));
    report.insert("checks".to_owned(), Value::Array(checks.to_vec()));
    report.insert("managed_harness_count".to_owned(), integer(managed));
    report.insert("installed_harnesses".to_owned(), json!(installed));
    report.insert("review_item_count".to_owned(), integer(review_items));
    report.insert("pending_approval_count".to_owned(), integer(pending));
    report.insert("receipt_count".to_owned(), integer(receipts));
    report.insert("cloud_sync_configured".to_owned(), json!(sync_configured));
    report.insert("sensitive_content_included".to_owned(), json!(false));
    report.insert("certification".to_owned(), json!(false));
    report.insert("limitation".to_owned(), json!(LIMITATION));
    let canonical = dumps_sorted(&Value::Object(report.clone()))?;
    let digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    report.insert("integrity_sha256".to_owned(), json!(digest));
    Some(report)
}

fn check(id: &str, status: &str, summary: String) -> Value {
    json!({"id": id, "status": status, "summary": summary})
}

/// `_nonnegative_int`: a bool counts as 0 or 1, a negative or non-integer
/// value as 0.
fn nonnegative_int(value: &Value) -> u128 {
    match value {
        Value::Bool(flag) => u128::from(*flag),
        Value::Number(number) if !number.to_string().contains(['.', 'e', 'E']) => {
            number.to_string().parse().unwrap_or(0)
        }
        _ => 0,
    }
}

fn integer(value: u128) -> Value {
    serde_json::from_str(&value.to_string()).unwrap_or(Value::Null)
}

/// Python's `bool(value)` for a decoded JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64() != Some(0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

/// `json.dumps(report, sort_keys=True, indent=2) + "\n"`.
fn report_json(report: &Map<String, Value>) -> Option<String> {
    // Reparsing the sorted text keeps key order whatever map serde_json uses.
    let sorted: Value =
        serde_json::from_str(&dumps_sorted(&Value::Object(report.clone()))?).ok()?;
    let pretty = serde_json::to_string_pretty(&sorted).ok()?;
    Some(ensure_ascii(&pretty) + "\n")
}

/// Escapes every non-ASCII character as `json.dumps` does; outside strings
/// JSON text is ASCII, so this only touches string contents.
fn ensure_ascii(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_ascii() {
            out.push(c);
        } else {
            let mut units = [0u16; 2];
            for unit in c.encode_utf16(&mut units) {
                out.push_str(&format!("\\u{unit:04x}"));
            }
        }
    }
    out
}

/// `render_local_risk_report_html`.
fn render_html(report: &Map<String, Value>) -> Option<String> {
    let text = |name: &str| report.get(name).and_then(Value::as_str).unwrap_or_default();
    let mut check_items = String::new();
    for check in report.get("checks")?.as_array()? {
        let part = |name: &str| escape(check[name].as_str().unwrap_or_default());
        check_items.push_str(&format!(
            "<li><strong>{}</strong>: {} \u{2014} {}</li>",
            part("id"),
            part("status"),
            part("summary")
        ));
    }
    let harnesses: Vec<String> = report
        .get("installed_harnesses")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .map(escape)
        .collect();
    let harnesses = if harnesses.is_empty() {
        "None detected".to_owned()
    } else {
        harnesses.join(", ")
    };
    Some(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"robots\" content=\"noindex,nofollow\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>HOL Guard local risk report</title></head><body>\
         <main><h1>HOL Guard local risk report</h1>\
         <p>Risk band: <strong>{}</strong></p>\
         <p>Guard version: {}</p>\
         <p>Installed harnesses: {harnesses}</p>\
         <ul>{check_items}</ul>\
         <p>{}</p>\
         <p>Integrity SHA-256: <code>{}</code></p>\
         <p>Sensitive local content included: no.</p>\
         </main></body></html>\n",
        escape(text("risk_band")),
        escape(text("guard_version")),
        escape(text("limitation")),
        text("integrity_sha256"),
    ))
}

/// `html.escape(value, quote=True)`.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[path = "local_risk_report_tests.rs"]
mod tests;
