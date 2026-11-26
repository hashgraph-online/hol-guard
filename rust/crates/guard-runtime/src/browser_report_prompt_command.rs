//! The `browser-report-prompt` command behind `hol-guard browser report-prompt` (BP-T172).
//!
//! A user who thinks a browser review should not have asked can turn the stored approval into a
//! case skeleton and paste it into a public issue, where it becomes a benign gate row. The
//! skeleton names the driver, the tool, the verb, the intent, the profile mode and the reason
//! codes. Every argument value is a placeholder, and every web address becomes a synthetic site
//! (`site-a.example.test`, then `site-b`, ...), so the skeleton keeps the call's shape and nothing
//! the user typed or visited. The store is opened read-only and nothing is sent anywhere.

use std::collections::BTreeSet;
use std::path::Path;

use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use guard_command::browser_action_project::{
    project_screened_browser_action, BrowserProjection, BrowserProjectionContext,
    BrowserUnclassifiedReason,
};
use guard_command::browser_driver_compile::{
    CompiledBrowserDriverV1, CompiledBrowserOperationV1, CompiledBrowserToolV1,
};
use guard_command::browser_driver_match::{match_browser_driver, BrowserToolCallIdentity};
use guard_command::browser_first_party_drivers::first_party_browser_drivers;

use crate::approval_browser_card::{envelope_text, tool_input};
use crate::local_store_read::{open_read_only, table_exists, STORE_FILE_NAME};

pub(crate) const COMMAND: &str = "browser-report-prompt";

/// The synthetic sites addresses are mapped onto, in the order the call names them.
const SITE_LABELS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const SITE_DOMAIN: &str = "example.test";
const REQUEST_ID_MAX_BYTES: usize = 128;
const MAX_DEPTH: usize = 8;
const MAX_ITEMS: usize = 32;
const KEY_MAX_BYTES: usize = 64;
const REASON_CODE_MAX_BYTES: usize = 96;

/// Argument names browser drivers use for their own controls. A key on this list, or one the
/// matched tool's profile names, is a schema field and is kept; any other key may be data the user
/// typed (a form field, a header, a storage key) and is replaced.
const COMMON_ARGUMENT_KEYS: &[&str] = &[
    "action",
    "button",
    "doubleClick",
    "element",
    "endElement",
    "endRef",
    "fields",
    "filename",
    "fullPage",
    "function",
    "height",
    "index",
    "key",
    "modifiers",
    "name",
    "paths",
    "raw",
    "ref",
    "selector",
    "slowly",
    "startElement",
    "startRef",
    "submit",
    "text",
    "textGone",
    "time",
    "timeout",
    "type",
    "url",
    "value",
    "values",
    "width",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    guard_home: String,
    request_id: String,
}

struct StoredApproval {
    harness: String,
    envelope: Value,
    reason_codes: Vec<String>,
}

pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return refusal("request_invalid", "The request was not understood.");
    };
    let request_id = request.request_id.trim();
    if request_id.is_empty()
        || request_id.len() > REQUEST_ID_MAX_BYTES
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return refusal("request_id_invalid", "That is not an approval request id.");
    }
    let guard_home = Path::new(&request.guard_home);
    if !guard_home.is_absolute() {
        return refusal(
            "guard_home_invalid",
            "The Guard home must be an absolute path.",
        );
    }
    let stored = match read_approval(guard_home, request_id) {
        Ok(Some(stored)) => stored,
        Ok(None) => return refusal("request_not_found", "No approval has that request id."),
        Err(()) => return refusal("store_unavailable", "The Guard store could not be read."),
    };
    report(first_party_browser_drivers(), &stored)
}

fn read_approval(guard_home: &Path, request_id: &str) -> Result<Option<StoredApproval>, ()> {
    let Some(connection) = open_read_only(&guard_home.join(STORE_FILE_NAME)).map_err(|_| ())?
    else {
        return Ok(None);
    };
    if !table_exists(&connection, "approval_requests").map_err(|_| ())? {
        return Ok(None);
    }
    let row = connection
        .query_row(
            "select harness, action_envelope_json, decision_v2_json, risk_signals_json \
             from approval_requests where request_id = ?1",
            params![request_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ())?;
    let Some((harness, envelope, decision, signals)) = row else {
        return Ok(None);
    };
    let parse = |cell: Option<String>| {
        cell.and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .unwrap_or(Value::Null)
    };
    let mut codes = BTreeSet::new();
    if let Some(signals) = parse(decision).get("signals").and_then(Value::as_array) {
        collect_reason_codes(signals, &mut codes);
    }
    if let Some(signals) = parse(signals).as_array() {
        collect_reason_codes(signals, &mut codes);
    }
    Ok(Some(StoredApproval {
        harness: harness.unwrap_or_default(),
        envelope: parse(envelope),
        reason_codes: codes.into_iter().collect(),
    }))
}

/// The machine codes on the stored signals. Free text is never read, and a value that is not a
/// plain code is skipped, so a code cannot carry anything the call named.
fn collect_reason_codes(signals: &[Value], codes: &mut BTreeSet<String>) {
    for signal in signals {
        for key in ["signal_id", "reason_code", "code"] {
            if let Some(code) = signal.get(key).and_then(Value::as_str) {
                if is_reason_code(code) {
                    codes.insert(code.to_owned());
                }
            }
        }
    }
}

fn is_reason_code(code: &str) -> bool {
    (1..=REASON_CODE_MAX_BYTES).contains(&code.len())
        && code
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && code.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'.' | b':' | b'-')
        })
}

fn report(drivers: &[CompiledBrowserDriverV1], stored: &StoredApproval) -> Value {
    let Some(envelope) = stored.envelope.as_object() else {
        return not_browser();
    };
    let mcp_tool = envelope_text(envelope, "mcp_tool");
    let Some(harness_tool_name) = envelope_text(envelope, "tool_name").or(mcp_tool) else {
        return not_browser();
    };
    let call = BrowserToolCallIdentity {
        harness_tool_name,
        mcp_server_name: envelope_text(envelope, "mcp_server"),
        mcp_tool_name: mcp_tool,
        package: None,
    };
    let Some(matched) = match_browser_driver(drivers, &call) else {
        return not_browser();
    };
    let arguments = tool_input(envelope);
    let context = BrowserProjectionContext {
        harness: &stored.harness,
        ..BrowserProjectionContext::default()
    };
    let projection = project_screened_browser_action(&matched, &arguments, &Map::new(), &context);
    let mut sites = Sites::default();
    let mut skeleton = Map::new();
    skeleton.insert("driver".to_owned(), json!(matched.driver.id));
    skeleton.insert("tool".to_owned(), json!(matched.tool_name));
    match &projection {
        BrowserProjection::Classified(action) => {
            let action = serde_json::to_value(action.as_ref()).unwrap_or(Value::Null);
            for key in ["verb", "intent", "operation", "sensitive_surface_flags"] {
                skeleton.insert(key.to_owned(), action[key].clone());
            }
            skeleton.insert(
                "profile_mode".to_owned(),
                action["session"]["profile_mode"].clone(),
            );
            let origin = action["target"]["origin"].as_str().map(|origin| {
                let site = sites.replace(origin);
                json!({"placeholder": site.text, "loopback": site.loopback})
            });
            skeleton.insert("origin".to_owned(), origin.unwrap_or(Value::Null));
        }
        BrowserProjection::Unclassified { reason, .. } => {
            skeleton.insert(
                "unclassified".to_owned(),
                json!(match reason {
                    BrowserUnclassifiedReason::ToolNotListed => "tool_not_listed",
                    BrowserUnclassifiedReason::CaseNotListed => "case_not_listed",
                }),
            );
        }
    }
    skeleton.insert("reason_codes".to_owned(), json!(stored.reason_codes));
    // A tool the profile does not list has no known argument names, so every key is replaced.
    let keys = matched.tool.map(schema_keys).unwrap_or_default();
    skeleton.insert(
        "arguments".to_owned(),
        placeholder(&Value::Object(arguments), &keys, &mut sites, 0),
    );
    json!({"ok": true, "skeleton": skeleton})
}

/// Each distinct site the call names gets the next synthetic name, so a skeleton still shows
/// whether two addresses were the same site.
#[derive(Default)]
struct Sites {
    seen: Vec<String>,
}

struct Site {
    text: String,
    loopback: bool,
}

impl Sites {
    fn replace(&mut self, address: &str) -> Site {
        let Some((scheme, host)) = scheme_and_host(address) else {
            return Site {
                text: "<text>".to_owned(),
                loopback: false,
            };
        };
        let index = match self.seen.iter().position(|seen| *seen == host) {
            Some(index) => index,
            None => {
                self.seen.push(host.clone());
                self.seen.len() - 1
            }
        };
        let label = SITE_LABELS
            .get(index)
            .map(|byte| char::from(*byte).to_string())
            .unwrap_or_else(|| format!("{}", index + 1));
        Site {
            text: format!("{scheme}://site-{label}.{SITE_DOMAIN}/"),
            loopback: is_loopback(&host),
        }
    }
}

/// The scheme and lowercased host of a web address, or `None` for anything else.
fn scheme_and_host(address: &str) -> Option<(&'static str, String)> {
    let (scheme, rest) = address.trim().split_once("://")?;
    let scheme = ["http", "https", "ws", "wss"]
        .into_iter()
        .find(|known| known.eq_ignore_ascii_case(scheme))?;
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    let host_and_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(bracketed) = host_and_port.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or("")
    } else {
        host_and_port.split(':').next().unwrap_or("")
    };
    (!host.is_empty()).then(|| (scheme, host.to_ascii_lowercase()))
}

fn is_loopback(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host == "::1"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.is_loopback())
}

/// The argument names a listed tool is known to take: the names its profile points at, its
/// discriminator, and the common browser control names.
fn schema_keys(tool: &CompiledBrowserToolV1) -> BTreeSet<String> {
    fn operation_pointers(operation: &CompiledBrowserOperationV1) -> impl Iterator<Item = &String> {
        let pointers = &operation.pointers;
        pointers
            .url
            .iter()
            .chain(&pointers.element_name)
            .chain(&pointers.text)
            .chain(&pointers.script)
            .chain(&pointers.file)
    }
    let pointers: Vec<&String> = match tool {
        CompiledBrowserToolV1::Fixed(fixed) => operation_pointers(fixed).collect(),
        CompiledBrowserToolV1::Discriminated {
            discriminator,
            cases,
        } => cases
            .values()
            .flat_map(operation_pointers)
            .chain(std::iter::once(discriminator))
            .collect(),
        CompiledBrowserToolV1::CdpPassthrough { method, params } => {
            method.iter().chain(params).collect()
        }
    };
    COMMON_ARGUMENT_KEYS
        .iter()
        .copied()
        .chain(
            pointers
                .into_iter()
                .flat_map(|pointer| pointer.split('/'))
                .filter(|segment| is_field_name(segment)),
        )
        .map(str::to_owned)
        .collect()
}

/// The value's shape with every value replaced: a web address by its synthetic site, any other
/// text by `<text>`, numbers, booleans and nulls by their kind. A key in `keys` is a schema field
/// name and is kept; any other key may be data and becomes `<key-N>`.
fn placeholder(value: &Value, keys: &BTreeSet<String>, sites: &mut Sites, depth: usize) -> Value {
    if depth >= MAX_DEPTH {
        return json!("<nested>");
    }
    match value {
        Value::Null => json!("<null>"),
        Value::Bool(_) => json!("<boolean>"),
        Value::Number(_) => json!("<number>"),
        Value::String(text) => {
            if scheme_and_host(text).is_some() {
                json!(sites.replace(text).text)
            } else {
                json!("<text>")
            }
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(MAX_ITEMS)
                .map(|item| placeholder(item, keys, sites, depth + 1))
                .collect(),
        ),
        Value::Object(fields) => {
            let mut shaped = Map::new();
            for (index, (key, field)) in fields.iter().take(MAX_ITEMS).enumerate() {
                let key = if keys.contains(key) {
                    key.clone()
                } else {
                    format!("<key-{}>", index + 1)
                };
                shaped.insert(key, placeholder(field, keys, sites, depth + 1));
            }
            Value::Object(shaped)
        }
    }
}

fn is_field_name(key: &str) -> bool {
    (1..=KEY_MAX_BYTES).contains(&key.len())
        && key
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn not_browser() -> Value {
    refusal(
        "not_a_browser_call",
        "That approval is not a call to a browser driver Guard knows.",
    )
}

fn refusal(code: &str, message: &str) -> Value {
    json!({"ok": false, "error": {"code": code, "message": message}})
}

#[cfg(test)]
#[path = "browser_report_prompt_command_tests.rs"]
mod tests;
