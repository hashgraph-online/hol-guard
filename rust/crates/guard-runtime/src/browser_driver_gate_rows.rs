//! Benign gate rows for `hol-guard extensions generate|validate --browser` (BP-T057).
//!
//! `generate` drafts a pair of `mcp_cases` rows for every tool it maps: a protect row whose id
//! starts `neg-` and its benign pair, an `allow` row for the same server and tool. A routine verb
//! (navigation, inspection, interaction) is allowed under a site grant and paused without one. Any
//! other verb stays paused under a site grant, and its benign pair is an exact saved approval,
//! because Always allow is the one answer that settles it. `validate` refuses a profile whose rows
//! leave a tool without a row or a protect row without its benign pair, the rules the gate coverage
//! test holds every shipped profile to.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use guard_command::browser_driver_compile::CompiledBrowserDriverV1;

/// Verbs a site grant covers: the navigation, inspection and interaction intents (PRD 5.5).
const ROUTINE_VERBS: &[&str] = &[
    "Navigate",
    "Read",
    "Screenshot",
    "Scroll",
    "Click",
    "Type",
    "Key",
    "Select",
];

/// The `expect` values a gate row may carry.
const EXPECTS: &[&str] = &["allow", "block", "review", "not_allow", "setup"];

/// The scripted page every drafted row starts on.
const DRAFT_PAGE: &str = "docs-article";

const MAX_ROWS: usize = 4096;

/// A synthetic value for one drafted argument, chosen by the kind of pointer that names it.
fn draft_value(kind: &str, property: &str) -> Value {
    match kind {
        "url" => json!("https://docs.example.test/guide/configuration"),
        "text" => json!("install"),
        "script" => json!("() => document.title"),
        "file" => json!([]),
        _ if property.eq_ignore_ascii_case("ref") => json!("e3"),
        _ => json!("Configuration"),
    }
}

/// Arguments for one drafted tool, filled from the pointers the drafter found.
fn draft_arguments(tool: &Value) -> Value {
    let mut arguments = Map::new();
    for kind in ["url", "text", "script", "file"] {
        for property in tool[kind].as_array().into_iter().flatten() {
            if let Some(property) = property.as_str() {
                arguments.insert(property.to_owned(), draft_value(kind, property));
            }
        }
    }
    for property in tool["element"]["name"].as_array().into_iter().flatten() {
        if let Some(property) = property.as_str() {
            arguments.insert(property.to_owned(), draft_value("element", property));
        }
    }
    Value::Object(arguments)
}

fn row(
    id: String,
    server: &str,
    tool: &str,
    arguments: &Value,
    expect: &str,
    state: &str,
) -> Value {
    json!({
        "id": id,
        "server": server,
        "tool": tool,
        "arguments": arguments,
        "expect": expect,
        "state": state,
        "page": DRAFT_PAGE,
    })
}

/// The protect row and benign pair for every drafted tool of `browser.<slug>`.
pub(crate) fn draft_gate_rows(slug: &str, server: &str, tools: &[Value]) -> Vec<Value> {
    let mut rows = Vec::with_capacity(tools.len() * 2);
    for tool in tools {
        let (Some(name), Some(verb)) = (tool["name"].as_str(), tool["verb"].as_str()) else {
            continue;
        };
        let arguments = draft_arguments(tool);
        let stem = format!("browser-{slug}-{name}");
        if ROUTINE_VERBS.contains(&verb) {
            rows.push(row(
                format!("neg-{stem}"),
                server,
                name,
                &arguments,
                "block",
                "none",
            ));
            rows.push(row(
                format!("{stem}-site-grant"),
                server,
                name,
                &arguments,
                "allow",
                "site-grant",
            ));
        } else {
            rows.push(row(
                format!("neg-{stem}-site-grant"),
                server,
                name,
                &arguments,
                "block",
                "site-grant",
            ));
            rows.push(row(
                format!("{stem}-saved-exact"),
                server,
                name,
                &arguments,
                "allow",
                "saved-exact",
            ));
        }
    }
    rows
}

/// Server names a driver's tools arrive under: MCP server names and tool namespaces.
fn driver_servers(driver: &CompiledBrowserDriverV1) -> BTreeSet<String> {
    let mut servers: BTreeSet<String> = driver.matches.mcp_server_names.iter().cloned().collect();
    servers.extend(driver.matches.tool_namespaces.iter().map(|namespace| {
        let name = namespace.strip_prefix("mcp__").unwrap_or(namespace);
        name.strip_suffix("__").unwrap_or(name).to_owned()
    }));
    servers
}

/// One gate row reduced to what the coverage rules read.
struct GateRow {
    id: String,
    server: String,
    tool: String,
    expect: String,
}

fn gate_refusal(code: &str, message: &str, items: Vec<String>) -> Value {
    json!({"ok": false, "error": {"code": code, "message": message, "items": items}})
}

fn parse_rows(document: &str) -> Result<Vec<GateRow>, Value> {
    let invalid = |message: &str| gate_refusal("gate_rows_invalid", message, Vec::new());
    let Ok(document) = serde_json::from_str::<Value>(document) else {
        return Err(invalid("The gate rows must be JSON."));
    };
    let listed = match &document {
        Value::Array(rows) => rows,
        Value::Object(object) => match object.get("mcp_cases").and_then(Value::as_array) {
            Some(rows) => rows,
            None => return Err(invalid("The gate rows need an mcp_cases array.")),
        },
        _ => return Err(invalid("The gate rows must be an array or an object.")),
    };
    if listed.len() > MAX_ROWS {
        return Err(invalid("The gate rows hold too many rows."));
    }
    let mut rows = Vec::with_capacity(listed.len());
    for entry in listed {
        let field = |key: &str| entry.get(key).and_then(Value::as_str).map(str::to_owned);
        let (Some(id), Some(server), Some(tool), Some(expect)) =
            (field("id"), field("server"), field("tool"), field("expect"))
        else {
            return Err(invalid(
                "Every gate row needs an id, server, tool and expect.",
            ));
        };
        if !EXPECTS.contains(&expect.as_str()) || !entry["arguments"].is_object() {
            return Err(gate_refusal(
                "gate_rows_invalid",
                "A gate row has an unknown expect or no arguments object.",
                vec![id],
            ));
        }
        rows.push(GateRow {
            id,
            server,
            tool,
            expect,
        });
    }
    Ok(rows)
}

/// Check `document` against the gate coverage rules for `driver`. `Ok` carries how many rows
/// belong to the driver; `Err` carries the refusal to return.
pub(crate) fn check_gate_rows(
    driver: &CompiledBrowserDriverV1,
    document: &str,
) -> Result<usize, Value> {
    let servers = driver_servers(driver);
    let rows: Vec<GateRow> = parse_rows(document)?
        .into_iter()
        .filter(|row| servers.contains(&row.server))
        .collect();
    if rows.is_empty() {
        return Err(gate_refusal(
            "gate_rows_missing",
            "No gate row names a server this driver answers as.",
            servers.into_iter().collect(),
        ));
    }
    let unknown: Vec<String> = rows
        .iter()
        .filter(|row| !driver.tools.contains_key(&row.tool))
        .map(|row| row.id.clone())
        .collect();
    if !unknown.is_empty() {
        return Err(gate_refusal(
            "gate_row_tool_unknown",
            "These gate rows name a tool the profile does not map.",
            unknown,
        ));
    }
    let pinned: BTreeSet<&str> = rows.iter().map(|row| row.tool.as_str()).collect();
    let missing: Vec<String> = driver
        .tools
        .keys()
        .filter(|name| !pinned.contains(name.as_str()))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(gate_refusal(
            "gate_row_missing",
            "Every tool of the profile needs a gate row.",
            missing,
        ));
    }
    let allowed: BTreeSet<(&str, &str)> = rows
        .iter()
        .filter(|row| row.expect == "allow")
        .map(|row| (row.server.as_str(), row.tool.as_str()))
        .collect();
    let unpaired: Vec<String> = rows
        .iter()
        .filter(|row| row.id.starts_with("neg-"))
        .filter(|row| !allowed.contains(&(row.server.as_str(), row.tool.as_str())))
        .map(|row| row.id.clone())
        .collect();
    if !unpaired.is_empty() {
        return Err(gate_refusal(
            "gate_benign_pair_missing",
            "Every protect row needs an allow row for the same server and tool.",
            unpaired,
        ));
    }
    Ok(rows.len())
}

#[cfg(test)]
#[path = "browser_driver_gate_rows_tests.rs"]
mod tests;
