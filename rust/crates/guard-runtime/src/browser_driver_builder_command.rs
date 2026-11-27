//! The `browser-driver` command behind `hol-guard extensions generate|validate --browser`
//! (BP-T053).
//!
//! `generate` drafts a contributed browser driver profile from an MCP `tools/list` result: every
//! tool gets a proposed verb from its name and argument pointers from its input schema. The draft
//! errs toward strict. A tool whose name says nothing about what it does maps to `Other`, the
//! profile mode is `unknown`, and the publisher is never verified. `validate` runs a profile
//! through the same compiler Guard uses at runtime, as a contributed profile, and reports what it
//! claims. Nothing is written and no setting is read.
//!
//! Both ops also carry benign gate rows (BP-T057): `generate` drafts a protect row and its benign
//! pair for every tool, and `validate` refuses a profile without rows that cover every tool and pair
//! every protect row. The rules live in [`crate::browser_driver_gate_rows`].

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use guard_command::browser_driver_compile::{
    compile_browser_driver, BrowserDriverOrigin, CompiledBrowserDriverV1, CompiledBrowserToolV1,
};
use guard_command::browser_first_party_drivers::first_party_browser_drivers;

use crate::browser_driver_gate_rows::{check_gate_rows, draft_gate_rows};

pub(crate) const COMMAND: &str = "browser-driver";

const MAX_TOOLS: usize = 256;
const MAX_POINTERS: usize = 8;

/// Name tokens that propose a verb, strongest first. The first row with a matching token wins.
const VERB_TOKENS: &[(&str, &[&str])] = &[
    (
        "Evaluate",
        &[
            "evaluate",
            "eval",
            "script",
            "javascript",
            "js",
            "execute",
            "exec",
            "code",
        ],
    ),
    ("Upload", &["upload"]),
    ("Download", &["download", "pdf"]),
    (
        "Intercept",
        &["intercept", "route", "mock", "throttle", "emulate"],
    ),
    ("Permission", &["permission", "permissions", "geolocation"]),
    ("Attach", &["attach", "connect", "cdp", "devtools"]),
    ("Screenshot", &["screenshot", "capture"]),
    (
        "TabControl",
        &["tab", "tabs", "window", "windows", "close", "resize"],
    ),
    (
        "Navigate",
        &[
            "navigate", "goto", "open", "back", "forward", "reload", "visit",
        ],
    ),
    (
        "Click",
        &["click", "hover", "drag", "drop", "tap", "dblclick"],
    ),
    ("Type", &["type", "fill", "input", "write"]),
    ("Key", &["key", "keys", "press", "keyboard"]),
    (
        "Select",
        &["select", "choose", "option", "check", "uncheck"],
    ),
    ("Scroll", &["scroll"]),
    (
        "Read",
        &[
            "read", "get", "text", "content", "snapshot", "console", "list", "extract", "find",
            "query", "wait", "html", "markdown", "title",
        ],
    ),
];

const WRITE_TOKENS: &[&str] = &["set", "write", "add", "delete", "remove", "clear", "put"];

/// Input schema property names that point at each kind of argument.
const URL_NAMES: &[&str] = &["url", "uri", "href", "link"];
const ELEMENT_NAMES: &[&str] = &["element", "selector", "ref", "target", "locator"];
const TEXT_NAMES: &[&str] = &["text", "value", "values", "key", "query"];
const SCRIPT_NAMES: &[&str] = &["function", "expression", "script", "code", "javascript"];
const FILE_NAMES: &[&str] = &["path", "paths", "file", "files", "filepath", "filename"];

pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let Ok(Value::Object(request)) = serde_json::from_slice::<Value>(bytes) else {
        return refusal("request_invalid", "The request was not understood.");
    };
    match request.get("op").and_then(Value::as_str) {
        Some("generate") => generate(&request),
        Some("validate") => validate(&request),
        _ => refusal("op_invalid", "The op must be generate or validate."),
    }
}

fn refusal(code: &str, message: &str) -> Value {
    json!({"ok": false, "error": {"code": code, "message": message}})
}

fn text<'a>(request: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    request
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn tool_list(document: &Value) -> Option<&Vec<Value>> {
    match document {
        Value::Array(tools) => Some(tools),
        Value::Object(object) => object
            .get("tools")
            .or_else(|| object.get("result").and_then(|result| result.get("tools")))
            .and_then(Value::as_array),
        _ => None,
    }
}

fn tokens(name: &str) -> Vec<String> {
    name.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn find<'a>(tokens: &'a [String], words: &[&str]) -> Option<&'a String> {
    tokens.iter().find(|token| words.contains(&token.as_str()))
}

/// The proposed verb and the token that chose it; `Other` when no token matches.
pub(crate) fn proposed_verb(name: &str) -> (&'static str, Option<String>) {
    let tokens = tokens(name);
    let writes = find(&tokens, WRITE_TOKENS).is_some();
    if let Some(token) = find(&tokens, &["cookie", "cookies"]) {
        let verb = if writes { "CookieWrite" } else { "CookieRead" };
        return (verb, Some(token.clone()));
    }
    if let Some(token) = find(&tokens, &["storage", "localstorage", "sessionstorage"]) {
        let verb = if writes {
            "StorageWrite"
        } else {
            "StorageRead"
        };
        return (verb, Some(token.clone()));
    }
    for (verb, words) in VERB_TOKENS {
        if let Some(token) = find(&tokens, words) {
            return (verb, Some(token.clone()));
        }
    }
    ("Other", None)
}

fn is_pointer(name: &str) -> bool {
    let mut characters = name.chars();
    matches!(characters.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
        && name.len() <= 64
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn pointers(properties: &[String], names: &[&str]) -> Vec<String> {
    properties
        .iter()
        .filter(|property| names.contains(&property.to_ascii_lowercase().as_str()))
        .filter(|property| is_pointer(property))
        .take(MAX_POINTERS)
        .cloned()
        .collect()
}

fn is_tool_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit())
        && name.len() <= 64
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn draft_tool(tool: &Map<String, Value>, name: &str) -> (Value, Value) {
    let (verb, token) = proposed_verb(name);
    let properties: Vec<String> = tool
        .get("inputSchema")
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object)
        .map(|properties| properties.keys().cloned().collect())
        .unwrap_or_default();
    let mut row = Map::new();
    row.insert("name".to_owned(), json!(name));
    row.insert("verb".to_owned(), json!(verb));
    let mut add = |key: &str, names: &[&str]| {
        let found = pointers(&properties, names);
        if !found.is_empty() {
            row.insert(key.to_owned(), json!(found));
        }
    };
    add("url", URL_NAMES);
    add("text", TEXT_NAMES);
    add("script", SCRIPT_NAMES);
    add("file", FILE_NAMES);
    let element = pointers(&properties, ELEMENT_NAMES);
    if !element.is_empty() {
        row.insert("element".to_owned(), json!({"name": element}));
    }
    let proposal = json!({"tool": name, "verb": verb, "evidence": token});
    (Value::Object(row), proposal)
}

fn generate(request: &Map<String, Value>) -> Value {
    let Some(slug) = text(request, "slug") else {
        return refusal(
            "slug_missing",
            "Provide --slug; the profile id is browser.<slug>.",
        );
    };
    let Some(server) = text(request, "server") else {
        return refusal(
            "server_missing",
            "Provide --server, the MCP server name the driver uses.",
        );
    };
    let Some(document) = text(request, "document") else {
        return refusal(
            "document_missing",
            "Provide the MCP tools/list result as --input.",
        );
    };
    let Ok(document) = serde_json::from_str::<Value>(document) else {
        return refusal("document_invalid", "The tool list must be JSON.");
    };
    let Some(listed) = tool_list(&document) else {
        return refusal("document_invalid", "The input has no tools array.");
    };
    let mut tools = Vec::new();
    let mut proposals = Vec::new();
    let mut notes = Vec::new();
    for entry in listed {
        let Some(tool) = entry.as_object() else {
            notes.push(json!({"code": "tool_skipped", "detail": "an entry was not an object"}));
            continue;
        };
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            notes.push(json!({"code": "tool_skipped", "detail": "an entry had no name"}));
            continue;
        };
        if !is_tool_name(name) {
            notes.push(json!({"code": "tool_name_unsupported", "tool": name}));
            continue;
        }
        if tools.len() == MAX_TOOLS {
            notes.push(json!({"code": "tool_limit", "tool": name}));
            continue;
        }
        let (row, proposal) = draft_tool(tool, name);
        if proposal["verb"] == "Other" {
            notes.push(json!({"code": "verb_unknown", "tool": name}));
        }
        tools.push(row);
        proposals.push(proposal);
    }
    if tools.is_empty() {
        return refusal("tools_empty", "No tool in the list has a usable name.");
    }
    // A tool namespace cannot hold a dot, so a dotted server name matches by name alone.
    let namespaces: Vec<String> = if server.contains('.') {
        Vec::new()
    } else {
        vec![format!("mcp__{server}__")]
    };
    let mut matches = json!({
        "mcpServerNames": [server],
        "packages": [],
        "toolNamespaces": namespaces,
        "harnessTools": [],
    });
    if let Some(package) = text(request, "package") {
        matches["packages"] = json!([package]);
    }
    let gate_rows = draft_gate_rows(slug, server, &tools);
    let profile = json!({
        "schemaVersion": "guard.browser-driver.v1",
        "id": format!("browser.{slug}"),
        "name": text(request, "name").unwrap_or(slug),
        "publisher": {
            "name": text(request, "publisher").unwrap_or(slug),
            "verified": false,
        },
        "match": matches,
        "profileMode": {"default": "unknown"},
        "tools": tools,
    });
    notes.push(json!({"code": "profile_mode_unknown"}));
    // The compiler checks the exact text the CLI writes, indentation included, so a draft near
    // the size limit cannot pass here and then fail validation once it is on disk.
    let mut profile_text = serde_json::to_string_pretty(&profile).unwrap_or_default();
    profile_text.push('\n');
    match compile_browser_driver(
        profile_text.as_bytes(),
        BrowserDriverOrigin::Contributed,
        &[],
    ) {
        Err(error) => {
            return json!({
                "ok": false,
                "error": {"code": error.code(), "message": "The draft does not compile; adjust the flags."},
            })
        }
        Ok(driver) if is_shipped_id(&driver) => {
            return refusal(
                "browser_driver_id_duplicate",
                "A shipped first-party profile already uses this id; choose another --slug.",
            )
        }
        Ok(_) => {}
    }
    let mut gate_rows_text = serde_json::to_string_pretty(&gate_rows).unwrap_or_default();
    gate_rows_text.push('\n');
    json!({
        "ok": true,
        "profile": profile,
        "profileText": profile_text,
        "gateRows": gate_rows,
        "gateRowsText": gate_rows_text,
        "proposals": proposals,
        "notes": notes,
    })
}

fn is_shipped_id(driver: &CompiledBrowserDriverV1) -> bool {
    first_party_browser_drivers()
        .iter()
        .any(|shipped| shipped.id == driver.id)
}

fn verb_name(tool: &CompiledBrowserToolV1) -> Vec<String> {
    match tool {
        CompiledBrowserToolV1::Fixed(operation) => vec![format!("{:?}", operation.verb)],
        CompiledBrowserToolV1::Discriminated { cases, .. } => cases
            .values()
            .map(|operation| format!("{:?}", operation.verb))
            .collect(),
        CompiledBrowserToolV1::CdpPassthrough { .. } => vec!["CdpPassthrough".to_owned()],
    }
}

fn summary(driver: &CompiledBrowserDriverV1) -> Value {
    let mut verbs: BTreeMap<String, usize> = BTreeMap::new();
    let mut other = Vec::new();
    for (name, tool) in &driver.tools {
        for verb in verb_name(tool) {
            if verb == "Other" {
                other.push(name.clone());
            }
            *verbs.entry(verb).or_default() += 1;
        }
    }
    other.dedup();
    let first_party: Vec<&str> = first_party_browser_drivers()
        .iter()
        .filter(|shipped| shares_identity(shipped, driver))
        .map(|shipped| shipped.id.as_str())
        .collect();
    json!({
        "ok": true,
        "id": driver.id,
        "name": driver.name,
        "trustClass": "contributed",
        "profileMode": serde_json::to_value(driver.profile_mode_default).unwrap_or(Value::Null),
        "tools": driver.tools.len(),
        "verbs": verbs,
        "otherTools": other,
        "firstPartyOverlap": first_party,
    })
}

fn shares_identity(left: &CompiledBrowserDriverV1, right: &CompiledBrowserDriverV1) -> bool {
    let overlap = |a: &[String], b: &[String]| a.iter().any(|item| b.contains(item));
    overlap(
        &left.matches.mcp_server_names,
        &right.matches.mcp_server_names,
    ) || overlap(&left.matches.packages, &right.matches.packages)
        || overlap(
            &left.matches.tool_namespaces,
            &right.matches.tool_namespaces,
        )
        || overlap(&left.matches.harness_tools, &right.matches.harness_tools)
}

fn validate(request: &Map<String, Value>) -> Value {
    let Some(profile) = request.get("profile").and_then(Value::as_str) else {
        return refusal("profile_missing", "Provide the profile file to validate.");
    };
    match compile_browser_driver(profile.as_bytes(), BrowserDriverOrigin::Contributed, &[]) {
        Ok(driver) => {
            if is_shipped_id(&driver) {
                return refusal(
                    "browser_driver_id_duplicate",
                    "A shipped first-party profile already uses this id.",
                );
            }
            let Some(gate_rows) = request.get("gateRows").and_then(Value::as_str) else {
                return refusal(
                    "gate_rows_missing",
                    "Provide the benign gate rows for the profile with --gate-rows.",
                );
            };
            match check_gate_rows(&driver, gate_rows) {
                Ok(count) => {
                    let mut reply = summary(&driver);
                    reply["gateRows"] = json!(count);
                    reply
                }
                Err(refused) => refused,
            }
        }
        Err(error) => json!({
            "ok": false,
            "error": {"code": error.code(), "message": "The profile was refused by the compiler."},
        }),
    }
}

#[cfg(test)]
#[path = "browser_driver_builder_command_tests.rs"]
mod tests;
