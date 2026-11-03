//! `mcp_tool_inventory` runner-authority kind: the inventory items an MCP
//! server's advertised tool definitions expand into (the readings
//! `inventory_contract_items._mcp_tool_items_from_artifact` and the
//! `inventory_contract_mcp` classifiers made before they moved here).
//!
//! Each tool's capabilities and risk level are protection readings: a tool
//! whose description names a shell or a secret must not reach the inventory
//! as `info`. Python keeps the trust metadata, attestation signing and
//! description resolution it already delegates, and applies these answers.
//!
//! The request carries the server's `harness` and `server_item_id`, plus two
//! JSON texts: `definitions` (the server metadata's `tools`, `tool_schemas`
//! and `toolSchemas` lists) and `trust_layers` (the server item's
//! `trustLayers`). They travel as text so the parse keeps their key order:
//! the schema signal text joins keys in the order the server declared them,
//! and the inherited layers keep the key order the server item exported.
//!
//! The answer is `{"answer": <JSON text>}` holding `tools`, one entry per
//! distinct tool in declaration order, and `inherited_layers`, the server's
//! Cisco scanner layers marked as inherited and unsigned.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::guard_store_wfcap_frame::sha256_hex;
use crate::hook_env_stamp::{dumps, set_member};
use crate::pyjson::{self, in_surrogate_plane, PyVal};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const KEYS: [&str; 4] = ["harness", "server_item_id", "definitions", "trust_layers"];
const DEFINITION_KEYS: [&str; 3] = ["tools", "tool_schemas", "toolSchemas"];
const ATTESTATION_KEYS: [&str; 5] = [
    "attestation",
    "attestationBindings",
    "attestationRef",
    "attestationStatus",
    "attestationVerification",
];

const READ: &[&str] = &[
    "read", "reads", "reading", "search", "searches", "list", "lists",
];
const DELETE: &[&str] = &[
    "delete", "deletes", "remove", "removes", "destroy", "destroys",
];
const WRITE: &[&str] = &[
    "write", "writes", "update", "updates", "create", "creates", "modify", "modifies",
];
const SHELL: &[&str] = &[
    "shell",
    "command",
    "commands",
    "execute",
    "exec",
    "subprocess",
];
const SECRET: &[&str] = &[
    "secret",
    "secrets",
    "token",
    "tokens",
    "password",
    "passwords",
    "credential",
    "credentials",
];
const NETWORK: &[&str] = &[
    "http", "url", "urls", "network", "fetch", "webhook", "webhooks",
];
const MODEL: &[&str] = &["sampling", "model", "models", "llm"];
const PERMISSION: &[&str] = &["permission", "permissions", "chmod"];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    if fields.len() != KEYS.len() || !KEYS.iter().all(|key| fields.contains_key(*key)) {
        return Err(ERR_INVALID);
    }
    let text = |key: &str| fields.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let harness = text("harness")?;
    let server = text("server_item_id")?;
    let definitions = parse(text("definitions")?)?;
    let trust_layers = parse(text("trust_layers")?)?;
    let mut tools = Vec::new();
    for tool in tool_definitions(&definitions) {
        tools.push(tool_entry(harness, server, tool)?);
    }
    let answer = PyVal::Dict(vec![
        ("tools".to_owned(), PyVal::List(tools)),
        (
            "inherited_layers".to_owned(),
            PyVal::List(inherited_layers(&trust_layers, server)),
        ),
    ]);
    let mut encoded = String::new();
    dumps(&answer, false, true, &mut encoded);
    Ok(json!({ "answer": encoded }))
}

/// A JSON text parsed the way `json.loads` reads it, lone surrogates kept.
fn parse(text: &str) -> Result<PyVal, &'static str> {
    let parsed = pyjson::parse_mapping_lone_surrogates(text).map_err(|_| ERR_INVALID)?;
    if parsed.collision {
        return Err(ERR_INVALID);
    }
    Ok(parsed.value)
}

/// `_mcp_tool_definitions`: the supported definition shapes, first
/// declaration of each name winning.
fn tool_definitions(metadata: &PyVal) -> Vec<&[(String, PyVal)]> {
    let mut seen: Vec<&str> = Vec::new();
    let mut tools: Vec<&[(String, PyVal)]> = Vec::new();
    for key in DEFINITION_KEYS {
        let Some(list) = metadata.get(key).and_then(PyVal::as_list) else {
            continue;
        };
        for raw in list {
            let Some(tool) = raw.as_dict() else {
                continue;
            };
            let Some(name) = member(tool, "name").and_then(PyVal::as_str) else {
                continue;
            };
            if name.chars().all(is_python_space) || seen.contains(&name) {
                continue;
            }
            seen.push(name);
            tools.push(tool);
        }
    }
    tools
}

fn tool_entry(
    harness: &str,
    server: &str,
    tool: &[(String, PyVal)],
) -> Result<PyVal, &'static str> {
    let name = member(tool, "name").and_then(PyVal::as_str).unwrap_or("");
    let non_empty = |key: &str| {
        member(tool, key)
            .and_then(PyVal::as_str)
            .filter(|value| !value.is_empty())
    };
    let display_name = non_empty("title").unwrap_or(name);
    let description = non_empty("description").unwrap_or("");
    if description.chars().any(in_surrogate_plane) {
        // `str.encode("utf-8")` raises on a lone surrogate, so the
        // description has no content hash to report.
        return Err(ERR_INVALID);
    }
    let input_schema = first_present(tool, "inputSchema", "input_schema");
    let output_schema = first_present(tool, "outputSchema", "output_schema");
    let annotations = member(tool, "annotations")
        .filter(|value| matches!(value, PyVal::Dict(_)))
        .cloned()
        .unwrap_or(PyVal::Dict(Vec::new()));
    let capabilities = capabilities(name, description, &input_schema, &annotations);
    let risk = risk_level(&capabilities);
    let schema_hash = |schema: &PyVal| match schema {
        PyVal::Null => PyVal::Null,
        value => PyVal::Str(fingerprint(value)),
    };
    let semantic_hash = fingerprint(&PyVal::Dict(vec![
        ("server".to_owned(), str_val(server)),
        ("name".to_owned(), str_val(name)),
        ("description".to_owned(), str_val(description)),
        ("inputSchema".to_owned(), input_schema.clone()),
        ("outputSchema".to_owned(), output_schema.clone()),
        ("annotations".to_owned(), annotations.clone()),
    ]));
    let source_fingerprint = fingerprint(&PyVal::Dict(vec![
        ("harness".to_owned(), str_val(harness)),
        ("server".to_owned(), str_val(server)),
        ("tool".to_owned(), str_val(name)),
    ]));
    let fingerprints = PyVal::Dict(vec![
        (
            "descriptionHash".to_owned(),
            PyVal::Str(sha256_hex(description.as_bytes())),
        ),
        ("inputSchemaHash".to_owned(), schema_hash(&input_schema)),
        ("outputSchemaHash".to_owned(), schema_hash(&output_schema)),
        ("annotations".to_owned(), annotations),
        (
            "schemaPresent".to_owned(),
            PyVal::Bool(input_schema != PyVal::Null || output_schema != PyVal::Null),
        ),
    ]);
    Ok(PyVal::Dict(vec![
        ("name".to_owned(), str_val(name)),
        ("display_name".to_owned(), str_val(display_name)),
        ("description".to_owned(), str_val(description)),
        (
            "item_id".to_owned(),
            PyVal::Str(format!("{server}:tool:{name}")),
        ),
        ("fingerprints".to_owned(), fingerprints),
        (
            "capabilities".to_owned(),
            PyVal::List(capabilities.into_iter().map(str_val).collect()),
        ),
        ("risk_level".to_owned(), str_val(risk)),
        ("semantic_hash".to_owned(), PyVal::Str(semantic_hash)),
        (
            "source_fingerprint".to_owned(),
            PyVal::Str(source_fingerprint),
        ),
    ]))
}

/// `_first_present_value`: the first key present wins, even when it is null.
fn first_present(tool: &[(String, PyVal)], first: &str, second: &str) -> PyVal {
    member(tool, first)
        .or_else(|| member(tool, second))
        .cloned()
        .unwrap_or(PyVal::Null)
}

/// `_capabilities_for_mcp_tool`, sorted, or `["unknown"]`.
fn capabilities(
    name: &str,
    description: &str,
    input_schema: &PyVal,
    annotations: &PyVal,
) -> Vec<&'static str> {
    let text = folded(&format!(
        "{name} {description} {}",
        signal_text(input_schema)
    ));
    let hint = |key: &str| matches!(annotations.get(key), Some(PyVal::Bool(true)));
    let mut found: BTreeSet<&'static str> = BTreeSet::new();
    if hint("readOnlyHint") || any_word(&text, READ) {
        found.insert("reads_files");
    }
    if hint("destructiveHint") || any_word(&text, DELETE) {
        found.extend(["writes_files", "deletes_files"]);
    }
    if hint("writeHint") || any_word(&text, WRITE) {
        found.insert("writes_files");
    }
    if any_word(&text, SHELL) {
        found.insert("runs_shell");
    }
    if any_word(&text, SECRET) || has_api_key(&text) {
        found.insert("reads_secrets");
    }
    if any_word(&text, NETWORK) {
        found.insert("network_egress");
    }
    if any_word(&text, MODEL) {
        found.insert("uses_model_sampling");
    }
    if any_word(&text, PERMISSION) {
        found.insert("changes_permissions");
    }
    if found.is_empty() {
        return vec!["unknown"];
    }
    found.into_iter().collect()
}

/// `_risk_level_for_capabilities`.
fn risk_level(capabilities: &[&str]) -> &'static str {
    let any = |names: &[&str]| capabilities.iter().any(|name| names.contains(name));
    if any(&["deletes_files", "reads_secrets", "runs_shell"]) {
        "high"
    } else if any(&[
        "writes_files",
        "network_egress",
        "uses_model_sampling",
        "changes_permissions",
    ]) {
        "medium"
    } else {
        "info"
    }
}

/// `_mcp_schema_signal_text`: keys and strings in declaration order. A
/// mapping drops its empty parts; a list keeps them, so two of its items
/// with an empty one between stay two spaces apart.
fn signal_text(value: &PyVal) -> String {
    match value {
        PyVal::Dict(entries) => {
            let mut parts: Vec<String> = Vec::new();
            for (key, item) in entries {
                if key == "$schema" || key == "$id" {
                    continue;
                }
                parts.push(key.clone());
                parts.push(signal_text(item));
            }
            parts.retain(|part| !part.is_empty());
            parts.join(" ")
        }
        PyVal::List(items) => items.iter().map(signal_text).collect::<Vec<_>>().join(" "),
        PyVal::Str(text) => text.clone(),
        _ => String::new(),
    }
}

/// `str.lower()` with the two letters `re.IGNORECASE` also folds onto an
/// ASCII one: dotless `ı` matches `i` and long `ſ` matches `s` in every
/// pattern and boundary class, so they read as those letters here. Every
/// other cased letter that matches ASCII under the flag already lowers to it.
fn folded(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .map(|character| match character {
            '\u{131}' => 'i',
            '\u{17f}' => 's',
            other => other,
        })
        .collect()
}

/// `(?<![a-z0-9])`/`(?![a-z0-9])` on folded text.
fn word_char(character: Option<char>) -> bool {
    character.is_some_and(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
}

fn bounded(text: &str, start: usize, end: usize) -> bool {
    !word_char(text[..start].chars().next_back()) && !word_char(text[end..].chars().next())
}

fn any_word(text: &str, words: &[&str]) -> bool {
    words.iter().any(|word| {
        text.match_indices(word)
            .any(|(start, _)| bounded(text, start, start + word.len()))
    })
}

/// `api[_\-\s]?key` between the same boundaries.
fn has_api_key(text: &str) -> bool {
    text.match_indices("api").any(|(start, _)| {
        let rest = &text[start + 3..];
        let mut ends = Vec::with_capacity(2);
        if rest.starts_with("key") {
            ends.push(start + 6);
        }
        if let Some(separator) = rest.chars().next() {
            if (separator == '_' || separator == '-' || is_python_space(separator))
                && rest[separator.len_utf8()..].starts_with("key")
            {
                ends.push(start + 3 + separator.len_utf8() + 3);
            }
        }
        ends.into_iter().any(|end| bounded(text, start, end))
    })
}

/// `Py_UNICODE_ISSPACE`, behind `str.strip()` and `\s`: Unicode whitespace
/// plus the four ASCII separator controls U+001C..U+001F.
fn is_python_space(character: char) -> bool {
    character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
}

/// The server's Cisco scanner layers as each tool inherits them: the
/// attestation keys dropped, marked unsigned and pointing back at the server.
fn inherited_layers(trust_layers: &PyVal, server: &str) -> Vec<PyVal> {
    let Some(layers) = trust_layers.as_list() else {
        return Vec::new();
    };
    let mut inherited = Vec::new();
    for layer in layers {
        let Some(entries) = layer.as_dict() else {
            continue;
        };
        if layer.get("layerType").and_then(PyVal::as_str) != Some("cisco_mcp_scanner") {
            continue;
        }
        let mut metadata: Vec<(String, PyVal)> = layer
            .get("metadata")
            .and_then(PyVal::as_dict)
            .unwrap_or(&[])
            .iter()
            .filter(|(key, _)| !ATTESTATION_KEYS.contains(&key.as_str()))
            .cloned()
            .collect();
        set_member(&mut metadata, "attestationStatus", str_val("unsigned"));
        set_member(&mut metadata, "inheritedFromServerItemId", str_val(server));
        let mut entries = entries.to_vec();
        set_member(&mut entries, "metadata", PyVal::Dict(metadata));
        inherited.push(PyVal::Dict(entries));
    }
    inherited
}

/// `fingerprint_mapping`: sha256 of the sorted, compact, ASCII `json.dumps`.
fn fingerprint(value: &PyVal) -> String {
    let mut encoded = String::new();
    dumps(&sorted(value), true, true, &mut encoded);
    sha256_hex(encoded.as_bytes())
}

fn sorted(value: &PyVal) -> PyVal {
    match value {
        PyVal::Dict(entries) => {
            let mut entries: Vec<(String, PyVal)> = entries
                .iter()
                .map(|(key, item)| (key.clone(), sorted(item)))
                .collect();
            entries.sort_by(|left, right| code_points(&left.0).cmp(code_points(&right.0)));
            PyVal::Dict(entries)
        }
        PyVal::List(items) => PyVal::List(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// `sort_keys` compares code points, and a mapped lone surrogate sorts at
/// the surrogate it stands for.
fn code_points(key: &str) -> impl Iterator<Item = u32> + '_ {
    key.chars().map(|character| {
        if in_surrogate_plane(character) {
            character as u32 - pyjson::SURROGATE_PLANE_BASE + 0xd800
        } else {
            character as u32
        }
    })
}

fn member<'a>(entries: &'a [(String, PyVal)], key: &str) -> Option<&'a PyVal> {
    entries
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

fn str_val(text: &str) -> PyVal {
    PyVal::Str(text.to_owned())
}

#[cfg(test)]
#[path = "mcp_tool_inventory_tests.rs"]
mod tests;
