//! Draft a cloud action pack from an OpenAPI document or an MCP tool list.
//!
//! The draft is a starting point for a reviewed pack, never a pack to ship:
//! it carries no fixtures, so `validate` refuses it until an author adds a
//! safe and a risky case for every action. Everything the generator proposes
//! leans strict. The class comes from the name classifier and only an HTTP
//! method can tighten it further, or lower a nameless `GET` to `read`; every
//! non-read action is proposed `permanent`; and request bounds come from the
//! source schema when it states them, or from fixed limits when it does not.

use crate::cloud_action_classifier::{rank, Proposal};
use crate::cloud_action_v2::class_effect;
use crate::cloud_pack::{MAX_ACTIONS, MAX_ARGUMENTS, PACK_SCHEMA};
use crate::cloud_pack_validate::{compile_whole, valid_host};
use guard_contracts::ActionClassV2;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Longest string a draft accepts when the source schema states no bound.
pub(crate) const DEFAULT_TEXT_LENGTH: u64 = 1_024;
const MAX_TEXT_LENGTH: u64 = 65_536;
pub(crate) const DEFAULT_ARRAY_ITEMS: u64 = 100;
const MAX_ARRAY_ITEMS: u64 = 1_000;
const SAFE_INTEGER: i64 = 1 << 53;
const MAX_TITLE_CHARS: usize = 120;
/// Scope label used when the source names no provider permission.
pub(crate) const PLACEHOLDER_SCOPE: &str = "api";

/// Notes and proposals collected while one draft is built.
#[derive(Default)]
pub(crate) struct Draft {
    pub actions: Vec<Value>,
    pub proposals: Vec<Value>,
    pub notes: Vec<Value>,
    pub scopes: BTreeSet<String>,
    ids: BTreeSet<String>,
}

impl Draft {
    pub fn note(&mut self, code: &str, at: &str) {
        self.notes.push(json!({ "code": code, "at": at }));
    }

    /// A unique action id under `provider`, or `None` once the pack is full.
    pub fn action_id(&mut self, provider: &str, name: &str) -> Option<String> {
        if self.actions.len() >= MAX_ACTIONS {
            return None;
        }
        let base = snake(name).unwrap_or_else(|| "action".into());
        let base = if base.starts_with('_') {
            format!("action{base}")
        } else {
            base
        };
        let mut id = format!("{provider}.{base}");
        let mut suffix = 2;
        while self.ids.contains(&id) {
            id = format!("{provider}.{base}_{suffix}");
            suffix += 1;
        }
        self.ids.insert(id.clone());
        Some(id)
    }
}

/// The pieces of one action that differ between the two source formats.
pub(crate) struct ActionParts {
    pub action_id: String,
    pub title: String,
    pub link: Value,
    pub executor: Value,
    pub arguments: Map<String, Value>,
    pub proposal: Proposal,
    pub response: Value,
    pub scopes: BTreeSet<String>,
}

pub(crate) use crate::cloud_pack_generate_response::response;

pub(crate) fn push_action(draft: &mut Draft, parts: ActionParts) {
    let class = parts.proposal.class;
    let read = class == ActionClassV2::Read;
    let mut facts = json!({ "class": class });
    if !read {
        facts["reversibility"] = json!({ "const": "permanent" });
    }
    let safety = json!({
        "effect": class_effect(class),
        "requiredCapabilities": ["bounded-output", "egress-pinned"],
        "idempotency": if read { "safe-read" } else { "none" },
        "scopes": parts.scopes,
        "maxItems": if read { 100 } else { 1 },
        "minIntervalMs": if read { 1_000 } else { 3_000 },
        "timeoutMs": if read { 10_000 } else { 15_000 },
    });
    draft.scopes.extend(parts.scopes);
    draft.proposals.push(json!({
        "actionId": parts.action_id,
        "class": class,
        "destructive": parts.proposal.destructive,
        "reversibility": if read { Value::Null } else { json!("permanent") },
        "evidence": parts.proposal.evidence,
    }));
    let mut action = json!({
        "actionId": parts.action_id,
        "title": parts.title,
        "executor": parts.executor,
        "arguments": parts.arguments,
        "facts": facts,
        "response": parts.response,
        "safety": safety,
        "fixtures": [],
    });
    if !parts.link.is_null() {
        action["link"] = parts.link;
    }
    draft.actions.push(action);
}

/// Tighten a classifier proposal by HTTP method. Only a `GET` the name gave
/// no evidence for drops to `read`; a `DELETE` is never below `delete`.
pub(crate) fn method_class(method: &str, mut proposal: Proposal) -> Proposal {
    match method {
        "GET" if proposal.evidence.is_empty() => {
            proposal.class = ActionClassV2::Read;
            proposal.evidence.push("method:GET".into());
        }
        "DELETE" if rank(proposal.class) < rank(ActionClassV2::Delete) => {
            proposal.class = ActionClassV2::Delete;
            proposal.destructive = true;
            proposal.evidence = vec!["method:DELETE".into()];
        }
        _ => {}
    }
    proposal
}

/// The argument spec for one JSON Schema, or `None` when no pack type fits.
pub(crate) fn argument(schema: &Value, required: bool) -> Option<Value> {
    // A source bound of zero admits nothing a pack can express; never widen it.
    let zero = |schema: &Value, key: &str| schema.get(key).and_then(Value::as_u64) == Some(0);
    if zero(schema, "maxLength") || zero(schema, "maxItems") {
        return None;
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("string") => Some(text_spec(schema, required)),
        Some("integer") => integer_spec(schema, required),
        Some("boolean") => Some(json!({ "type": "boolean", "required": required })),
        Some("array") => {
            let items = schema.get("items")?;
            if items.get("type").and_then(Value::as_str) != Some("string")
                || zero(items, "maxLength")
            {
                return None;
            }
            let mut rule = text_spec(items, false);
            let rule = rule.as_object_mut()?;
            rule.remove("type");
            rule.remove("required");
            let min = schema.get("minItems").and_then(Value::as_u64).unwrap_or(0);
            let max = schema
                .get("maxItems")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_ARRAY_ITEMS)
                .clamp(1, MAX_ARRAY_ITEMS);
            Some(json!({
                "type": "array",
                "required": required,
                "minItems": min.min(max),
                "maxItems": max,
                "items": rule,
            }))
        }
        _ => None,
    }
}

fn text_spec(schema: &Value, required: bool) -> Value {
    let max = schema
        .get("maxLength")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TEXT_LENGTH)
        .clamp(1, MAX_TEXT_LENGTH);
    let mut spec = json!({ "type": "string", "required": required, "maxLength": max });
    if let Some(pattern) = enum_pattern(schema).or_else(|| anchored(schema)) {
        spec["pattern"] = json!(pattern);
    }
    spec
}

/// A whole-value pattern for a string enum, so only the listed values pass.
fn enum_pattern(schema: &Value) -> Option<String> {
    let values = schema.get("enum")?.as_array()?;
    let words: Option<Vec<String>> = values
        .iter()
        .map(|value| value.as_str().map(regex::escape))
        .collect();
    let words = words.filter(|words| !words.is_empty())?;
    let pattern = format!("^(?:{})$", words.join("|"));
    compile_whole(&pattern).map(|_| pattern)
}

/// The source pattern when it already pins the whole value.
fn anchored(schema: &Value) -> Option<String> {
    let pattern = schema.get("pattern")?.as_str()?;
    (pattern.starts_with('^') && pattern.ends_with('$') && compile_whole(pattern).is_some())
        .then(|| pattern.to_owned())
}

/// Integer bounds rounded inward, with the exclusive forms of OpenAPI 3.0
/// (`exclusiveMinimum: true`) and 3.1 (`exclusiveMinimum: 5`) honoured.
fn integer_spec(schema: &Value, required: bool) -> Option<Value> {
    let number = |key: &str| schema.get(key).and_then(Value::as_f64);
    let flag = |key: &str| schema.get(key).and_then(Value::as_bool) == Some(true);
    let low = match (number("minimum"), number("exclusiveMinimum")) {
        (Some(min), _) if flag("exclusiveMinimum") => Some(min.floor() + 1.0),
        (min, exclusive) => [min.map(f64::ceil), exclusive.map(|n| n.floor() + 1.0)]
            .into_iter()
            .flatten()
            .reduce(f64::max),
    };
    let high = match (number("maximum"), number("exclusiveMaximum")) {
        (Some(max), _) if flag("exclusiveMaximum") => Some(max.ceil() - 1.0),
        (max, exclusive) => [max.map(f64::floor), exclusive.map(|n| n.ceil() - 1.0)]
            .into_iter()
            .flatten()
            .reduce(f64::min),
    };
    let clamp = |value: f64| (value.clamp(-SAFE_INTEGER as f64, SAFE_INTEGER as f64)) as i64;
    let minimum = low.map_or(0, clamp);
    let maximum = high.map_or(i64::from(i32::MAX), clamp);
    (minimum <= maximum).then(|| {
        json!({ "type": "integer", "required": required, "minimum": minimum, "maximum": maximum })
    })
}

/// Arguments for the top-level properties of an object schema. Properties no
/// pack type can bound are left out; a left-out required one is noted, and
/// the result is `false` when any required property was left out.
///
/// With `rename` off (an MCP tool, whose call keeps the caller's names) a
/// property whose name is not already `snake_case` is left out rather than
/// renamed, since nothing would translate the new name back.
pub(crate) fn object_arguments(
    schema: &Value,
    into: &mut Map<String, Value>,
    names: &mut BTreeMap<String, String>,
    draft: &mut Draft,
    at: &str,
    rename: bool,
) -> bool {
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return true;
    };
    let required: BTreeSet<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut complete = true;
    for (key, property) in properties {
        let wanted = required.contains(key.as_str());
        let spec = argument(property, wanted);
        let name = snake(key)
            .filter(|name| rename || name == key)
            .filter(|name| !into.contains_key(name));
        match (spec, name) {
            (Some(spec), Some(name)) if into.len() < MAX_ARGUMENTS => {
                into.insert(name.clone(), spec);
                names.insert(key.clone(), name);
            }
            _ if wanted => {
                complete = false;
                draft.note("required_argument_unsupported", &format!("{at}/{key}"));
            }
            _ => draft.note("argument_skipped", &format!("{at}/{key}")),
        }
    }
    complete
}

/// `camelCase`, `kebab-case` and spaced names as `snake_case`, at most 64 bytes.
pub(crate) fn snake(name: &str) -> Option<String> {
    let mut out = String::new();
    let mut previous_lower = false;
    for ch in name.chars() {
        if ch.is_ascii_uppercase() {
            if previous_lower {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            previous_lower = false;
        } else if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            out.push(ch);
            previous_lower = true;
        } else if !out.ends_with('_') {
            out.push('_');
            previous_lower = false;
        }
    }
    let trimmed = out.trim_matches('_');
    let mut name: String = trimmed.chars().take(64).collect();
    name = name.trim_end_matches('_').to_owned();
    if name.is_empty() {
        return None;
    }
    if name.as_bytes()[0].is_ascii_digit() {
        name = format!("_{name}").chars().take(64).collect();
    }
    Some(name)
}

/// One display line: control characters dropped, at most 120 characters.
pub(crate) fn title(text: Option<&str>, fallback: &str) -> String {
    let clean = |text: &str| -> String {
        let line: String = text.chars().filter(|ch| !ch.is_control()).collect();
        line.trim().chars().take(MAX_TITLE_CHARS).collect()
    };
    let chosen = text.map(clean).filter(|line| !line.is_empty());
    chosen.unwrap_or_else(|| clean(fallback))
}

/// Answer a `generate` request.
pub fn generate(request: &mut Map<String, Value>) -> Result<Value, Refusal> {
    let provider = text_field(request, "providerId").ok_or(("request_invalid", "/providerId"))?;
    if !provider_id(&provider) {
        return Err(("request_invalid", "/providerId"));
    }
    let name = text_field(request, "providerName").unwrap_or_else(|| provider.clone());
    let publisher = text_field(request, "publisher").unwrap_or_else(|| name.clone());
    let host = text_field(request, "host");
    if host.as_deref().is_some_and(|host| !valid_host(host)) {
        return Err(("request_invalid", "/host"));
    }
    let mut draft = Draft::default();
    let (openapi, tools) = source(request)?;
    let (hosts, mode) = match (openapi, tools) {
        (Some(document), None) => {
            crate::cloud_pack_generate_openapi::build(&document, &provider, host, &mut draft)?
        }
        (None, Some(Value::Array(tools))) => {
            let host = host.ok_or(("request_invalid", "/host"))?;
            let mode = text_field(request, "authMode").unwrap_or_else(|| "none".into());
            if !matches!(mode.as_str(), "none" | "oauth2" | "api-key") {
                return Err(("request_invalid", "/authMode"));
            }
            crate::cloud_pack_generate_mcp::build(&tools, &provider, &mode, &mut draft);
            (vec![host], mode)
        }
        _ => return Err(("request_invalid", "/openapi")),
    };
    if draft.actions.is_empty() {
        return Err(("generate_no_actions", ""));
    }
    let pack = json!({
        "schema": PACK_SCHEMA,
        "provider": {
            "id": provider,
            "name": title(Some(&name), &provider),
            "publisher": { "name": title(Some(&publisher), &provider), "verified": false },
        },
        "hosts": hosts,
        "auth": { "mode": mode, "scopes": draft.scopes },
        "actions": draft.actions,
    });
    Ok(json!({ "pack": pack, "proposals": draft.proposals, "notes": draft.notes }))
}

/// The OpenAPI document or MCP tool list, given inline or as the exported
/// file's text under `document` with `from` naming its format. Text is parsed
/// strictly, so a duplicate key cannot hide a second definition.
fn source(request: &mut Map<String, Value>) -> Result<(Option<Value>, Option<Value>), Refusal> {
    let Some(Value::String(text)) = request.remove("document") else {
        return Ok((request.remove("openapi"), request.remove("mcpTools")));
    };
    if request.contains_key("openapi") || request.contains_key("mcpTools") {
        return Err(("request_invalid", "/document"));
    }
    let document = crate::cloud_action_canonical::parse_strict(text.as_bytes())
        .map_err(|_| ("generate_document_invalid", "/document"))?;
    match (text_field(request, "from").as_deref(), document) {
        (Some("openapi"), document) => Ok((Some(document), None)),
        (Some("mcp"), Value::Object(mut listing)) => match listing.remove("tools") {
            Some(tools @ Value::Array(_)) => Ok((None, Some(tools))),
            _ => Err(("generate_document_invalid", "/document")),
        },
        (Some("mcp"), tools @ Value::Array(_)) => Ok((None, Some(tools))),
        (Some("mcp"), _) => Err(("generate_document_invalid", "/document")),
        _ => Err(("request_invalid", "/from")),
    }
}

type Refusal = (&'static str, &'static str);

fn text_field(request: &mut Map<String, Value>, key: &str) -> Option<String> {
    match request.remove(key) {
        Some(Value::String(text)) => Some(text),
        _ => None,
    }
}

fn provider_id(value: &str) -> bool {
    (2..=32).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
