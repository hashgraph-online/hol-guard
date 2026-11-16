//! The OpenAPI 3 half of `generate`: one `declarative-http` action per
//! operation whose path, parameters and JSON body a pack can express.

use crate::cloud_action_binding::valid_label;
use crate::cloud_action_classifier::classify;
use crate::cloud_pack::{MAX_ARGUMENTS, MAX_HOSTS};
use crate::cloud_pack_generate::{
    argument, method_class, object_arguments, push_action, response, snake, title, ActionParts,
    Draft, PLACEHOLDER_SCOPE,
};
use crate::cloud_pack_validate::valid_host;
use crate::cloud_pack_validate_request::path_placeholders;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];
const MAX_REF_HOPS: usize = 8;
const MAX_SCHEMA_DEPTH: usize = 32;
/// Schema nodes one operation may copy while inlining `$ref`s, so a document
/// of mutually referencing schemas cannot grow the draft without bound.
const MAX_SCHEMA_NODES: usize = 50_000;

type Refusal = (&'static str, &'static str);

/// Build every action of `document`, returning the pack hosts and auth mode.
pub(crate) fn build(
    document: &Value,
    provider: &str,
    host: Option<String>,
    draft: &mut Draft,
) -> Result<(Vec<String>, String), Refusal> {
    let version = document.get("openapi").and_then(Value::as_str);
    if !version.is_some_and(|version| version.starts_with("3.")) {
        return Err(("generate_openapi_unsupported", "/openapi/openapi"));
    }
    let mode = auth_mode(document);
    let mut hosts = BTreeSet::new();
    let paths = document.get("paths").and_then(Value::as_object);
    for (path, item) in paths.into_iter().flatten() {
        let mut item_budget = MAX_SCHEMA_NODES;
        let item = match item.get("$ref") {
            Some(_) => resolve(document, item, &mut item_budget),
            None => item.clone(),
        };
        for method in METHODS {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let at = format!("/openapi/paths/{}/{method}", pointer_escape(path));
            // The operation's own servers win over the path's, then the document's.
            let servers = [operation, &item, document]
                .into_iter()
                .find_map(|node| node.get("servers"));
            let Some((op_host, base)) = server(servers, host.as_deref())
                .filter(|(op_host, _)| hosts.contains(op_host) || hosts.len() < MAX_HOSTS)
            else {
                draft.note("server_unsupported", &at);
                continue;
            };
            let source = Source {
                document,
                host: &op_host,
                base: &base,
                path,
                method,
                mode: &mode,
            };
            let mut budget = MAX_SCHEMA_NODES;
            let built = operation_action(
                &source,
                operation,
                item.get("parameters"),
                provider,
                &at,
                draft,
                &mut budget,
            );
            if budget == 0 {
                draft.note("schema_budget_exhausted", &at);
            }
            match built {
                Some(()) => {
                    hosts.insert(op_host);
                }
                None => draft.note("operation_skipped", &at),
            }
        }
    }
    if hosts.is_empty() && server(document.get("servers"), host.as_deref()).is_none() {
        return Err(("generate_openapi_server_invalid", "/openapi/servers"));
    }
    Ok((hosts.into_iter().collect(), mode))
}

struct Source<'a> {
    document: &'a Value,
    host: &'a str,
    base: &'a str,
    path: &'a str,
    method: &'a str,
    mode: &'a str,
}

fn operation_action(
    source: &Source<'_>,
    operation: &Value,
    shared: Option<&Value>,
    provider: &str,
    at: &str,
    draft: &mut Draft,
    budget: &mut usize,
) -> Option<()> {
    let document = source.document;
    let method = source.method.to_ascii_uppercase();
    let mut arguments = Map::new();
    let mut renamed = BTreeMap::new();
    let mut query = Vec::new();
    for parameter in parameters(document, shared, operation, budget)? {
        let name = parameter.get("name").and_then(Value::as_str)?;
        let location = parameter.get("in").and_then(Value::as_str)?;
        let schema = resolve(
            document,
            parameter.get("schema").unwrap_or(&Value::Null),
            budget,
        );
        let required = location == "path" || parameter.get("required") == Some(&json!(true));
        let arg = snake(name)
            .filter(|arg| !arguments.contains_key(arg) && arguments.len() < MAX_ARGUMENTS);
        match (location, arg, argument(&schema, required)) {
            ("path", Some(arg), Some(spec)) if path_type(&spec) => {
                renamed.insert(name.to_owned(), arg.clone());
                arguments.insert(arg, spec);
            }
            ("path", _, _) => return None,
            ("query", Some(arg), Some(spec)) if query_name(name) && !is_array(&spec) => {
                query.push(json!({ "name": name, "value": { "arg": { "name": arg } } }));
                arguments.insert(arg, spec);
            }
            (_, _, _) if required => {
                draft.note(
                    "required_argument_unsupported",
                    &format!("{at}/parameters/{name}"),
                );
            }
            _ => draft.note("argument_skipped", &format!("{at}/parameters/{name}")),
        }
    }
    let path = rewrite_path(source.base, source.path, &renamed)?;
    let body_schema = body_schema(document, operation, budget);
    let mut request = json!({
        "method": method,
        "host": source.host,
        "path": path,
        "query": query,
        "maxPages": 1,
    });
    match (&body_schema, method.as_str()) {
        (Some(_), "GET" | "DELETE") => draft.note("body_ignored", at),
        (Some(schema), _) => {
            let mut names = BTreeMap::new();
            let at = format!("{at}/requestBody");
            object_arguments(schema, &mut arguments, &mut names, draft, &at, true);
            if names.is_empty() {
                return None;
            }
            let fields: Vec<Value> = names
                .iter()
                .map(|(key, arg)| json!({ "name": key, "value": { "arg": arg } }))
                .collect();
            request["body"] = json!({ "object": fields });
        }
        (None, _) if operation.get("requestBody").is_some() => {
            draft.note("body_unsupported", at);
            // An action that left out a body the provider requires could never succeed.
            let body = resolve(document, operation.get("requestBody")?, budget);
            if body.get("required") == Some(&json!(true)) {
                return None;
            }
        }
        (None, _) => {}
    }
    let name = operation
        .get("operationId")
        .and_then(Value::as_str)
        .map_or_else(
            || format!("{} {}", source.method, source.path),
            str::to_owned,
        );
    let proposal = method_class(&method, classify(&name, body_schema.as_ref()));
    let (response_schema, empty_ok) = response_schema(document, operation, budget);
    let response = response(response_schema.as_ref(), empty_ok, draft, at);
    let action_id = draft.action_id(provider, &name)?;
    let summary = operation.get("summary").and_then(Value::as_str);
    let link = Some(&name)
        .filter(|name| valid_label(name) && name.len() <= 128)
        .map_or(Value::Null, |name| json!({ "tool": name }));
    let scopes = scopes(document, operation, source.mode, draft, at);
    push_action(
        draft,
        ActionParts {
            action_id,
            title: title(summary, &name),
            link,
            executor: json!({ "kind": "declarative-http", "request": request }),
            arguments,
            proposal,
            response,
            scopes,
        },
    );
    Some(())
}

/// Shared path-item parameters merged with the operation's own, which replace
/// a shared one with the same `in` and `name`. `None` when one is unreadable.
fn parameters(
    document: &Value,
    shared: Option<&Value>,
    operation: &Value,
    budget: &mut usize,
) -> Option<Vec<Value>> {
    let mut merged: Vec<((String, String), Value)> = Vec::new();
    let listed = [shared, operation.get("parameters")];
    for parameter in listed
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .flatten()
    {
        let parameter = resolve(document, parameter, budget);
        let key = (
            parameter.get("in").and_then(Value::as_str)?.to_owned(),
            parameter.get("name").and_then(Value::as_str)?.to_owned(),
        );
        match merged.iter_mut().find(|(seen, _)| *seen == key) {
            Some(slot) => slot.1 = parameter,
            None => merged.push((key, parameter)),
        }
    }
    Some(merged.into_iter().map(|(_, parameter)| parameter).collect())
}

/// A pack path placeholder holds a required string or integer only.
fn path_type(spec: &Value) -> bool {
    matches!(
        spec.get("type").and_then(Value::as_str),
        Some("string" | "integer")
    )
}

fn is_array(spec: &Value) -> bool {
    spec.get("type").and_then(Value::as_str) == Some("array")
}

/// The pack path for `base` + `path`, with each `{param}` renamed to its argument.
fn rewrite_path(base: &str, path: &str, renamed: &BTreeMap<String, String>) -> Option<String> {
    let mut out = String::from(base);
    for segment in path.trim_start_matches('/').split('/') {
        out.push('/');
        match segment
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
        {
            Some(name) => out.push_str(&format!("{{{}}}", renamed.get(name)?)),
            None => out.push_str(segment),
        }
    }
    let placeholders = path_placeholders(&out)?;
    (placeholders.len() == renamed.len()).then_some(out)
}

fn body_schema(document: &Value, operation: &Value, budget: &mut usize) -> Option<Value> {
    let body = resolve(document, operation.get("requestBody")?, budget);
    let schema = body
        .get("content")?
        .get("application/json")?
        .get("schema")?;
    let schema = resolve(document, schema, budget);
    schema.get("properties").is_some().then_some(schema)
}

/// The first success response's JSON schema, and whether that success
/// carries no body at all (a `204`, or a `2xx` with no `content`).
fn response_schema(
    document: &Value,
    operation: &Value,
    budget: &mut usize,
) -> (Option<Value>, bool) {
    let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
        return (None, false);
    };
    let Some((code, chosen)) = responses.iter().find(|(code, _)| code.starts_with('2')) else {
        return (None, false);
    };
    let chosen = resolve(document, chosen, budget);
    let content = chosen
        .get("content")
        .filter(|content| content.as_object().is_some_and(|map| !map.is_empty()));
    let empty = code == "204" || content.is_none();
    let schema = content
        .and_then(|content| content.get("application/json"))
        .and_then(|json| json.get("schema"))
        .map(|schema| resolve(document, schema, budget));
    (schema, empty)
}

/// Provider scopes for one operation, from its own or the document's `security`.
fn scopes(
    document: &Value,
    operation: &Value,
    mode: &str,
    draft: &mut Draft,
    at: &str,
) -> BTreeSet<String> {
    if mode == "none" {
        return BTreeSet::new();
    }
    let schemes = document.pointer("/components/securitySchemes");
    let requirements = operation
        .get("security")
        .or_else(|| document.get("security"));
    let mut scopes = BTreeSet::new();
    for requirement in requirements.and_then(Value::as_array).into_iter().flatten() {
        for (scheme, listed) in requirement.as_object().into_iter().flatten() {
            let kind = schemes
                .and_then(|schemes| schemes.get(scheme))
                .and_then(|scheme| scheme.get("type"))
                .and_then(Value::as_str);
            if matches!(kind, Some("oauth2" | "openIdConnect")) {
                let names = listed
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str);
                scopes.extend(
                    names
                        .filter(|name| valid_label(name) && name.len() <= 128)
                        .map(str::to_owned),
                );
            }
        }
    }
    if scopes.is_empty() {
        draft.note("scope_placeholder", at);
        scopes.insert(PLACEHOLDER_SCOPE.to_owned());
    }
    scopes
}

fn auth_mode(document: &Value) -> String {
    let schemes = document
        .pointer("/components/securitySchemes")
        .and_then(Value::as_object);
    let kinds: BTreeSet<&str> = schemes
        .into_iter()
        .flatten()
        .filter_map(|(_, scheme)| scheme.get("type").and_then(Value::as_str))
        .collect();
    if kinds.contains("oauth2") || kinds.contains("openIdConnect") {
        "oauth2".into()
    } else if kinds.is_empty() {
        "none".into()
    } else {
        "api-key".into()
    }
}

/// The host and base path of the first usable server: an `https` URL with a
/// concrete host, or, when the author named a host, a relative URL or one
/// whose host is templated. The named host always wins; the base path is kept.
fn server(servers: Option<&Value>, given: Option<&str>) -> Option<(String, String)> {
    let urls = servers.and_then(Value::as_array);
    let mut urls = urls
        .into_iter()
        .flatten()
        .filter_map(|server| server.get("url")?.as_str());
    let found = urls.find_map(|url| {
        let (host, path) = match url.strip_prefix("https://") {
            Some(rest) => rest.split_once('/').unwrap_or((rest, "")),
            None if url.starts_with('/') => ("", url),
            None => return None,
        };
        let path = path.trim_matches('/');
        let base = if path.is_empty() {
            String::new()
        } else {
            format!("/{path}")
        };
        if base.contains('{') {
            return None;
        }
        let host = host.to_ascii_lowercase();
        let host = match given {
            Some(given) => given.to_owned(),
            None if !host.contains('{') && valid_host(&host) => host,
            None => return None,
        };
        Some((host, base))
    });
    found.or_else(|| given.map(|host| (host.to_owned(), String::new())))
}

fn query_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'[' | b']'))
}

fn pointer_escape(path: &str) -> String {
    path.replace('~', "~0").replace('/', "~1")
}

/// `value` with local `$ref`s inlined, to a fixed hop count, depth and node
/// budget. A reference that leaves the document, cycles past the hop count or
/// runs the budget out becomes `null`, which every caller treats as "not
/// expressible".
fn resolve(document: &Value, value: &Value, budget: &mut usize) -> Value {
    inline(document, value, 0, 0, budget)
}

fn inline(document: &Value, value: &Value, hops: usize, depth: usize, budget: &mut usize) -> Value {
    if *budget == 0 || hops > MAX_REF_HOPS || depth > MAX_SCHEMA_DEPTH {
        return Value::Null;
    }
    *budget -= 1;
    match value {
        Value::Object(map) => {
            if let Some(Value::String(reference)) = map.get("$ref") {
                let target = reference
                    .strip_prefix('#')
                    .and_then(|pointer| document.pointer(pointer));
                return target.map_or(Value::Null, |target| {
                    inline(document, target, hops + 1, depth, budget)
                });
            }
            let mut out = Map::new();
            for (key, item) in map {
                out.insert(key.clone(), inline(document, item, hops, depth + 1, budget));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| inline(document, item, hops, depth + 1, budget))
                .collect(),
        ),
        other => other.clone(),
    }
}
