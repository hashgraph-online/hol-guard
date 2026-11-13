//! The OpenAPI 3 half of `generate`: one `declarative-http` action per
//! operation whose path, parameters and JSON body a pack can express.

use crate::cloud_action_binding::valid_label;
use crate::cloud_action_classifier::classify;
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
/// Schema nodes one draft may copy while inlining `$ref`s, so a document of
/// mutually referencing schemas cannot grow the draft without bound.
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
    let (server_host, base) = server(document);
    let host = host
        .or(server_host)
        .ok_or(("generate_openapi_server_invalid", "/openapi/servers"))?;
    let mode = auth_mode(document);
    let mut budget = MAX_SCHEMA_NODES;
    let paths = document.get("paths").and_then(Value::as_object);
    for (path, item) in paths.into_iter().flatten() {
        let item = match item.get("$ref") {
            Some(_) => resolve(document, item, &mut budget),
            None => item.clone(),
        };
        for method in METHODS {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let at = format!("/openapi/paths/{}/{method}", pointer_escape(path));
            let shared = item.get("parameters");
            let source = Source {
                document,
                host: &host,
                base: &base,
                path,
                method,
                mode: &mode,
            };
            if operation_action(
                &source,
                operation,
                shared,
                provider,
                &at,
                draft,
                &mut budget,
            )
            .is_none()
            {
                draft.note("operation_skipped", &at);
            }
        }
    }
    Ok((vec![host], mode))
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
    let parameters = shared
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            operation
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        );
    for parameter in parameters {
        let parameter = resolve(document, parameter, budget);
        let name = parameter.get("name").and_then(Value::as_str)?;
        let location = parameter.get("in").and_then(Value::as_str)?;
        let schema = resolve(
            document,
            parameter.get("schema").unwrap_or(&Value::Null),
            budget,
        );
        let required = location == "path" || parameter.get("required") == Some(&json!(true));
        let arg = snake(name).filter(|arg| !arguments.contains_key(arg));
        match (location, arg, argument(&schema, required)) {
            ("path", Some(arg), Some(spec)) => {
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
            object_arguments(schema, &mut arguments, &mut names, draft, &at);
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
    let response_schema = response_schema(document, operation, budget);
    let response = response(response_schema.as_ref(), draft, at);
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

fn response_schema(document: &Value, operation: &Value, budget: &mut usize) -> Option<Value> {
    let responses = operation.get("responses")?.as_object()?;
    let (_, chosen) = responses.iter().find(|(code, _)| code.starts_with('2'))?;
    let chosen = resolve(document, chosen, budget);
    let schema = chosen
        .get("content")?
        .get("application/json")?
        .get("schema")?;
    Some(resolve(document, schema, budget))
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

/// The host and base path of the first `https` server, when it is concrete.
fn server(document: &Value) -> (Option<String>, String) {
    let url = document.pointer("/servers/0/url").and_then(Value::as_str);
    let Some(rest) = url.and_then(|url| url.strip_prefix("https://")) else {
        return (None, String::new());
    };
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = host.to_ascii_lowercase();
    let path = path.trim_end_matches('/');
    let base = if path.is_empty() {
        String::new()
    } else {
        format!("/{path}")
    };
    let concrete = !base.contains('{') && valid_host(&host);
    if concrete {
        (Some(host), base)
    } else {
        (None, String::new())
    }
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
