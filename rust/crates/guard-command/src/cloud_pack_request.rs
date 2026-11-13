//! Argument checks and request rendering for `declarative-http` actions.
//!
//! Rendering builds the one request an action may send; it never sends it.
//! Every argument is checked against its declared bounds first. Path values
//! are percent-encoded per segment, query values as form data, and the body is
//! written in template order. The finished URL is parsed again and refused
//! unless it is HTTPS on the declared host under the template's literal path
//! prefix, so no argument can move the request elsewhere.

use crate::cloud_pack::*;
use crate::cloud_pack_validate_request::custom_method;
use serde::Serialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArgumentError {
    pub code: &'static str,
    pub argument: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedRequest {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<[String; 2]>,
    pub body: Option<String>,
    pub max_pages: u32,
}

fn error(code: &'static str, argument: Option<&str>) -> ArgumentError {
    ArgumentError {
        code,
        argument: argument.map(str::to_owned),
    }
}

/// Check caller arguments against an action's declared bounds.
pub fn check_arguments<'a>(
    action: &PackAction,
    args: &'a Value,
) -> Result<&'a Map<String, Value>, ArgumentError> {
    let record = args
        .as_object()
        .ok_or_else(|| error("not_an_object", None))?;
    let mut open_bytes = 0_usize;
    for (name, value) in record {
        if action.arguments.contains_key(name) {
            continue;
        }
        let Some(open) = &action.open_arguments else {
            return Err(error("unknown_argument", Some(name)));
        };
        if !crate::cloud_pack_validate::mcp_name(name) {
            return Err(error("unknown_argument", Some(name)));
        }
        // Count each entry as it is encoded, name and separators included,
        // so many empty values under long names still add up.
        let entry = json_len(&Value::String(name.clone())) + json_len(value) + 2;
        open_bytes = open_bytes.saturating_add(entry);
        if open_bytes > open.max_bytes as usize {
            return Err(error("open_arguments_too_large", Some(name)));
        }
    }
    for (name, spec) in &action.arguments {
        let Some(value) = record.get(name) else {
            if spec.required() {
                return Err(error("missing_argument", Some(name)));
            }
            continue;
        };
        check_value(spec, value).map_err(|code| error(code, Some(name)))?;
    }
    Ok(record)
}

fn check_value(spec: &ArgumentSpec, value: &Value) -> Result<(), &'static str> {
    match spec {
        ArgumentSpec::Integer {
            minimum, maximum, ..
        } => value
            .as_i64()
            .filter(|n| (*minimum..=*maximum).contains(n))
            .map(|_| ())
            .ok_or("invalid_argument"),
        ArgumentSpec::Boolean { .. } => value.as_bool().map(|_| ()).ok_or("invalid_argument"),
        ArgumentSpec::Json {
            max_bytes,
            max_items,
            ..
        } => {
            let shaped = value.is_object() || value.is_array();
            let fits = shaped && json_len(value) <= *max_bytes as usize;
            let counted = max_items.is_none_or(|max| {
                value
                    .as_array()
                    .is_some_and(|list| list.len() <= max as usize)
            });
            (fits && counted).then_some(()).ok_or("invalid_argument")
        }
        ArgumentSpec::String { .. } => check_text(spec.text_rule().as_ref(), value),
        ArgumentSpec::Array {
            min_items,
            max_items,
            items,
            ..
        } => {
            let list = value.as_array().ok_or("invalid_argument")?;
            if list.len() < *min_items as usize || list.len() > *max_items as usize {
                return Err("invalid_argument");
            }
            list.iter()
                .try_for_each(|item| check_text(Some(items), item))
        }
    }
}

/// The serialized size of a value; one that cannot be written counts as too large.
fn json_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

pub(crate) fn check_text(rule: Option<&TextRule>, value: &Value) -> Result<(), &'static str> {
    let rule = rule.ok_or("invalid_argument")?;
    let text = value.as_str().ok_or("invalid_argument")?;
    if text.trim().is_empty() || text.chars().count() > rule.max_length as usize {
        return Err("invalid_argument");
    }
    if let Some(pattern) = &rule.pattern {
        let compiled =
            crate::cloud_pack_validate::compile_whole(pattern).ok_or("invalid_argument")?;
        if !compiled.is_match(text) {
            return Err("invalid_argument");
        }
    }
    if let Some(forbidden) = &rule.forbidden {
        let compiled = crate::cloud_pack_validate::compile(forbidden).ok_or("invalid_argument")?;
        if compiled.is_match(text) {
            return Err("forbidden_content");
        }
    }
    Ok(())
}

/// Render the exact request for checked arguments.
pub fn render(action: &PackAction, args: &Value) -> Result<RenderedRequest, ArgumentError> {
    let Executor::DeclarativeHttp { request } = &action.executor else {
        return Err(error("executor_not_renderable", None));
    };
    let record = check_arguments(action, args)?;
    let path = render_path(&request.path, record)?;
    let mut url = format!("https://{}{}", request.host, path);
    let query = render_query(&request.query, record)?;
    if !query.is_empty() {
        url.push('?');
        url.push_str(&query);
    }
    confine(&url, request)?;
    let mut headers: Vec<[String; 2]> = request
        .headers
        .iter()
        .map(|header| [header.name.clone(), header.value.clone()])
        .collect();
    let body = match &request.body {
        Some(template) => {
            headers.push([
                "content-type".into(),
                "application/json; charset=utf-8".into(),
            ]);
            Some(render_body(template, record)?)
        }
        None => None,
    };
    Ok(RenderedRequest {
        method: request.method.as_str(),
        url,
        headers,
        body,
        max_pages: request.max_pages,
    })
}

fn refused(argument: Option<&str>) -> ArgumentError {
    error("render_refused", argument)
}

fn render_path(template: &str, args: &Map<String, Value>) -> Result<String, ArgumentError> {
    let mut out = String::new();
    for segment in template[1..].split('/') {
        let (inner, verb) = custom_method(segment).ok_or_else(|| refused(None))?;
        let Some(inner) = inner
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
        else {
            out.push('/');
            out.push_str(segment);
            continue;
        };
        let (name, spans) = inner
            .strip_suffix('*')
            .map_or((inner, false), |name| (name, true));
        let value = match args.get(name) {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Number(number)) if number.as_i64().is_some() => number.to_string(),
            _ => return Err(refused(Some(name))),
        };
        let parts: Vec<&str> = if spans {
            value.split('/').collect()
        } else {
            vec![value.as_str()]
        };
        for part in parts {
            if dot_segment(part) || part.chars().any(char::is_control) {
                return Err(refused(Some(name)));
            }
            out.push('/');
            out.push_str(&encode(part, false));
        }
        if let Some(verb) = verb {
            out.push(':');
            out.push_str(verb);
        }
    }
    Ok(out)
}

/// Empty, `.` or `..`, counting look-alike full stops as dots.
fn dot_segment(part: &str) -> bool {
    let folded: String = part
        .chars()
        .map(|c| match c {
            '\u{FF0E}' | '\u{3002}' | '\u{FF61}' | '\u{2024}' | '\u{FE52}' => '.',
            other => other,
        })
        .collect();
    folded.is_empty() || folded == "." || folded == ".."
}

fn render_query(params: &[QueryParam], args: &Map<String, Value>) -> Result<String, ArgumentError> {
    let mut pairs = Vec::new();
    for param in params {
        let value = match &param.value {
            ValueSource::Const(value) => Some(value),
            ValueSource::Arg { name, default } => args.get(name).or(default.as_ref()),
        };
        let Some(value) = value else { continue };
        if let Value::Array(items) = value {
            for item in items {
                let Value::String(text) = item else {
                    return Err(refused(Some(&param.name)));
                };
                if text.chars().any(char::is_control) {
                    return Err(refused(Some(&param.name)));
                }
                pairs.push(format!(
                    "{}={}",
                    query_name(&param.name),
                    encode(text, true)
                ));
            }
            continue;
        }
        let text = match value {
            Value::String(text) if !text.chars().any(char::is_control) => text.clone(),
            Value::Number(number) if number.as_i64().is_some() => number.to_string(),
            Value::Bool(flag) => flag.to_string(),
            _ => return Err(refused(Some(&param.name))),
        };
        pairs.push(format!(
            "{}={}",
            query_name(&param.name),
            encode(&text, true)
        ));
    }
    Ok(pairs.join("&"))
}

/// A declared parameter name as sent; an OData `$` prefix stays literal.
fn query_name(name: &str) -> String {
    match name.strip_prefix('$') {
        Some(rest) => format!("${}", encode(rest, true)),
        None => encode(name, true),
    }
}

/// Percent-encode one path segment, or one form value when `form` is set
/// (the WHATWG `application/x-www-form-urlencoded` set, space as `+`).
pub(crate) fn encode(text: &str, form: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || if form {
                matches!(byte, b'*' | b'-' | b'.' | b'_')
            } else {
                matches!(byte, b'-' | b'.' | b'_' | b'~')
            };
        if keep {
            out.push(byte as char);
        } else if form && byte == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Refuse a rendered URL that is not HTTPS on the declared host under the literal prefix.
fn confine(rendered: &str, request: &RequestTemplate) -> Result<(), ArgumentError> {
    let parsed = url::Url::parse(rendered).map_err(|_| refused(None))?;
    let prefix = request.path.split('{').next().unwrap_or("/");
    let ok = parsed.scheme() == "https"
        && parsed.host_str() == Some(request.host.as_str())
        && parsed.port().is_none()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.fragment().is_none()
        && parsed.path().starts_with(prefix)
        && parsed.as_str() == rendered;
    if ok {
        Ok(())
    } else {
        Err(refused(None))
    }
}

fn write_template(
    template: &Template,
    args: &Map<String, Value>,
    element: Option<&Value>,
    out: &mut String,
) -> Result<(), ArgumentError> {
    match template {
        Template::Arg(name) => write_json(args.get(name).unwrap_or(&Value::Null), out),
        Template::Const(value) => write_json(value, out),
        Template::Element(_) => write_json(element.ok_or_else(|| refused(None))?, out),
        Template::Rfc822(mail) => {
            let encoded =
                crate::cloud_pack_mail::render(mail, args).ok_or_else(|| refused(None))?;
            write_json(&Value::String(encoded), out)
        }
        Template::Object(fields) => {
            out.push('{');
            let mut first = true;
            for field in fields {
                if let Template::Arg(name) = &field.value {
                    if !args.contains_key(name) {
                        continue;
                    }
                }
                if !first {
                    out.push(',');
                }
                first = false;
                write_json(&Value::String(field.name.clone()), out)?;
                out.push(':');
                write_template(&field.value, args, element, out)?;
            }
            out.push('}');
            Ok(())
        }
        Template::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_template(item, args, element, out)?;
            }
            out.push(']');
            Ok(())
        }
        Template::Keyed { key, value } => {
            let name = args
                .get(key)
                .filter(|name| name.is_string())
                .ok_or_else(|| refused(Some(key)))?;
            out.push('{');
            write_json(name, out)?;
            out.push(':');
            write_template(value, args, element, out)?;
            out.push('}');
            Ok(())
        }
        Template::Each { arg, item } => {
            out.push('[');
            let list = args
                .get(arg)
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice);
            for (index, value) in list.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_template(item, args, Some(value), out)?;
            }
            out.push(']');
            Ok(())
        }
    }
}

/// Longest request body a pack may render. An `each` item can repeat a whole
/// argument once per element, so the body is checked as it grows rather than
/// trusting the argument bounds to keep it small.
pub const MAX_BODY_BYTES: usize = 1 << 20;

/// The JSON body for `template`. The size is checked again once the body is
/// complete, because closing brackets and separators are written after the
/// last value check.
pub(crate) fn render_body(
    template: &Template,
    args: &Map<String, Value>,
) -> Result<String, ArgumentError> {
    let mut out = String::new();
    write_template(template, args, None, &mut out)?;
    if out.len() > MAX_BODY_BYTES {
        return Err(refused(None));
    }
    Ok(out)
}

fn write_json(value: &Value, out: &mut String) -> Result<(), ArgumentError> {
    out.push_str(&serde_json::to_string(value).map_err(|_| refused(None))?);
    if out.len() > MAX_BODY_BYTES {
        return Err(refused(None));
    }
    Ok(())
}
