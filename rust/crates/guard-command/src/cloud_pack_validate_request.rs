//! Validation of a `declarative-http` request template.

use crate::cloud_pack::*;
use crate::cloud_pack_validate::header_allowed;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_PATH_CHARS: usize = 512;
const MAX_QUERY: usize = 32;
const MAX_HEADERS: usize = 16;
const MAX_CONST_BYTES: usize = 4_096;
/// Longest argument a `keyed` template may use as a field name.
const MAX_KEY_LENGTH: u32 = 256;

type Fail = (&'static str, String);

fn fail(code: &'static str, rest: &str) -> Result<(), Fail> {
    Err((code, rest.to_owned()))
}

pub(crate) fn validate_request(
    action: &PackAction,
    request: &RequestTemplate,
    hosts: &BTreeSet<&str>,
) -> Result<(), Fail> {
    let args = &action.arguments;
    if !hosts.contains(request.host.as_str()) {
        return fail("cloud_pack_request_host_undeclared", "/host");
    }
    if request.max_pages == 0 || request.max_pages > MAX_PAGES {
        return fail("cloud_pack_request_invalid", "/maxPages");
    }
    if path_placeholders(&request.path)
        .ok_or(("cloud_pack_request_path_invalid", "/path".to_owned()))?
        .iter()
        .any(|(name, spans)| !path_argument(args.get(name), *spans))
    {
        return fail("cloud_pack_request_path_invalid", "/path");
    }
    if request.query.len() > MAX_QUERY {
        return fail("cloud_pack_request_query_invalid", "/query");
    }
    let mut names = BTreeSet::new();
    for (index, param) in request.query.iter().enumerate() {
        let ok = query_name(&param.name)
            && names.insert(param.name.as_str())
            && match &param.value {
                ValueSource::Const(value) => scalar(value),
                ValueSource::Arg { name, default } => {
                    scalar_argument(args.get(name))
                        && default
                            .as_ref()
                            .is_none_or(|value| default_fits(args.get(name), value))
                }
            };
        if !ok {
            return fail(
                "cloud_pack_request_query_invalid",
                &format!("/query/{index}"),
            );
        }
    }
    if request.headers.len() > MAX_HEADERS {
        return fail("cloud_pack_request_header_invalid", "/headers");
    }
    let mut headers = BTreeSet::new();
    for (index, header) in request.headers.iter().enumerate() {
        if !header_allowed(&header.name)
            || !headers.insert(header.name.to_ascii_lowercase())
            || header.value.is_empty()
            || header.value.len() > 256
            || !header.value.bytes().all(|b| (0x20..0x7f).contains(&b))
        {
            return fail(
                "cloud_pack_request_header_invalid",
                &format!("/headers/{index}"),
            );
        }
    }
    match (&request.body, request.method) {
        (Some(_), HttpMethod::Get | HttpMethod::Delete) => {
            fail("cloud_pack_request_body_invalid", "/body")
        }
        (Some(template), _) if !matches!(template, Template::Object(_)) => {
            fail("cloud_pack_request_body_invalid", "/body")
        }
        (Some(template), _) => {
            validate_template(template, args, 0, false).map_err(|code| (code, "/body".to_owned()))
        }
        (None, _) => Ok(()),
    }
}

/// Placeholders of a path template with whether each spans segments, or `None` when malformed.
pub(crate) fn path_placeholders(path: &str) -> Option<BTreeMap<String, bool>> {
    if !path.starts_with('/') || path.len() > MAX_PATH_CHARS || path.contains("//") {
        return None;
    }
    let mut found = BTreeMap::new();
    for segment in path[1..].split('/') {
        if let Some(inner) = segment
            .strip_prefix('{')
            .and_then(|rest| rest.strip_suffix('}'))
        {
            let (name, spans) = match inner.strip_suffix('*') {
                Some(name) => (name, true),
                None => (inner, false),
            };
            if !crate::cloud_pack_validate::snake_name(name)
                || found.insert(name.to_owned(), spans).is_some()
            {
                return None;
            }
        } else if segment.is_empty()
            || segment == "."
            || segment == ".."
            || !segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        {
            // A trailing slash leaves one empty final segment, which is refused too.
            return None;
        }
    }
    Some(found)
}

fn path_argument(spec: Option<&ArgumentSpec>, spans: bool) -> bool {
    match spec {
        Some(ArgumentSpec::String { required: true, .. }) => true,
        Some(ArgumentSpec::Integer { required: true, .. }) => !spans,
        _ => false,
    }
}

fn scalar_argument(spec: Option<&ArgumentSpec>) -> bool {
    matches!(
        spec,
        Some(
            ArgumentSpec::String { .. }
                | ArgumentSpec::Integer { .. }
                | ArgumentSpec::Boolean { .. }
        )
    )
}

fn default_fits(spec: Option<&ArgumentSpec>, value: &Value) -> bool {
    match (spec, value) {
        (
            Some(ArgumentSpec::Integer {
                minimum, maximum, ..
            }),
            Value::Number(number),
        ) => number
            .as_i64()
            .is_some_and(|n| (*minimum..=*maximum).contains(&n)),
        (Some(ArgumentSpec::Boolean { .. }), Value::Bool(_)) => true,
        (Some(spec @ ArgumentSpec::String { .. }), Value::String(text)) => {
            clean_text(text)
                && crate::cloud_pack_request::check_text(spec.text_rule().as_ref(), value).is_ok()
        }
        _ => false,
    }
}

fn query_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'[' | b']'))
}

fn scalar(value: &Value) -> bool {
    match value {
        Value::Bool(_) => true,
        Value::Number(number) => number.as_i64().is_some(),
        Value::String(text) => clean_text(text) && text.len() <= 256,
        _ => false,
    }
}

fn clean_text(text: &str) -> bool {
    !text.chars().any(char::is_control)
}

fn validate_template(
    template: &Template,
    args: &BTreeMap<String, ArgumentSpec>,
    depth: usize,
    in_each: bool,
) -> Result<(), &'static str> {
    if depth > MAX_TEMPLATE_DEPTH {
        return Err("cloud_pack_template_too_deep");
    }
    match template {
        Template::Arg(name) => args
            .get(name)
            .map(|_| ())
            .ok_or("cloud_pack_template_argument_unknown"),
        Template::Const(value) => {
            let bytes = serde_json::to_vec(value).map_err(|_| "cloud_pack_template_invalid")?;
            if bytes.len() > MAX_CONST_BYTES {
                return Err("cloud_pack_template_invalid");
            }
            Ok(())
        }
        Template::Object(fields) => {
            let mut names = BTreeSet::new();
            for field in fields {
                if field.name.is_empty()
                    || field.name.len() > 64
                    || !names.insert(field.name.as_str())
                {
                    return Err("cloud_pack_template_invalid");
                }
                validate_template(&field.value, args, depth + 1, in_each)?;
            }
            Ok(())
        }
        Template::Array(items) => items
            .iter()
            .try_for_each(|item| validate_template(item, args, depth + 1, in_each)),
        Template::Each { arg, item } => {
            if in_each || !matches!(args.get(arg), Some(ArgumentSpec::Array { .. })) {
                return Err("cloud_pack_template_each_invalid");
            }
            validate_template(item, args, depth + 1, true)
        }
        Template::Keyed { key, value } => {
            let bound = matches!(
                args.get(key),
                Some(ArgumentSpec::String { required: true, pattern: Some(_), max_length, .. })
                    if *max_length <= MAX_KEY_LENGTH
            );
            if !bound {
                return Err("cloud_pack_template_key_invalid");
            }
            validate_template(value, args, depth + 1, in_each)
        }
        Template::Rfc822(mail) if !in_each => crate::cloud_pack_mail::validate(mail, args),
        Template::Rfc822(_) => Err("cloud_pack_template_mail_invalid"),
        Template::Element(true) if in_each => Ok(()),
        Template::Element(_) => Err("cloud_pack_template_each_invalid"),
    }
}
