//! Form-encoded request bodies.
//!
//! Some providers (Stripe's v1 API among them) accept only
//! `application/x-www-form-urlencoded` bodies. A form body is a flat list of
//! fields at the top of the request; each value is a scalar argument or a
//! scalar constant. A field whose argument is absent is left out. Names may
//! use the bracket notation such providers read as nesting (`metadata[order]`),
//! and both names and values are percent-encoded.

use crate::cloud_pack::{ArgumentSpec, Template, TemplateField};
use crate::cloud_pack_request::encode;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_FORM_FIELDS: usize = 64;

pub(crate) fn validate(
    fields: &[TemplateField],
    args: &BTreeMap<String, ArgumentSpec>,
) -> Result<(), &'static str> {
    const INVALID: &str = "cloud_pack_template_form_invalid";
    if fields.is_empty() || fields.len() > MAX_FORM_FIELDS {
        return Err(INVALID);
    }
    let mut names = BTreeSet::new();
    for field in fields {
        let name_ok = !field.name.is_empty()
            && field.name.len() <= 64
            && field.name.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'[' | b']')
            });
        if !name_ok || !names.insert(field.name.as_str()) {
            return Err(INVALID);
        }
        let value_ok = match &field.value {
            Template::Arg(name) => matches!(
                args.get(name),
                Some(
                    ArgumentSpec::String { .. }
                        | ArgumentSpec::Integer { .. }
                        | ArgumentSpec::Boolean { .. }
                )
            ),
            Template::Const(value) => scalar(value).is_some_and(|text| text.len() <= 256),
            _ => false,
        };
        if !value_ok {
            return Err(INVALID);
        }
    }
    Ok(())
}

/// The encoded body, or `None` when an argument is not a scalar.
pub(crate) fn render(fields: &[TemplateField], args: &Map<String, Value>) -> Option<String> {
    let mut pairs = Vec::with_capacity(fields.len());
    for field in fields {
        let value = match &field.value {
            Template::Arg(name) => match args.get(name) {
                None => continue,
                Some(value) => value,
            },
            Template::Const(value) => value,
            _ => return None,
        };
        let text = scalar(value)?;
        pairs.push(format!(
            "{}={}",
            encode(&field.name, true),
            encode(&text, true)
        ));
    }
    Some(pairs.join("&"))
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(text) if !text.chars().any(char::is_control) => Some(text.clone()),
        Value::Number(number) => number.as_i64().map(|n| n.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}
