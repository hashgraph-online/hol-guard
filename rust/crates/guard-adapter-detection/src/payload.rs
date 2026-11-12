//! The payload helpers the detection leaves share: the `_json_payload` reader
//! over CPython-compatible [`PyVal`] input and the `serde_json` projection that
//! keeps Python scalar semantics.

use std::fs;
use std::path::Path;

use serde_json::{json, Number, Value};

use crate::artifacts::Fields;
use guard_runtime_pyjson::{parse_marking_lone_surrogates, JsonFailure, PyVal};

pub const ERR_TEXT: &str = "native_runner_authority_adapter_text_undecodable";
pub const ERR_NAME: &str = "native_runner_authority_adapter_name_undecodable";
pub const ERR_VALUE: &str = "native_runner_authority_adapter_value_unrepresentable";

/// A parsed value as the wire carries it to Python: an integer that would not
/// keep its digits or a non-finite float is refused.
pub fn carried(value: &PyVal) -> Result<Value, &'static str> {
    Ok(match value {
        PyVal::Null => Value::Null,
        PyVal::Bool(flag) => Value::Bool(*flag),
        PyVal::Int(digits) => match (digits.parse::<i64>(), digits.parse::<u64>()) {
            (Ok(number), _) => json!(number),
            (_, Ok(number)) => json!(number),
            _ => return Err(ERR_VALUE),
        },
        PyVal::Float(number) => Value::Number(Number::from_f64(*number).ok_or(ERR_VALUE)?),
        PyVal::Str(text) => Value::String(text.clone()),
        PyVal::List(items) => Value::Array(items.iter().map(carried).collect::<Result<_, _>>()?),
        PyVal::Dict(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, item)| Ok((key.clone(), carried(item)?)))
                .collect::<Result<_, &'static str>>()?,
        ),
    })
}

/// `json.loads(path.read_text(encoding="utf-8"))`: `None` when the file
/// cannot be read or is not JSON. Bytes that are not UTF-8 and input
/// `json.loads` raises a non-`JSONDecodeError` on are refused.
pub fn json_document(path: &Path) -> Result<Option<PyVal>, &'static str> {
    let Ok(bytes) = fs::read(path) else {
        return Ok(None);
    };
    let text = String::from_utf8(bytes).map_err(|_| ERR_TEXT)?;
    match parse_marking_lone_surrogates(&text) {
        Ok(value) => Ok(Some(value)),
        Err(JsonFailure::Syntax) => Ok(None),
        Err(_) => Err(ERR_VALUE),
    }
}

/// `_json_payload`: the object a file holds, or an empty one.
pub fn json_payload(path: &Path) -> Result<PyVal, &'static str> {
    Ok(match json_document(path)? {
        Some(value @ PyVal::Dict(_)) => value,
        _ => PyVal::Dict(Vec::new()),
    })
}

/// `_string_args`: the strings of a list `args`, else nothing.
pub fn string_args(config: &PyVal) -> Vec<String> {
    config
        .get("args")
        .and_then(PyVal::as_list)
        .unwrap_or_default()
        .iter()
        .filter_map(PyVal::as_str)
        .map(str::to_owned)
        .collect()
}

/// One MCP server entry: `command` and `url` when they are strings.
/// Gemini names a streamable remote server `httpUrl`; Antigravity uses
/// `serverUrl`. Each is the same remote endpoint as `url`; a blank one is
/// skipped so a later alias still counts.
pub fn mcp_fields<'a>(config: &'a PyVal) -> Fields<'a> {
    let url = ["url", "httpUrl", "serverUrl"]
        .into_iter()
        .filter_map(|key| config.get(key).and_then(PyVal::as_str))
        .find(|url| !url.trim().is_empty());
    Fields {
        command: config.get("command").and_then(PyVal::as_str),
        args: string_args(config),
        url,
        transport: Some(if url.is_some() { "http" } else { "stdio" }),
        publisher: None,
    }
}
