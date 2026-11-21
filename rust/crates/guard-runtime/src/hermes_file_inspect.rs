//! `hermes-file-inspect --stdin`: race-checked reads of one Hermes file for
//! the install, uninstall and runtime-hook paths
//! (`guard/adapters/hermes_file_inspection.py` frames the request).
//!
//! - `text` streams one regular file, hashing every byte and keeping a
//!   bounded preview plus, under `content_limit_bytes`, the complete text.
//! - `config` parses a complete, bounded JSON or YAML mapping with the
//!   PyYAML `SafeLoader` value rules. The payload keeps the file's key order,
//!   because Guard writes the mapping back without sorting it, and carries
//!   integers as exact digits.
//!
//! Every failure is a static reason; input the original loader raised an
//! unrelated exception on reads as `config_parse_error`, never as a mapping.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::hermes_inspect::{
    inspect_config_keeping_file, inspect_text_file, FileInspection, Syntax, CONFIG_MAX_BYTES,
};
use crate::pyjson::{float_repr, PyVal};

const SCHEMA: &str = "hermes-file-inspect.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const PARSE_ERROR: &str = "config_parse_error";
const VALUE_INVALID: &str = "config_value_invalid";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    path: String,
    #[serde(default)]
    scope_root: Option<String>,
    #[serde(default)]
    content_limit_bytes: Option<u64>,
    #[serde(default)]
    syntax: Option<String>,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "hermes-file-inspect"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "hermes_file_inspect_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("hermes_file_inspect_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    answer(&request).map(String::into_bytes)
}

fn invalid() -> String {
    "hermes_file_inspect_request_invalid".to_owned()
}

fn absolute(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(invalid())
    }
}

fn answer(request: &Request) -> Result<String, String> {
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    let path = absolute(&request.path)?;
    match request.op.as_str() {
        "text" if request.syntax.is_none() => {
            let scope_root = request.scope_root.as_deref().map(absolute).transpose()?;
            let limit = match request.content_limit_bytes {
                Some(limit) if limit > CONFIG_MAX_BYTES as u64 => return Err(invalid()),
                limit => limit.map(|limit| limit as usize),
            };
            let file = inspect_text_file(&path, scope_root.as_deref(), limit);
            Ok(json!({ "file": file_json(&file) }).to_string())
        }
        "config" if request.scope_root.is_none() && request.content_limit_bytes.is_none() => {
            let syntax = match request.syntax.as_deref() {
                Some("json") => Syntax::Json,
                Some("yaml") => Syntax::Yaml,
                _ => return Err(invalid()),
            };
            Ok(config_answer(&path, syntax))
        }
        _ => Err(invalid()),
    }
}

fn file_json(file: &FileInspection) -> Value {
    json!({
        "preview": file.preview,
        "content": file.content,
        "content_hash": file.content_hash,
        "size_bytes": file.size_bytes,
        "readable": file.readable,
        "complete": file.complete,
        "analysis_truncated": file.analysis_truncated,
        "reason": file.reason,
    })
}

fn config_answer(path: &Path, syntax: Syntax) -> String {
    let (file, payload, reason) = match inspect_config_keeping_file(path, syntax) {
        Ok(inspection) => (inspection.file, inspection.payload, inspection.reason),
        // A refusal still read the file; only the parse is withheld.
        Err((file, _)) => (file, None, Some(PARSE_ERROR)),
    };
    let mut file = file_json(&file);
    file["content"] = Value::Null;
    let (payload, reason) = match payload.map(|entries| ordered_json(&PyVal::Dict(entries))) {
        Some(Some(payload)) => (payload, None),
        Some(None) => ("null".to_owned(), Some(VALUE_INVALID)),
        None => ("null".to_owned(), reason),
    };
    format!(
        "{{\"file\":{file},\"payload\":{payload},\"complete\":{},\"reason\":{}}}",
        reason.is_none(),
        json!(reason),
    )
}

/// JSON text for a parsed value in its original key order, with integers as
/// exact digits and floats as CPython `repr` renders them. `None` for a
/// non-finite float, which has no JSON form.
fn ordered_json(value: &PyVal) -> Option<String> {
    let mut out = String::new();
    write_ordered(value, &mut out)?;
    Some(out)
}

fn write_ordered(value: &PyVal, out: &mut String) -> Option<()> {
    match value {
        PyVal::Null => out.push_str("null"),
        PyVal::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        PyVal::Int(digits) => out.push_str(digits),
        PyVal::Float(number) if number.is_finite() => out.push_str(&float_repr(*number)),
        PyVal::Float(_) => return None,
        PyVal::Str(text) => out.push_str(&Value::String(text.clone()).to_string()),
        PyVal::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_ordered(item, out)?;
            }
            out.push(']');
        }
        PyVal::Dict(entries) => {
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_ordered(item, out)?;
            }
            out.push('}');
        }
    }
    Some(())
}

#[cfg(test)]
#[path = "hermes_file_inspect_tests.rs"]
mod tests;
