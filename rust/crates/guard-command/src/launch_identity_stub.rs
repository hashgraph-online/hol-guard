//! Fail-closed launch identity API for non-Unix targets.
//!
//! The full launch identity implementation relies on POSIX filesystem metadata
//! and executable semantics. Keep its API available to cross-platform callers,
//! but do not claim runtime identities can be verified on other targets.

use std::collections::HashSet;
use std::path::Path;

use serde_json::{json, Map, Value};

fn unsupported_identity() -> Value {
    json!({
        "status": "unsupported_platform",
        "reuse_nonce": "unsupported_platform",
    })
}

pub fn build_runtime_executable_identity(
    _command: &Value,
    _search_path: Option<&str>,
    _cwd: Option<&Path>,
    _home_dir: Option<&Path>,
    _require_executable: bool,
) -> Value {
    unsupported_identity()
}

pub fn runtime_launch_identity_is_reusable(_identity: &Value) -> bool {
    false
}

pub fn resolved_runtime_launch_executable(_identity: &Value) -> Option<String> {
    None
}

pub fn resolved_runtime_launch_argv(_identity: &Value, _args: &[String]) -> Option<Vec<String>> {
    None
}

#[allow(clippy::too_many_arguments)]
pub fn runtime_launch_identity_matches(
    _expected_identity: &Value,
    _command: &Value,
    _args: &[Value],
    _structured_command: bool,
    _direct_executable: bool,
    _search_path: Option<&str>,
    _cwd: Option<&Path>,
    _launch_env: Option<&Value>,
) -> bool {
    false
}

#[allow(clippy::too_many_arguments)]
pub fn build_runtime_launch_identity(
    _command: &Value,
    _args: &[Value],
    _structured_command: bool,
    _direct_executable: bool,
    _search_path: Option<&str>,
    _cwd: Option<&Path>,
    _home_dir: Option<&Path>,
    _launch_env: Option<&Value>,
) -> Value {
    unsupported_identity()
}

fn python_str_is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn python_str_strip(value: &str) -> &str {
    value.trim_matches(python_str_is_space)
}

pub fn package_advisory_ids(package: &Map<String, Value>) -> Vec<String> {
    let mut advisory_ids: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut add_id = |value: Option<&Value>| {
        if let Some(text) = value.and_then(Value::as_str) {
            let trimmed = python_str_strip(text);
            if !trimmed.is_empty() && !seen.contains(trimmed) {
                seen.insert(trimmed.to_string());
                advisory_ids.push(trimmed.to_string());
            }
        }
    };
    for key in [
        "advisoryIds",
        "advisory_ids",
        "relatedAdvisoryIds",
        "related_advisory_ids",
    ] {
        if let Some(raw) = package.get(key).and_then(Value::as_array) {
            for entry in raw {
                add_id(Some(entry));
            }
        }
    }
    add_id(package.get("advisoryId"));
    add_id(package.get("advisory_id"));
    if let Some(reasons) = package.get("reasons").and_then(Value::as_array) {
        for reason in reasons {
            let Some(reason) = reason.as_object() else {
                continue;
            };
            add_id(reason.get("advisoryId"));
            add_id(reason.get("advisory_id"));
        }
    }
    advisory_ids
}
