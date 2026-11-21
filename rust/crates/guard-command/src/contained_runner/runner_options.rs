//! Bounded local test-runner options and Bun registry lock entries.
//!
//! Faithful port of `runtime/local_node_runner_options.py`.

use serde_json::{Map, Value};

use super::pkg_json::{object_of, valid_sha512_integrity};

const STDOUT_REPORTERS: [&str; 4] = ["default", "dot", "verbose", "basic"];

/// `vitest_result_arguments`: `run` plus optional `--no-coverage` and one
/// stdout reporter, followed by explicit files. Returns `(files, valid)`.
pub(crate) fn vitest_result_arguments(tail: &[String]) -> (Vec<String>, bool) {
    if tail.first().map(String::as_str) != Some("run") {
        return (Vec::new(), false);
    }
    let mut files: Vec<String> = Vec::new();
    let mut coverage_seen = false;
    let mut reporter_seen = false;
    let mut index = 1;
    while index < tail.len() {
        let token = tail[index].as_str();
        if token == "--no-coverage" {
            if coverage_seen {
                return (Vec::new(), false);
            }
            coverage_seen = true;
        } else if token == "--reporter" || token.starts_with("--reporter=") {
            if reporter_seen {
                return (Vec::new(), false);
            }
            reporter_seen = true;
            let reporter = if token == "--reporter" {
                index += 1;
                match tail.get(index) {
                    Some(value) => value.as_str(),
                    None => return (Vec::new(), false),
                }
            } else {
                token.split_once('=').map_or("", |(_, value)| value)
            };
            if !STDOUT_REPORTERS.contains(&reporter) {
                return (Vec::new(), false);
            }
        } else if token.starts_with('-') {
            return (Vec::new(), false);
        } else {
            files.push(token.to_owned());
        }
        index += 1;
    }
    let valid = !files.is_empty();
    (files, valid)
}

/// `bun_locked_version`: the exact Bun registry entry for `package`.
pub(crate) fn bun_locked_version(
    payload: Option<&Map<String, Value>>,
    package: &str,
) -> (Option<String>, bool) {
    let Some(payload) = payload else {
        return (None, false);
    };
    let lock_version = payload.get("lockfileVersion").and_then(|value| {
        value
            .as_i64()
            .or_else(|| value.as_u64().and_then(|number| i64::try_from(number).ok()))
    });
    if !matches!(lock_version, Some(0 | 1)) {
        return (None, false);
    }
    let Some(Value::Array(item)) =
        object_of(payload.get("packages")).and_then(|map| map.get(package))
    else {
        return (None, false);
    };
    let [name_version, source, metadata, integrity] = item.as_slice() else {
        return (None, false);
    };
    let prefix = format!("{package}@");
    let Some(version) = name_version
        .as_str()
        .and_then(|text| text.strip_prefix(&prefix))
    else {
        return (None, false);
    };
    let parts: Vec<&str> = version.split('.').collect();
    let exact = parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()));
    if !exact {
        return (None, false);
    }
    // An empty registry source is Bun's canonical npm registry entry.
    let ok = source.as_str() == Some("")
        && object_of(Some(metadata)).is_some()
        && valid_sha512_integrity(Some(integrity));
    (Some(version.to_owned()), ok)
}
