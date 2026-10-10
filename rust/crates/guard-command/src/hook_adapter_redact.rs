//! Path-mention and raw-payload redaction for the hook action envelope.

use std::sync::LazyLock;

use fancy_regex::Regex as FancyRegex;

use crate::hook_adapter_envelope_text::{normalized_secret_key, PATH_KEYS, PROMPT_PATH};
use crate::hook_adapter_paths::{redacted_target_path, PathEnv};
use crate::hook_adapter_prepare::AdapterError;
use crate::hook_adapter_pytext::{compile_fancy, fancy_replace_all, py_prefix_chars};
use crate::hook_adapter_value::{OMap, OValue};
use crate::redacted_command_tokens::redact_text;

const EXCERPT_LIMIT: usize = 240;
const SENSITIVE_RAW_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "access_token",
    "auth",
    "authorization",
    "client_secret",
    "content",
    "cookie",
    "credential",
    "credentials",
    "id_token",
    "output",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session_token",
    "set_cookie",
    "stderr",
    "stdout",
    "token",
    "tool_response",
];

static POSIX_ABSOLUTE: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(
        r"(?<![:A-Za-z0-9_./-])(?P<path>/(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+)(?![A-Za-z0-9_.-])",
    )
});
static WINDOWS_ABSOLUTE: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(
        r#"(?<![A-Za-z0-9_./\\:-])(?P<path>[A-Za-z]:\\(?:[^\\\s\x1c-\x1f'"<>|]+\\)+[^\\\s\x1c-\x1f'"<>|]+)"#,
    )
});
static WINDOWS_UNC: LazyLock<FancyRegex> = LazyLock::new(|| {
    compile_fancy(
        r#"(?<![A-Za-z0-9_./\\:-])(?P<path>\\\\[^\\\s\x1c-\x1f'"<>|]+\\[^\\\s\x1c-\x1f'"<>|]+(?:\\[^\\\s\x1c-\x1f'"<>|]+)+)"#,
    )
});

fn substitute(
    pattern: &FancyRegex,
    text: &str,
    home_dir: Option<&str>,
    env: &PathEnv,
) -> Result<String, AdapterError> {
    let mut failure: Option<AdapterError> = None;
    let replaced = fancy_replace_all(pattern, text, |captures| {
        let path = captures.name("path").map_or("", |found| found.as_str());
        if failure.is_some() {
            return path.to_owned();
        }
        match redacted_target_path(path, home_dir, env) {
            Ok(Some(redacted)) if !redacted.is_empty() => redacted,
            Ok(_) => path.to_owned(),
            Err(error) => {
                failure = Some(error);
                path.to_owned()
            }
        }
    });
    failure.map_or(Ok(replaced), Err)
}

/// `_redact_path_mentions`.
pub fn redact_path_mentions(
    text: &str,
    home_dir: Option<&str>,
    env: &PathEnv,
) -> Result<String, AdapterError> {
    let redacted = substitute(&WINDOWS_UNC, text, home_dir, env)?;
    let redacted = substitute(&WINDOWS_ABSOLUTE, &redacted, home_dir, env)?;
    let redacted = substitute(&POSIX_ABSOLUTE, &redacted, home_dir, env)?;
    substitute(&PROMPT_PATH, &redacted, home_dir, env)
}

/// `_command_detail`.
pub fn command_detail(
    command: &str,
    home_dir: Option<&str>,
    env: &PathEnv,
) -> Result<String, AdapterError> {
    redact_path_mentions(&redact_text(command).text, home_dir, env)
}

fn is_sensitive_key(normalized: &str) -> bool {
    let squeezed = normalized.replace('_', "");
    SENSITIVE_RAW_KEYS.contains(&normalized)
        || SENSITIVE_RAW_KEYS
            .iter()
            .any(|key| key.replace('_', "") == squeezed)
}

fn is_path_like_key(key: &str) -> bool {
    let normalized = normalized_secret_key(key);
    let squeezed = normalized.replace('_', "");
    PATH_KEYS.iter().any(|path_key| {
        let candidate = normalized_secret_key(path_key);
        candidate == normalized || candidate.replace('_', "") == squeezed
    })
}

fn redacted_string_value(
    key: &str,
    value: &str,
    home_dir: Option<&str>,
    env: &PathEnv,
) -> Result<String, AdapterError> {
    if is_path_like_key(key) {
        if let Some(redacted) = redacted_target_path(value, home_dir, env)? {
            return Ok(redacted);
        }
    }
    redact_path_mentions(&redact_text(value).text, home_dir, env)
}

fn redacted_value(
    key: &str,
    value: &OValue,
    home_dir: Option<&str>,
    env: &PathEnv,
) -> Result<OValue, AdapterError> {
    if is_sensitive_key(&normalized_secret_key(key)) {
        return Ok(OValue::str("[redacted]"));
    }
    Ok(match value {
        OValue::Map(map) => {
            let mut out = OMap::new();
            for (child_key, child) in map.iter() {
                out.insert(child_key, redacted_value(child_key, child, home_dir, env)?);
            }
            OValue::Map(out)
        }
        OValue::List(items) => OValue::List(
            items
                .iter()
                .map(|item| redacted_value(key, item, home_dir, env))
                .collect::<Result<_, _>>()?,
        ),
        OValue::Str(text) => {
            let redacted = redacted_string_value(key, text, home_dir, env)?;
            OValue::str(py_prefix_chars(&redacted, EXCERPT_LIMIT))
        }
        other => other.clone(),
    })
}

/// `_redacted_payload`.
pub fn redacted_payload(
    payload: &OMap,
    home_dir: Option<&str>,
    env: &PathEnv,
) -> Result<OMap, AdapterError> {
    let mut out = OMap::new();
    for (key, value) in payload.iter() {
        out.insert(key, redacted_value(key, value, home_dir, env)?);
    }
    Ok(out)
}
