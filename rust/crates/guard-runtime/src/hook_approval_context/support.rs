//! Path normalization and Python-shaped JSON helpers for approval contexts.

use std::collections::BTreeMap;
use std::path::Path;

use guard_command::hook_adapter_paths::{expanduser, safe_resolve, PathEnv, PurePath};
use serde_json::{json, Map, Value};

use super::{Effects, LaunchRequest, ERR_INPUT, ERR_PATH, ERR_RANDOM};
use crate::context_digest::python_strip;
use crate::resident_diagnostics::{observe_value, Phase};

/// Python `_normalized_runtime_context_path`:
/// `str(p.expanduser().resolve(strict=False))`, else `.absolute()`.
pub(super) struct Paths {
    env: PathEnv,
}

impl Paths {
    pub(super) fn from_host(host: &Value) -> Result<Self, &'static str> {
        let host = host.as_object().ok_or(ERR_INPUT)?;
        Ok(Self {
            env: PathEnv {
                tilde_home: text(host, "tilde_home")?.map(str::to_owned),
                default_home: None,
                cwd: text(host, "cwd")?.map(str::to_owned),
            },
        })
    }

    pub(super) fn cwd(&self) -> Result<&str, &'static str> {
        self.env.cwd.as_deref().ok_or(ERR_PATH)
    }

    pub(super) fn normalized(&self, text: &str) -> Result<String, &'static str> {
        let expanded = match expanduser(PurePath::host(text), &self.env) {
            Ok(path) => path.text(),
            Err(_) => named_user_home(text).ok_or(ERR_PATH)?,
        };
        #[cfg(windows)]
        if let Some(resolved) = windows_resolve(&expanded, self.env.cwd.as_deref()) {
            return Ok(PurePath::host(&resolved).text());
        }
        let resolved = safe_resolve(&expanded, &self.env).map_err(|_| ERR_PATH)?;
        if PurePath::host(&resolved).is_absolute() {
            return Ok(PurePath::host(&resolved).text());
        }
        Ok(PurePath::host(&format!("{}/{resolved}", self.cwd()?)).text())
    }
}

/// `~user` expansion through the password database; unknown users fail as
/// Python's `RuntimeError("Could not determine home directory.")` did.
#[cfg(unix)]
pub(super) fn named_user_home(text: &str) -> Option<String> {
    let normalized = PurePath::host(text).text();
    let rest = normalized.strip_prefix('~')?;
    let (name, tail) = rest.split_once('/').unwrap_or((rest, ""));
    if name.is_empty() {
        return None;
    }
    let user = nix::unistd::User::from_name(name).ok()??;
    let home = user.dir.to_str()?.trim_end_matches('/');
    Some(PurePath::host(&format!("{home}/{tail}")).text())
}

/// Windows `Path.resolve(strict=False)`: the deepest existing ancestor's
/// final path (symlinks and `..` resolved) plus the missing tail. `None`
/// leaves the lexical fallback.
#[cfg(windows)]
fn windows_resolve(text: &str, cwd: Option<&str>) -> Option<String> {
    let mut path = std::path::PathBuf::from(text);
    if !path.is_absolute() {
        path = Path::new(cwd?).join(path);
    }
    let mut tail = Vec::new();
    let mut base = path.as_path();
    loop {
        if let Ok(mut resolved) = std::fs::canonicalize(base) {
            for part in tail.iter().rev() {
                resolved.push(part);
            }
            let text = resolved.to_str()?;
            return Some(match text.strip_prefix(r"\\?\UNC\") {
                Some(rest) => format!(r"\\{rest}"),
                None => text.strip_prefix(r"\\?\").unwrap_or(text).to_owned(),
            });
        }
        tail.push(base.file_name()?.to_owned());
        base = base.parent()?;
    }
}

#[cfg(not(unix))]
pub(super) fn named_user_home(_text: &str) -> Option<String> {
    None
}

pub(super) fn optional_normalized(
    paths: &Paths,
    text: Option<&str>,
) -> Result<Option<String>, &'static str> {
    text.map(|text| paths.normalized(text)).transpose()
}

pub(super) fn string_map(value: &Value) -> Result<BTreeMap<String, String>, &'static str> {
    value
        .as_object()
        .ok_or(ERR_INPUT)?
        .iter()
        .map(|(key, value)| Ok((key.clone(), value.as_str().ok_or(ERR_INPUT)?.to_owned())))
        .collect()
}

pub(super) fn field<'a>(object: &'a Map<String, Value>, key: &str) -> &'a Value {
    object.get(key).unwrap_or(&Value::Null)
}

pub(super) fn field_of<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

pub(super) fn text<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match field(object, key) {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text)),
        _ => Err(ERR_INPUT),
    }
}

/// Python truthiness of a JSON value.
pub(super) fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64() != Some(0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(entries)) => !entries.is_empty(),
    }
}

/// Python `a or b`.
pub(super) fn py_or(first: Option<&Value>, second: Option<&Value>) -> Value {
    if truthy(first) {
        first.cloned().unwrap_or(Value::Null)
    } else {
        second.cloned().unwrap_or(Value::Null)
    }
}

/// `_optional_string`: a non-blank string, stripped.
pub(super) fn optional_string(value: &Value) -> Option<String> {
    let text = python_strip(value.as_str()?);
    (!text.is_empty()).then(|| text.to_owned())
}

pub(super) fn envelope(
    input: &Map<String, Value>,
) -> Result<Option<&Map<String, Value>>, &'static str> {
    match field(input, "envelope") {
        Value::Null => Ok(None),
        Value::Object(envelope) => Ok(Some(envelope)),
        _ => Err(ERR_INPUT),
    }
}

pub(super) fn capabilities(envelope: &Map<String, Value>, keys: &[&str]) -> Value {
    Value::Object(
        keys.iter()
            .map(|key| ((*key).to_owned(), field(envelope, key).clone()))
            .collect(),
    )
}

pub(super) fn policy(input: &Map<String, Value>) -> Value {
    json!({
        "config": field(input, "policy_config"),
        "evaluator_policy_version": field(input, "evaluator_policy_version"),
        "composition": field(input, "composition"),
    })
}

pub(super) fn sandbox_required(input: &Map<String, Value>) -> bool {
    field(input, "current_action").as_str() == Some("sandbox-required")
}

pub(super) fn extension_control_digest(input: &Map<String, Value>) -> Result<String, &'static str> {
    text(input, "extension_control_digest")?
        .map(str::to_owned)
        .ok_or(ERR_INPUT)
}

pub(super) fn with_native_effects<T>(run: impl FnOnce(&mut Effects<'_>) -> T) -> T {
    let mut nonce = || {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| ERR_RANDOM)?;
        Ok(hex::encode(bytes))
    };
    run(&mut Effects {
        launch: &native_launch,
        nonce: &mut nonce,
    })
}

fn native_launch(request: &LaunchRequest<'_>) -> Value {
    observe_value(Phase::ContextRuntimeLaunchIdentity, || {
        guard_command::launch_identity::build_runtime_launch_identity(
            request.command,
            request.args,
            request.structured_command,
            false,
            request.search_path,
            Some(Path::new(request.cwd)),
            request.home_dir.map(Path::new),
            Some(request.launch_env),
        )
    })
}
