//! `runner_authority` kind `harness_adapter`: the Gemini, Antigravity, Kimi,
//! Devin, Muse, OpenClaw, Paseo, Grok and ZCode harness adapters.
//!
//! Python keeps one generic adapter class that holds the ownership locks,
//! prepares and removes the launcher shim, builds the bounded hook argv and
//! publishes the file plans this kind returns through the runtime transition
//! journal. Everything else is answered here: the adapter descriptions, policy
//! and config paths, detection and command lookup, the install and uninstall
//! plans with their manifests, the launch environment, the runtime probe
//! fields, the approval flow and Paseo's delegated native installs.
//!
//! Every request carries `harness`, `op` and a `context` object:
//! `{home, workspace, guard_home, home_override_explicit, cwd, user_home,
//! env}`, where `env` holds only the variables `describe` names and the ones
//! starting with its prefixes. A failure Python raises answers one key:
//! `{"refusal": message}` is a `ValueError`, `{"os_error": message}` an
//! `OSError`, `{"not_found": message}` a `FileNotFoundError` and
//! `{"integrity": reason}` the snapshot's integrity error.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::harness_coverage::artifacts::resolve_lenient;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

mod cloud_identity;
mod describe;
mod files;
mod grok;
mod grok_install;
mod kimi;
mod openclaw;
mod paseo;
mod paseo_install;
mod paseo_paths;
mod proof;
mod settings_hooks;
mod simple;
mod which;
mod zcode;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

pub(crate) use describe::Spec;

/// The paths a harness adapter works from, as Python's `HarnessContext` and
/// process hold them.
pub(crate) struct Ctx {
    pub(crate) home: PathBuf,
    pub(crate) workspace: Option<PathBuf>,
    pub(crate) guard_home: PathBuf,
    pub(crate) home_explicit: bool,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) user_home: PathBuf,
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) executable_overrides: BTreeMap<String, String>,
    pub(crate) windows: bool,
}

impl Ctx {
    fn parse(value: Option<&Value>) -> Result<Self, &'static str> {
        let map = value.and_then(Value::as_object).ok_or(ERR_INVALID)?;
        let text = |key: &str| map.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
        let optional = |key: &str| match map.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => Ok(Some(PathBuf::from(text))),
            Some(_) => Err(ERR_INVALID),
        };
        let flag = |key: &str| match map.get(key) {
            None => Ok(false),
            Some(value) => value.as_bool().ok_or(ERR_INVALID),
        };
        let strings = |key: &str| match map.get(key) {
            None | Some(Value::Null) => Ok(BTreeMap::new()),
            Some(Value::Object(entries)) => entries
                .iter()
                .map(|(key, value)| {
                    value
                        .as_str()
                        .map(|text| (key.clone(), text.to_owned()))
                        .ok_or(ERR_INVALID)
                })
                .collect::<Result<_, _>>(),
            Some(_) => Err(ERR_INVALID),
        };
        Ok(Self {
            home: PathBuf::from(text("home")?),
            workspace: optional("workspace")?,
            guard_home: PathBuf::from(text("guard_home")?),
            home_explicit: flag("home_override_explicit")?,
            cwd: optional("cwd")?,
            user_home: PathBuf::from(text("user_home")?),
            env: strings("env")?,
            executable_overrides: strings("executable_overrides")?,
            windows: cfg!(windows),
        })
    }

    /// `os.path.abspath`-style anchoring against the caller's directory.
    pub(crate) fn absolute(&self, path: &Path) -> PathBuf {
        match &self.cwd {
            Some(cwd) if !path.is_absolute() => cwd.join(path),
            _ => path.to_path_buf(),
        }
    }

    /// `path.resolve()` as the caller's process would answer it.
    pub(crate) fn resolved(&self, path: &Path) -> PathBuf {
        resolve_lenient(&self.absolute(path))
    }

    /// `context.home_dir.resolve() == Path.home().resolve()`.
    pub(crate) fn default_home(&self) -> bool {
        self.resolved(&self.home) == self.resolved(&self.user_home)
    }

    pub(crate) fn env(&self, name: &str) -> Option<&str> {
        self.env.get(name).map(String::as_str)
    }

    /// The request a native detection kind reads for this harness.
    pub(crate) fn detection_request(&self, harness: &str) -> Map<String, Value> {
        let mut request = Map::new();
        request.insert("harness".into(), json!(harness));
        request.insert("home".into(), json!(path_text(&self.home)));
        request.insert(
            "workspace".into(),
            self.workspace
                .as_deref()
                .map_or(Value::Null, |path| json!(path_text(path))),
        );
        if let Some(cwd) = &self.cwd {
            request.insert("cwd".into(), json!(path_text(cwd)));
        }
        request
    }
}

pub(crate) fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Why an op stopped, as the Python adapter raised it.
pub(crate) enum Failure {
    Refusal(String),
    Os(String),
    NotFound(String),
    Integrity(&'static str),
    Invalid,
}

pub(crate) type Step<T> = Result<T, Failure>;

impl From<&'static str> for Failure {
    fn from(_: &'static str) -> Self {
        Self::Invalid
    }
}

fn answer(step: Step<Value>) -> KindResult {
    match step {
        Ok(value) => Ok(value),
        Err(Failure::Refusal(message)) => Ok(json!({ "refusal": message })),
        Err(Failure::Os(message)) => Ok(json!({ "os_error": message })),
        Err(Failure::NotFound(message)) => Ok(json!({ "not_found": message })),
        Err(Failure::Integrity(reason)) => Ok(json!({ "integrity": reason })),
        Err(Failure::Invalid) => Err(ERR_INVALID),
    }
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let fields = args_object(args)?;
    let op = fields
        .get("op")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    if op == "describe" {
        return Ok(describe::describe());
    }
    let ctx = Ctx::parse(fields.get("context"))?;
    if op == "proof_verify" || op == "proof_bind" {
        return answer(proof::dispatch(op, &ctx, fields));
    }
    let harness = fields
        .get("harness")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let spec = describe::spec(harness).ok_or(ERR_INVALID)?;
    answer(match spec.harness {
        "gemini" | "antigravity" => simple::dispatch(spec, op, &ctx, fields),
        "kimi" => kimi::dispatch(spec, op, &ctx, fields),
        "devin" | "muse" => settings_hooks::dispatch(spec, op, &ctx, fields),
        "openclaw" => openclaw::dispatch(spec, op, &ctx, fields),
        "paseo" => paseo::dispatch(spec, op, &ctx, fields),
        "grok" => grok::dispatch(spec, op, &ctx, fields),
        "zcode" => zcode::dispatch(spec, op, &ctx, fields),
        _ => Err(Failure::Invalid),
    })
}

/// `{"path": ...}` for `resolved_executable`, shared by every harness.
pub(crate) fn resolved_executable(spec: &Spec, ctx: &Ctx, candidates: &[PathBuf]) -> Step<Value> {
    Ok(json!({ "path": which::resolve_command(ctx, spec.executable, candidates) }))
}

/// A native detection kind's `{artifacts, found_paths, warnings?}` answer,
/// with this adapter's command lookup, as Python builds `HarnessDetection`.
pub(crate) fn detection(
    spec: &Spec,
    kind_answer: KindResult,
    command_available: bool,
) -> Step<Value> {
    let mut found = kind_answer.map_err(|_| Failure::Invalid)?;
    let found = found.as_object_mut().ok_or(Failure::Invalid)?;
    let artifacts = found.remove("artifacts").ok_or(Failure::Invalid)?;
    let paths = found.remove("found_paths").ok_or(Failure::Invalid)?;
    let installed = paths.as_array().is_some_and(|paths| !paths.is_empty()) || command_available;
    Ok(json!({
        "artifacts": artifacts,
        "config_paths": paths,
        "warnings": found.remove("warnings").unwrap_or_else(|| json!([])),
        "installed": installed,
        "command_available": command_available,
        "workspace_aibom": spec.workspace_aibom,
    }))
}

/// A path answer, as `policy_path` returns it.
pub(crate) fn path_answer(path: &Path) -> Step<Value> {
    Ok(json!({ "path": path_text(path) }))
}

/// The ops whose answer is the `HarnessAdapter` default for this harness.
pub(crate) fn common(spec: &Spec, op: &str, ctx: &Ctx) -> Step<Value> {
    match op {
        "resolved_executable" => resolved_executable(spec, ctx, &[]),
        "launch_env" => Ok(json!({ "env": {} })),
        "runtime_probe" => Ok(json!({ "probe": null })),
        "approval_flow" => Ok(spec.approval_flow()),
        _ => Err(Failure::Invalid),
    }
}
