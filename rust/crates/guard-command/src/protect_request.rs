//! Install-time protect request parsing and cached-advisory verdict, ported
//! from `protect.py` (`parse_protect_command`, `evaluate_protect_request`).
//!
//! Pure: the caller supplies the wrapped command and the cached advisory rows.
//! Parsing never touches the filesystem; `Path(...).name` and
//! `urlparse(...).path` are emulated on the token text.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::cloud_audit_sync::{urlparse_path_end, urlsplit};
use crate::command_launcher_floors::shlex_quote;
use crate::hook_adapter_pyjson::{parse_python_json, PyJsonError};
use crate::hook_adapter_value::OValue;
use crate::package_manager_command::strip_package_manager_global_options;
use crate::target_identities::{advisory_matches_target, build_package_url, py_str, py_truthy};
use crate::workspace_inventory::python_strip;

mod advisory;
mod package;
mod registration;

pub use advisory::evaluate_protect_request;
use package::*;
use registration::*;

const URL_PREFIXES: [&str; 4] = ["http://", "https://", "git+", "file:"];

/// Typed failure the resident reports instead of a request; the caller raises
/// the same `ValueError` Python's `urlparse` would have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectParseError {
    /// `urllib.parse.urlparse` raised `ValueError` for a package spec.
    InvalidUrl(String),
    /// A registration payload is valid JSON the port cannot represent.
    UnsupportedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectTarget {
    pub artifact_id: String,
    pub artifact_name: String,
    pub artifact_type: String,
    pub ecosystem: String,
    pub package_name: Option<String>,
    pub package_url: Option<String>,
    pub raw_spec: Option<String>,
    pub version: Option<String>,
    pub source_url: Option<String>,
    pub harness: Option<String>,
}

impl ProtectTarget {
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("artifact_id".into(), self.artifact_id.clone().into());
        map.insert("artifact_name".into(), self.artifact_name.clone().into());
        map.insert("artifact_type".into(), self.artifact_type.clone().into());
        map.insert("ecosystem".into(), self.ecosystem.clone().into());
        map.insert("package_name".into(), self.package_name.clone().into());
        map.insert("package_url".into(), self.package_url.clone().into());
        map.insert("raw_spec".into(), self.raw_spec.clone().into());
        map.insert("version".into(), self.version.clone().into());
        map.insert("source_url".into(), self.source_url.clone().into());
        map.insert("harness".into(), self.harness.clone().into());
        Value::Object(map)
    }

    /// `ProtectTargetIdentity` view used by `advisory_matches_target`.
    fn identity(&self) -> Value {
        let mut map = Map::new();
        map.insert("artifact_id".into(), self.artifact_id.clone().into());
        map.insert("artifact_name".into(), self.artifact_name.clone().into());
        map.insert("ecosystem".into(), self.ecosystem.clone().into());
        map.insert("package_name".into(), self.package_name.clone().into());
        map.insert("package_url".into(), self.package_url.clone().into());
        map.insert("source_url".into(), self.source_url.clone().into());
        Value::Object(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectRequest {
    pub command: Vec<String>,
    pub install_kind: String,
    pub executor: String,
    pub package_manager: Option<String>,
    pub harness: Option<String>,
    pub targets: Vec<ProtectTarget>,
}

impl ProtectRequest {
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("command".into(), self.command.clone().into());
        map.insert("install_kind".into(), self.install_kind.clone().into());
        map.insert("executor".into(), self.executor.clone().into());
        map.insert(
            "package_manager".into(),
            self.package_manager.clone().into(),
        );
        map.insert("harness".into(), self.harness.clone().into());
        map.insert(
            "targets".into(),
            Value::Array(self.targets.iter().map(ProtectTarget::to_value).collect()),
        );
        Value::Object(map)
    }
}

/// Verdict over the cached advisories; `matched` indexes the input rows in
/// severity order (highest first, stable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectVerdict {
    pub action: &'static str,
    pub reason: String,
    pub risk_signals: Vec<String>,
    pub matched: Vec<usize>,
}

fn registration(
    command: &[String],
    executor: &str,
    harness: &str,
    target: ProtectTarget,
) -> ProtectRequest {
    ProtectRequest {
        command: command.to_vec(),
        install_kind: "harness_registration".into(),
        executor: executor.into(),
        package_manager: None,
        harness: Some(harness.into()),
        targets: vec![target],
    }
}

#[allow(clippy::too_many_arguments)]
fn target(
    artifact_id: String,
    artifact_name: &str,
    artifact_type: &str,
    ecosystem: &str,
    package_name: Option<String>,
    package_url: Option<String>,
    raw_spec: Option<String>,
    version: Option<String>,
    source_url: Option<String>,
    harness: Option<&str>,
) -> ProtectTarget {
    ProtectTarget {
        artifact_id,
        artifact_name: artifact_name.into(),
        artifact_type: artifact_type.into(),
        ecosystem: ecosystem.into(),
        package_name,
        package_url,
        raw_spec,
        version,
        source_url,
        harness: harness.map(str::to_owned),
    }
}

/// `Path(text).name` for the host's pathlib flavour.
fn path_name(text: &str) -> &str {
    #[cfg(windows)]
    let (text, separators): (&str, &[char]) = {
        let bytes = text.as_bytes();
        let text = if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            &text[2..]
        } else {
            text
        };
        (text, &['/', '\\'])
    };
    #[cfg(not(windows))]
    let separators: &[char] = &['/'];
    text.split(separators)
        .rfind(|part| !part.is_empty() && *part != ".")
        .unwrap_or("")
}

fn starts_with_url(text: &str) -> bool {
    URL_PREFIXES.iter().any(|prefix| text.starts_with(prefix))
}

fn shlex_join(command: &[String]) -> String {
    command
        .iter()
        .map(|token| shlex_quote(token))
        .collect::<Vec<_>>()
        .join(" ")
}

fn command_fingerprint(command: &[String]) -> String {
    let digest = Sha256::digest(command.join("\u{0}").as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn option_value(command: &[String], option: &str) -> Option<String> {
    command
        .iter()
        .position(|value| value == option)
        .filter(|index| index + 1 < command.len())
        .map(|index| command[index + 1].clone())
}

fn first_url(command: &[String]) -> Option<String> {
    command.iter().find(|value| starts_with_url(value)).cloned()
}

/// `parse_protect_command`: dispatch on the lower-cased executable name.
pub fn parse_protect_command(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    let Some(first) = command.first() else {
        return Ok(parse_custom(&[String::new()]));
    };
    match path_name(first).to_lowercase().as_str() {
        "npm" => parse_package_manager(command, "npm"),
        "pnpm" => parse_package_manager(command, "pnpm"),
        "yarn" => parse_package_manager(command, "yarn"),
        "pip" | "pip3" => parse_package_manager(command, "pip"),
        "uv" => parse_package_manager(command, "uv"),
        "go" => parse_package_manager(command, "go"),
        "claude" => parse_claude(command),
        "codex" => parse_codex(command),
        "cursor" => parse_cursor(command),
        "antigravity" => parse_antigravity(command),
        "gemini" => parse_gemini(command),
        "opencode" => parse_opencode(command),
        _ => Ok(parse_custom(command)),
    }
}

#[cfg(test)]
#[path = "protect_request_tests.rs"]
mod tests;
