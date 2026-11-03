//! `omp_code_mode`: the doctor warning for Oh My Pi's Codex code mode.
//!
//! Code mode sends every tool call through `eval`, which Guard reviews, so an
//! Oh My Pi user with it on sees reviews for ordinary reads and edits. This
//! kind finds the settings files Oh My Pi reads, takes the effective
//! `providers.openai-codex.codeMode`, and answers a warning naming the file
//! to change when it is `on` or `auto`.
//!
//! The layers mirror Oh My Pi's loader, lowest precedence first: the first of
//! `config.yml` and `config.yaml` in the agent directory, then the project's
//! `.omp/config.yml`. The agent directory is `PI_CODING_AGENT_DIR` or
//! `<home>/<PI_CONFIG_DIR or .omp>/agent`; the caller passes those variables
//! (already `~`-expanded), or nothing when it describes another installation.
//!
//! A file is read with the bounded YAML 1.1 loader the Hermes configuration
//! uses. A file that is missing, larger than 1 MB, not UTF-8, or a document
//! that loader refuses (aliases, duplicate keys, non-text keys, timestamps)
//! leaves the mode unset; the warning is advice, so an unread file only means
//! no warning.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::hermes_yaml;
use crate::pyjson::PyVal;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const CODE_MODE_KEY: &str = "providers.openai-codex.codeMode";
const CODE_MODE_PATH: [&str; 3] = ["providers", "openai-codex", "codeMode"];
const MAX_CONFIG_BYTES: u64 = 1_000_000;
const USER_CONFIG_NAMES: [&str; 2] = ["config.yml", "config.yaml"];

fn optional_text<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, &'static str> {
    match args.get(key) {
        Some(Value::String(text)) => Ok(Some(text.as_str())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(ERR_INVALID),
    }
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let home = args
        .get("home")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let workspace = optional_text(args, "workspace")?;
    let agent_dir = optional_text(args, "agentDir")?;
    let config_dir = optional_text(args, "configDir")?;
    let layers = config_layers(
        Path::new(home),
        workspace.map(Path::new),
        agent_dir,
        config_dir,
    );
    let warnings: Vec<String> = effective_mode(&layers)
        .filter(|(mode, _)| matches!(mode.as_str(), "on" | "auto"))
        .map(|(_, path)| warning(&path))
        .into_iter()
        .collect();
    Ok(json!({ "warnings": warnings }))
}

fn warning(path: &Path) -> String {
    format!(
        "Oh My Pi Codex code mode sends every tool call through eval, which Guard reviews. \
         Set providers.openai-codex.codeMode to off in {} so Guard can allow ordinary reads and edits.",
        path.display()
    )
}

/// `omp_config_layers`: the files that can set code mode, lowest precedence
/// first. An empty variable counts as unset.
fn config_layers(
    home: &Path,
    workspace: Option<&Path>,
    agent_dir: Option<&str>,
    config_dir: Option<&str>,
) -> Vec<PathBuf> {
    let agent_dir = match agent_dir.filter(|dir| !dir.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => home
            .join(config_dir.filter(|dir| !dir.is_empty()).unwrap_or(".omp"))
            .join("agent"),
    };
    let mut layers: Vec<PathBuf> = USER_CONFIG_NAMES
        .iter()
        .map(|name| agent_dir.join(name))
        .find(|path| path.is_file())
        .into_iter()
        .collect();
    layers.extend(workspace.map(|workspace| workspace.join(".omp").join("config.yml")));
    layers
}

/// The last layer that sets a mode, with the file that set it.
fn effective_mode(layers: &[PathBuf]) -> Option<(String, PathBuf)> {
    layers
        .iter()
        .filter_map(|path| code_mode(path).map(|mode| (mode, path.clone())))
        .last()
}

/// `omp_code_mode_value`: the configured mode, or `None` when the file is
/// unset or unreadable. A boolean reads as `on` or `off`; text is trimmed and
/// lowercased.
fn code_mode(path: &Path) -> Option<String> {
    let metadata = fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let document = hermes_yaml::load(&text).ok()?.ok()?;
    mode_value(&document)
}

fn mode_value(document: &PyVal) -> Option<String> {
    document.as_dict()?;
    let value = match document.get(CODE_MODE_KEY) {
        None | Some(PyVal::Null) => CODE_MODE_PATH
            .iter()
            .try_fold(document, |node, part| node.get(part))?,
        Some(value) => value,
    };
    match value {
        PyVal::Bool(true) => Some("on".to_owned()),
        PyVal::Bool(false) => Some("off".to_owned()),
        PyVal::Str(text) => Some(text.trim().to_lowercase()),
        _ => None,
    }
}

#[cfg(test)]
#[path = "omp_code_mode_tests.rs"]
mod tests;
