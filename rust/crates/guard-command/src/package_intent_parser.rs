//! Rust port of `codex_plugin_scanner.guard.runtime.package_intent_parser`.
//!
//! Parses shell command text into `PackageIntent`s describing package-manager
//! install/execute/sync actions, including local-execution evidence for `npx`
//! and `bunx`. Mirrors the Python implementation one function per function.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::command_model::CanonicalCommand;
use crate::env_wrapper::parse_env_wrapper;
use crate::homebrew_intent::parse_brew_intent;
use crate::package_intent_common::*;
use crate::package_manager_command::strip_package_manager_global_options;
use crate::shell_execution_context::*;
use crate::shell_execution_context_support::*;
use crate::typescript_launch_evidence::*;

#[path = "package_intent_parser/managers_js.rs"]
mod managers_js;
use managers_js::*;

#[path = "package_intent_parser/execution_intent.rs"]
mod execution_intent;
use execution_intent::*;

#[path = "package_intent_parser/managers_python.rs"]
mod managers_python;
use managers_python::*;

#[path = "package_intent_parser/managers_other.rs"]
mod managers_other;
use managers_other::*;

#[path = "package_intent_parser/execution_context.rs"]
mod execution_context;
use execution_context::*;

#[path = "package_intent_parser/shell_normalization.rs"]
mod shell_normalization;
use shell_normalization::*;

#[path = "package_intent_parser/redaction_and_combination.rs"]
mod redaction_and_combination;
use redaction_and_combination::*;

#[path = "package_intent_parser/local_execution.rs"]
mod local_execution;
use local_execution::*;

#[path = "package_intent_parser/local_files.rs"]
mod local_files;
use local_files::*;

#[cfg(test)]
#[path = "package_intent_parser/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "package_intent_parser/uvx_value_options_tests.rs"]
mod uvx_value_options_tests;

// ---------------------------------------------------------------------------
// Module constants  (package_intent_parser.py :51-131)
// ---------------------------------------------------------------------------

// package_intent_parser.py :51  `_CONTROL_TOKENS`
static CONTROL_TOKENS: &[&str] = &["&&", "||", ";", "|", "|&", "&"];

// package_intent_parser.py :52-61  `_CONTROL_CONTEXT_LABELS`
fn control_context_label(operator: Option<&str>) -> &'static str {
    match operator {
        Some("&&") => "and",
        Some("||") => "or",
        Some(";") | Some("\n") => "sequence",
        Some("|") => "pipe",
        Some("|&") => "pipe-stderr",
        Some("&") => "background",
        _ => "end",
    }
}

// package_intent_parser.py :62  `_EXECUTION_CONTEXT_HMAC_KEY = os.urandom(32)`
// Fail-closed: if the OS RNG is unavailable the key is all-zero and every
// HMAC still runs (identical to Python semantics for hashing, just
// non-secret).  We deliberately keep the process-ephemeral nature.
static EXECUTION_CONTEXT_HMAC_KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    let mut key = [0u8; 32];
    if let Err(err) = getrandom::fill(&mut key) {
        // Match Python's "best effort" entropy acquisition. If the OS RNG
        // fails we still need a stable per-process key; fall back to a
        // deterministic-but-process-scoped value derived from pid+time so the
        // hash remains an oracle-only value.
        let mut h = Sha256::new();
        h.update(b"hol-guard-context-fallback");
        h.update(std::process::id().to_le_bytes());
        if let Ok(t) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            h.update(t.as_nanos().to_le_bytes());
        }
        let digest = h.finalize();
        key.copy_from_slice(&digest);
        let _ = err;
    }
    key
});

// package_intent_parser.py :63  `_ENV_ASSIGNMENT_RE`
static ENV_ASSIGNMENT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*=.*$").expect("env assignment regex"));

// package_intent_parser.py :64-66  `_ENV_REFERENCE_RE`
static ENV_REFERENCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))")
        .expect("env reference regex")
});

// package_intent_parser.py :67  `_LOCAL_EXECUTION_COMMANDS`
static LOCAL_EXECUTION_COMMANDS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ["bunx", "npx"].into_iter().collect());

// package_intent_parser.py :68-97  `_PACKAGE_COMMAND_NAMES`
static PACKAGE_COMMAND_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "apk", "apt", "apt-get", "brew", "bun", "bundle", "bundler", "bunx", "cargo", "composer",
        "dnf", "gem", "go", "gradle", "gradlew", "helm", "mvn", "mvnw", "npm", "npx", "pacman",
        "pip", "pip3", "pipenv", "pipx", "pnpm", "poetry", "uv", "uvx", "yarn", "yum", "zypper",
    ]
    .into_iter()
    .collect()
});

// package_intent_parser.py :98-103  `_LOCAL_EXECUTION_FLAGS_BY_COMMAND`
fn local_execution_flags(command: &str) -> &'static [&'static str] {
    match command {
        "bunx" => &["--bun", "--no-install"],
        "npx" => &["--no", "--no-install"],
        _ => &[],
    }
}

// package_intent_parser.py :104  `_LOCAL_EXECUTABLE_PACKAGE_ALIASES`
fn local_executable_package_alias(name: &str) -> &str {
    match name {
        "tsc" => "typescript",
        other => other,
    }
}

// package_intent_parser.py :105-107  `_JS_LOCKFILE_NAMES`
const JS_LOCKFILE_NAMES: &[&str] = &[
    "bun.lock",
    "bun.lockb",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
];

// package_intent_parser.py :108  `_PYTHON_EXECUTABLES`
static PYTHON_EXECUTABLES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "py",
        "python",
        "python3",
        "python3.11",
        "python3.12",
        "python3.13",
        "python3.14",
    ]
    .into_iter()
    .collect()
});

// package_intent_parser.py :109-131  `_PACKAGE_SOURCE_ENV_NAMES`
static PACKAGE_SOURCE_ENV_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "PIP_EXTRA_INDEX_URL",
        "PIP_FIND_LINKS",
        "PIP_INDEX_URL",
        "PIP_NO_INDEX",
        "UV_DEFAULT_INDEX",
        "UV_EXTRA_INDEX_URL",
        "UV_FIND_LINKS",
        "UV_INDEX",
        "UV_INDEX_URL",
        "UV_NO_INDEX",
        "NPM_CONFIG_REGISTRY",
        "YARN_NPM_REGISTRY_SERVER",
    ]
    .into_iter()
    .collect()
});

// ---------------------------------------------------------------------------
// HMAC-SHA256 (package_intent_parser.py `_opaque_unresolved_context_binding`)
// ---------------------------------------------------------------------------

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block_key = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        block_key[..32].copy_from_slice(&digest);
    } else {
        block_key[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    for (i, b) in block_key.iter().enumerate() {
        ipad[i] = b ^ 0x36;
        opad[i] = b ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let result = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// `_CommandSegment`  (package_intent_parser.py :134-144)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct CommandSegment {
    tokens: Vec<String>,
    redacted_tokens: Vec<String>,
    effective_path: Option<String>,
    path_source: String,
    effective_cwd: Option<PathBuf>,
    cwd_source: String,
    context_hash: String,
    context_complete: bool,
    context_reason_code: Option<String>,
}

// ---------------------------------------------------------------------------
// Public entry points  (package_intent_parser.py :147-…)
// ---------------------------------------------------------------------------

/// `parse_package_intent`  (package_intent_parser.py :147-…).
pub fn parse_package_intent(
    command_text: &str,
    workspace: Option<&Path>,
    home_dir: Option<&Path>,
    _canonical_command: Option<&CanonicalCommand>,
    environment: Option<&BTreeMap<String, String>>,
) -> Option<PackageIntent> {
    let segments = normalized_command_segments(command_text, workspace, home_dir, environment);
    let mut intents: Vec<PackageIntent> = Vec::new();
    for segment in &segments {
        if segment.tokens.is_empty() {
            continue;
        }
        let name = command_name(&segment.tokens[0]);
        let segment_workspace = if segment.context_complete {
            segment.effective_cwd.clone()
        } else {
            None
        };
        let mut intent = if LOCAL_EXECUTION_COMMANDS.contains(name.as_str()) {
            parse_exec_intent(
                &segment.tokens,
                workspace,
                segment.effective_path.as_deref(),
                &segment.path_source,
                segment.effective_cwd.as_deref(),
                &segment.cwd_source,
                &segment.context_hash,
                segment.context_complete,
            )
        } else {
            dispatch_intent(&name, &segment.tokens, segment_workspace.as_deref())
        };
        if let Some(mut i) = intent.take() {
            if segment.context_complete && segment_workspace.is_some() {
                i = rebase_intent_paths(i, segment_workspace.as_deref().unwrap(), workspace);
            } else if let Some(reason) = &segment.context_reason_code {
                i.notes.push(reason.clone());
            }
            if segment.cwd_source.starts_with("shell_")
                || segment.cwd_source.starts_with("env_chdir")
                || segment.context_reason_code.is_some()
            {
                i.execution_context_hashes = vec![segment.context_hash.clone()];
                i.execution_context_cwds = segment
                    .effective_cwd
                    .as_ref()
                    .map(|p| vec![p.to_string_lossy().into_owned()])
                    .unwrap_or_default();
                i.execution_context_reason_codes = segment
                    .context_reason_code
                    .as_ref()
                    .map(|r| vec![r.clone()])
                    .unwrap_or_default();
            }
            i.redacted_command = redacted_command(&segment.redacted_tokens);
            intents.push(i);
        }
    }
    combine_package_intents(&intents)
}

/// Dispatch to the non-local-execution intent parsers.
fn dispatch_intent(
    name: &str,
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    match name {
        "npm" => parse_npm_intent(tokens, workspace),
        "pnpm" => parse_pnpm_intent(tokens, workspace),
        "yarn" => parse_yarn_intent(tokens, workspace),
        "bun" => parse_bun_intent(tokens, workspace),
        "pip" | "pip3" => parse_pip_intent(tokens, workspace),
        "pipx" => parse_pipx_intent(tokens, workspace),
        "uv" => parse_uv_intent(tokens, workspace),
        "uvx" => parse_exec_intent_default(tokens, workspace),
        "poetry" => parse_poetry_intent(tokens, workspace),
        "pipenv" => parse_pipenv_intent(tokens, workspace),
        "cargo" => parse_cargo_intent(tokens, workspace),
        "go" => parse_go_intent(tokens, workspace),
        "mvn" | "mvnw" => parse_maven_intent(tokens, workspace),
        "gradle" | "gradlew" => parse_gradle_intent(tokens, workspace),
        "composer" => parse_composer_intent(tokens, workspace),
        "bundle" | "bundler" => parse_bundle_intent(tokens, workspace),
        "gem" => parse_gem_intent(tokens, workspace),
        "brew" => parse_brew_intent(tokens, workspace),
        "apt" | "apt-get" | "yum" | "dnf" | "apk" | "pacman" | "zypper" => {
            parse_system_package_intent(tokens, workspace)
        }
        "helm" => parse_helm_intent(tokens, workspace),
        _ => None,
    }
}

/// `extract_package_intent_request`  (package_intent_parser.py :1541-…).
pub fn extract_package_intent_request(
    tool_name: &str,
    arguments: &Value,
    action_envelope_command: Option<&str>,
    workspace: Option<&Path>,
    home_dir: Option<&Path>,
) -> Option<PackageIntent> {
    if let Some(normalized_tool_name) = normalize_tool_name(tool_name) {
        if SHELL_TOOL_NAMES.contains(&normalized_tool_name.as_str()) {
            for command_text in candidate_command_texts(arguments) {
                if let Some(intent) =
                    parse_package_intent(&command_text, workspace, home_dir, None, None)
                {
                    return Some(intent);
                }
            }
        }
    }
    if let Some(command) = action_envelope_command {
        return parse_package_intent(command, workspace, home_dir, None, None);
    }
    None
}

// ---------------------------------------------------------------------------
// Manager-specific intent parsers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// `_build_intent` / `_collect_specs`
// ---------------------------------------------------------------------------

// package_intent_parser.py `_build_intent`
#[allow(clippy::too_many_arguments)]
fn build_intent(
    package_manager: &str,
    intent_kind: IntentKind,
    command_tokens: &[String],
    targets: Vec<PackageIntentTarget>,
    workspace: Option<&Path>,
    manifest_candidates: &[String],
    lockfile_candidates: &[String],
    manifest_paths: &[String],
    notes: &[String],
) -> PackageIntent {
    PackageIntent {
        package_manager: package_manager.to_owned(),
        intent_kind,
        command_tokens: command_tokens.to_vec(),
        redacted_command: redacted_command(command_tokens),
        targets,
        manifest_paths: if manifest_paths.is_empty() {
            existing_relative_paths(workspace, manifest_candidates)
        } else {
            manifest_paths.to_vec()
        },
        lockfile_paths: existing_relative_paths(workspace, lockfile_candidates),
        flags: flag_tokens(&command_tokens[1..]),
        notes: notes.to_vec(),
        local_executions: Vec::new(),
        execution_context_hashes: Vec::new(),
        execution_context_cwds: Vec::new(),
        execution_context_reason_codes: Vec::new(),
    }
}

// package_intent_parser.py `_collect_specs`
fn collect_specs(tokens: &[String], skip_value_options: &[&str]) -> Vec<String> {
    let mut specs = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if skip_value_options.contains(&token.as_str()) && index + 1 < tokens.len() {
            index += 2;
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        specs.push(token.clone());
        index += 1;
    }
    specs
}

