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

// package_intent_parser.py `_parse_npm_intent`
fn parse_npm_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 {
        return None;
    }
    if matches!(
        working_tokens[1].as_str(),
        "install" | "i" | "add" | "update"
    ) {
        return Some(build_intent(
            "npm",
            "install",
            tokens,
            collect_package_specs(&working_tokens[2..])
                .iter()
                .map(|s| js_target(s))
                .collect(),
            workspace,
            &["package.json".to_owned()],
            &["package-lock.json".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens[1] == "ci"
        || (working_tokens.len() >= 3 && working_tokens[1] == "audit" && working_tokens[2] == "fix")
    {
        return Some(build_intent(
            "npm",
            "sync",
            tokens,
            Vec::new(),
            workspace,
            &["package.json".to_owned()],
            &["package-lock.json".to_owned()],
            &[],
            &[],
        ));
    }
    if matches!(working_tokens[1].as_str(), "exec" | "x") {
        return parse_exec_intent_default(&working_tokens, workspace);
    }
    None
}

// package_intent_parser.py `_parse_pnpm_intent`
fn parse_pnpm_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 {
        return None;
    }
    if matches!(working_tokens[1].as_str(), "add" | "install" | "i") {
        return Some(build_intent(
            "pnpm",
            "install",
            tokens,
            collect_specs(&working_tokens[2..], &["--filter", "-F"])
                .iter()
                .map(|s| js_target(s))
                .collect(),
            workspace,
            &["package.json".to_owned(), "pnpm-workspace.yaml".to_owned()],
            &["pnpm-lock.yaml".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens[1] == "dlx" {
        return parse_exec_intent_default(&working_tokens, workspace);
    }
    None
}

// package_intent_parser.py `_parse_yarn_intent`
fn parse_yarn_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    let mut notes: Vec<String> = Vec::new();
    let mut working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() >= 4 && working_tokens[1] == "workspace" {
        notes.push(format!("workspace:{}", working_tokens[2]));
        let mut next = vec![working_tokens[0].clone()];
        next.extend_from_slice(&working_tokens[3..]);
        working_tokens = next;
    }
    if working_tokens.len() < 2 {
        return None;
    }
    if matches!(working_tokens[1].as_str(), "add" | "install" | "up") {
        return Some(build_intent(
            "yarn",
            "install",
            tokens,
            collect_package_specs(&working_tokens[2..])
                .iter()
                .map(|s| js_target(s))
                .collect(),
            workspace,
            &["package.json".to_owned()],
            &["yarn.lock".to_owned()],
            &[],
            &notes,
        ));
    }
    if working_tokens[1] == "dlx" {
        return parse_exec_intent_default(&working_tokens, workspace);
    }
    None
}

// package_intent_parser.py `_parse_bun_intent`
fn parse_bun_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    if tokens.len() < 2 || !matches!(tokens[1].as_str(), "add" | "install") {
        return None;
    }
    Some(build_intent(
        "bun",
        "install",
        tokens,
        collect_package_specs(&tokens[2..])
            .iter()
            .map(|s| js_target(s))
            .collect(),
        workspace,
        &["package.json".to_owned()],
        &["bun.lock".to_owned(), "bun.lockb".to_owned()],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_exec_intent`
#[allow(clippy::too_many_arguments)]
fn parse_exec_intent(
    tokens: &[String],
    workspace: Option<&Path>,
    effective_path: Option<&str>,
    path_source: &str,
    effective_cwd: Option<&Path>,
    cwd_source: &str,
    execution_context_hash: &str,
    execution_context_complete: bool,
) -> Option<PackageIntent> {
    let package_token_value = exec_package_spec(tokens)?;
    let command = command_name(&tokens[0]);
    let ecosystem = if matches!(command.as_str(), "uvx" | "pipx") {
        "pypi"
    } else {
        "npm"
    };
    let target = if ecosystem == "pypi" {
        python_target(&package_token_value, false, None, Vec::new())
    } else {
        js_target(&package_token_value)
    };
    let is_local = LOCAL_EXECUTION_COMMANDS.contains(command.as_str());
    let manifest_candidates: &[&str] = if is_local { &["package.json"] } else { &[] };
    let lockfile_candidates: &[&str] = if is_local { JS_LOCKFILE_NAMES } else { &[] };
    let intent_workspace = if is_local { effective_cwd } else { workspace };
    let manifest_candidates: Vec<String> =
        manifest_candidates.iter().map(|s| s.to_string()).collect();
    let lockfile_candidates: Vec<String> =
        lockfile_candidates.iter().map(|s| s.to_string()).collect();
    let mut intent = build_intent(
        &command,
        "execute",
        tokens,
        vec![target],
        if execution_context_complete {
            intent_workspace
        } else {
            None
        },
        &manifest_candidates,
        &lockfile_candidates,
        &[],
        &[],
    );
    if !is_local {
        return Some(intent);
    }
    let mut local_execution = local_package_execution_evidence(
        &command,
        tokens,
        workspace,
        effective_path,
        path_source,
        if execution_context_complete {
            effective_cwd
        } else {
            None
        },
        cwd_source,
        execution_context_hash,
        &intent.manifest_paths,
        &intent.lockfile_paths,
    );
    if let Some(launch) =
        build_typescript_launch_evidence(&typescript_launch_inputs(tokens, &local_execution))
    {
        local_execution.typescript_launch = Some(launch.to_dict());
    }
    intent.local_executions = vec![local_execution];
    intent
        .notes
        .push("local-execution-requires-review".to_owned());
    Some(intent)
}

/// `_parse_exec_intent` called from non-local manager paths with Python's
/// default context arguments.
fn parse_exec_intent_default(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    parse_exec_intent(
        tokens,
        workspace,
        None,
        "not_applicable",
        None,
        "not_applicable",
        "not_applicable",
        true,
    )
}

// package_intent_parser.py `_exec_package_spec`
fn exec_package_spec(tokens: &[String]) -> Option<String> {
    let command = command_name(&tokens[0]);
    if command == "npm" && tokens.len() >= 2 && matches!(tokens[1].as_str(), "exec" | "x") {
        let explicit_package = option_value(tokens, "--package");
        let positional_package = first_positional(&tokens[2..], &["--package"]);
        if let (Some(positional), Some(explicit)) =
            (positional_package.clone(), explicit_package.clone())
        {
            let positional_target = js_target(&positional);
            let explicit_target = js_target(&explicit);
            if positional_target.package_name == explicit_target.package_name {
                let positional_specifier = positional_target
                    .requested_specifier
                    .clone()
                    .or(positional_target.source_url.clone());
                let explicit_specifier = explicit_target
                    .requested_specifier
                    .clone()
                    .or(explicit_target.source_url.clone());
                if positional_specifier.is_none() && explicit_specifier.is_some() {
                    return Some(explicit);
                }
                return Some(positional);
            }
            return Some(explicit);
        }
        return explicit_package.or(positional_package);
    }
    if command == "pipx" && tokens.len() >= 2 && tokens[1] == "run" {
        return first_positional(&tokens[2..], &["--python"]);
    }
    if matches!(command.as_str(), "pnpm" | "yarn") && tokens.len() >= 2 && tokens[1] == "dlx" {
        return first_positional(&tokens[2..], &[]);
    }
    if command == "npx" {
        return option_value(tokens, "--package")
            .or_else(|| first_positional(&tokens[1..], &["--package", "-p"]));
    }
    if command == "bunx" {
        return first_positional(&tokens[1..], &["--bun"]);
    }
    if command == "uvx" {
        return first_positional(&tokens[1..], &["--from", "--python", "--with"]);
    }
    None
}

// package_intent_parser.py `_parse_pip_intent`
fn parse_pip_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 || working_tokens[1] != "install" {
        return None;
    }
    let mut targets: Vec<PackageIntentTarget> = Vec::new();
    let mut manifest_paths: Vec<String> = Vec::new();
    let mut index = 2usize;
    while index < working_tokens.len() {
        let token = &working_tokens[index];
        if matches!(
            token.as_str(),
            "-r" | "--requirement" | "-c" | "--constraint"
        ) && index + 1 < working_tokens.len()
        {
            manifest_paths.push(working_tokens[index + 1].clone());
            index += 2;
            continue;
        }
        if token.starts_with("--requirement=") || token.starts_with("--constraint=") {
            manifest_paths.push(
                token
                    .split_once('=')
                    .map(|(_, v)| v)
                    .unwrap_or("")
                    .to_owned(),
            );
            index += 1;
            continue;
        }
        if token.starts_with("-r") && token != "-r" {
            manifest_paths.push(token[2..].to_owned());
            index += 1;
            continue;
        }
        if token.starts_with("-c") && token != "-c" {
            manifest_paths.push(token[2..].to_owned());
            index += 1;
            continue;
        }
        if matches!(token.as_str(), "-e" | "--editable") && index + 1 < working_tokens.len() {
            targets.push(python_target(
                &working_tokens[index + 1],
                true,
                None,
                Vec::new(),
            ));
            index += 2;
            continue;
        }
        if matches!(
            token.as_str(),
            "--index-url" | "--extra-index-url" | "--hash"
        ) && index + 1 < tokens.len()
        {
            index += 2;
            continue;
        }
        if token.starts_with("--hash=") || token.starts_with('-') {
            index += 1;
            continue;
        }
        targets.push(python_target(token, false, None, Vec::new()));
        index += 1;
    }
    Some(build_intent(
        "pip",
        "install",
        tokens,
        targets,
        workspace,
        &[],
        &[],
        &existing_relative_paths(workspace, &manifest_paths),
        &[],
    ))
}

// package_intent_parser.py `_parse_pipx_intent`
fn parse_pipx_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 3 || !matches!(working_tokens[1].as_str(), "install" | "run") {
        return None;
    }
    let target_spec = first_positional(&working_tokens[2..], &["--python"])?;
    Some(build_intent(
        "pipx",
        if working_tokens[1] == "run" {
            "execute"
        } else {
            "install"
        },
        tokens,
        vec![python_target(&target_spec, false, None, Vec::new())],
        workspace,
        &[],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_uv_intent`
fn parse_uv_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 {
        return None;
    }
    if working_tokens[1] == "add" {
        return Some(build_intent(
            "uv",
            "install",
            tokens,
            collect_package_specs(&working_tokens[2..])
                .iter()
                .map(|s| python_target(s, false, None, Vec::new()))
                .collect(),
            workspace,
            &["pyproject.toml".to_owned()],
            &["uv.lock".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens.len() >= 3 && working_tokens[1] == "pip" && working_tokens[2] == "install" {
        return Some(build_intent(
            "uv",
            "install",
            tokens,
            collect_package_specs(&working_tokens[3..])
                .iter()
                .map(|s| python_target(s, false, None, Vec::new()))
                .collect(),
            workspace,
            &["pyproject.toml".to_owned()],
            &["uv.lock".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens[1] == "sync" {
        return Some(build_intent(
            "uv",
            "sync",
            tokens,
            Vec::new(),
            workspace,
            &["pyproject.toml".to_owned()],
            &["uv.lock".to_owned()],
            &[],
            &[],
        ));
    }
    None
}

// package_intent_parser.py `_parse_poetry_intent`
fn parse_poetry_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 {
        return None;
    }
    if working_tokens[1] == "install" {
        return Some(build_intent(
            "poetry",
            "sync",
            tokens,
            Vec::new(),
            workspace,
            &["pyproject.toml".to_owned()],
            &["poetry.lock".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens[1] != "add" {
        return None;
    }
    let group =
        option_value(&working_tokens, "--group").or_else(|| option_value(&working_tokens, "-G"));
    let extras_value = option_value(&working_tokens, "--extras");
    let extras: Vec<String> = extras_value
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|item| !item.is_empty())
        .map(|item| item.to_owned())
        .collect();
    let targets = collect_package_specs(&working_tokens[2..])
        .iter()
        .map(|s| python_target(s, false, group.as_deref(), extras.clone()))
        .collect();
    Some(build_intent(
        "poetry",
        "install",
        tokens,
        targets,
        workspace,
        &["pyproject.toml".to_owned()],
        &["poetry.lock".to_owned()],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_pipenv_intent`
fn parse_pipenv_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 {
        return None;
    }
    if working_tokens[1] == "sync" {
        return Some(build_intent(
            "pipenv",
            "sync",
            tokens,
            Vec::new(),
            workspace,
            &["Pipfile".to_owned()],
            &["Pipfile.lock".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens[1] != "install" {
        return None;
    }
    Some(build_intent(
        "pipenv",
        "install",
        tokens,
        collect_package_specs(&working_tokens[2..])
            .iter()
            .map(|s| python_target(s, false, None, Vec::new()))
            .collect(),
        workspace,
        &["Pipfile".to_owned()],
        &["Pipfile.lock".to_owned()],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_cargo_intent`
fn parse_cargo_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    if tokens.len() < 2 || !matches!(tokens[1].as_str(), "add" | "install") {
        return None;
    }
    let mut source_url = option_value(tokens, "--path").map(|value| format!("file:{value}"));
    if source_url.is_none() {
        source_url = option_value(tokens, "--git");
    }
    let targets = collect_specs(
        &tokens[2..],
        &[
            "--branch",
            "--git",
            "--index",
            "--path",
            "--registry",
            "--rev",
            "--tag",
        ],
    )
    .iter()
    .map(|spec| version_target("cargo", spec, source_url.as_deref()))
    .collect();
    Some(build_intent(
        "cargo",
        "install",
        tokens,
        targets,
        workspace,
        &["Cargo.toml".to_owned()],
        &["Cargo.lock".to_owned()],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_go_intent`
fn parse_go_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    if tokens.len() < 2 || !matches!(tokens[1].as_str(), "get" | "install") {
        return None;
    }
    Some(build_intent(
        "go",
        "install",
        tokens,
        collect_package_specs(&tokens[2..])
            .iter()
            .map(|s| version_target("go", s, None))
            .collect(),
        workspace,
        &["go.mod".to_owned()],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_maven_intent`
fn parse_maven_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    let mut artifact_value = property_value(tokens, "artifact");
    if artifact_value.is_none() {
        let includes = property_value(tokens, "includes");
        let dep_version = property_value(tokens, "depVersion");
        artifact_value = match (includes, dep_version) {
            (Some(includes), Some(dep_version)) => Some(format!("{includes}:{dep_version}")),
            _ => None,
        };
    }
    let artifact_value = artifact_value?;
    Some(build_intent(
        "maven",
        "install",
        tokens,
        vec![coordinate_target("maven", &artifact_value)],
        workspace,
        &["pom.xml".to_owned()],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_gradle_intent`
fn parse_gradle_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    let dependency_value = option_value(tokens, "--dependency")?;
    Some(build_intent(
        "gradle",
        "install",
        tokens,
        vec![coordinate_target("maven", &dependency_value)],
        workspace,
        &["build.gradle".to_owned(), "build.gradle.kts".to_owned()],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_composer_intent`
fn parse_composer_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    if tokens.len() < 2 || !matches!(tokens[1].as_str(), "require" | "install" | "update") {
        return None;
    }
    Some(build_intent(
        "composer",
        "install",
        tokens,
        collect_package_specs(&tokens[2..])
            .iter()
            .map(|s| composer_target(s))
            .collect(),
        workspace,
        &["composer.json".to_owned()],
        &["composer.lock".to_owned()],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_bundle_intent`
fn parse_bundle_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    if tokens.len() < 2 {
        return None;
    }
    if tokens[1] == "install" {
        return Some(build_intent(
            "bundle",
            "sync",
            tokens,
            Vec::new(),
            workspace,
            &["Gemfile".to_owned()],
            &["Gemfile.lock".to_owned()],
            &[],
            &[],
        ));
    }
    if tokens[1] != "add" || tokens.len() < 3 {
        return None;
    }
    let version = option_value(tokens, "--version");
    Some(build_intent(
        "bundle",
        "install",
        tokens,
        vec![PackageIntentTarget {
            ecosystem: "rubygems".to_owned(),
            package_name: Some(tokens[2].clone()),
            raw_spec: tokens[2].clone(),
            requested_specifier: version,
            ..Default::default()
        }],
        workspace,
        &["Gemfile".to_owned()],
        &["Gemfile.lock".to_owned()],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_gem_intent`
fn parse_gem_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    if tokens.len() < 3 || tokens[1] != "install" {
        return None;
    }
    let version = option_value(tokens, "-v").or_else(|| option_value(tokens, "--version"));
    Some(build_intent(
        "gem",
        "install",
        tokens,
        vec![PackageIntentTarget {
            ecosystem: "rubygems".to_owned(),
            package_name: Some(tokens[2].clone()),
            raw_spec: tokens[2].clone(),
            requested_specifier: version,
            ..Default::default()
        }],
        workspace,
        &[],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_system_package_intent`
fn parse_system_package_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    if tokens.len() < 2 {
        return None;
    }
    let name = command_name(&tokens[0]);
    let verb = tokens[1].to_lowercase();
    let install_verbs: &[&str] = match name.as_str() {
        "apk" => &["add"],
        "apt" | "apt-get" | "dnf" | "yum" => &["install"],
        "brew" => &["install"],
        "pacman" => &["-s", "-sy", "-syu", "-suy"],
        "zypper" => &["install", "in"],
        _ => &[],
    };
    if !install_verbs.contains(&verb.as_str()) {
        return None;
    }
    let targets = collect_specs(&tokens[2..], &["--repo", "--repository", "-c"])
        .iter()
        .map(|spec| PackageIntentTarget {
            ecosystem: "system".to_owned(),
            package_name: Some(spec.clone()),
            raw_spec: spec.clone(),
            ..Default::default()
        })
        .collect();
    Some(build_intent(
        &name,
        "install",
        tokens,
        targets,
        workspace,
        &[],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_helm_intent`
fn parse_helm_intent(tokens: &[String], workspace: Option<&Path>) -> Option<PackageIntent> {
    if tokens.len() < 4 || tokens[1] != "install" {
        return None;
    }
    let chart = first_positional(&tokens[3..], &["--version", "--repo", "-n", "--namespace"])
        .unwrap_or_else(|| tokens[3].clone());
    let version = option_value(tokens, "--version");
    let target = PackageIntentTarget {
        ecosystem: "unsupported".to_owned(),
        package_name: Some(chart.clone()),
        raw_spec: chart,
        requested_specifier: version,
        ..Default::default()
    };
    Some(build_intent(
        "helm",
        "install",
        tokens,
        vec![target],
        workspace,
        &[],
        &[],
        &[],
        &[],
    ))
}

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

// ---------------------------------------------------------------------------
// `_normalized_command_segments` and context machinery
// ---------------------------------------------------------------------------

// package_intent_parser.py `_normalized_command_segments`
fn normalized_command_segments(
    command_text: &str,
    workspace: Option<&Path>,
    home_dir: Option<&Path>,
    environment: Option<&BTreeMap<String, String>>,
) -> Vec<CommandSegment> {
    let default_environment;
    let inherited_environment: &BTreeMap<String, String> = match environment {
        Some(env) => env,
        None => {
            default_environment = std::env::vars().collect::<BTreeMap<_, _>>();
            &default_environment
        }
    };
    let mut execution_context =
        model_shell_execution_context(command_text, workspace, workspace, home_dir);
    if !execution_context.complete && home_dir.is_some() {
        let home_context =
            model_shell_execution_context(command_text, home_dir, home_dir, home_dir);
        if home_context.complete
            && !home_context.segments.is_empty()
            && home_context.segments[0].directory_operation.as_deref() == Some("cd")
        {
            let target = home_context
                .segments
                .iter()
                .skip(1)
                .find_map(|segment| segment.effective_cwd.clone());
            if let Some(target) = target {
                let recovered = model_shell_execution_context(
                    command_text,
                    Some(target.as_path()),
                    Some(target.as_path()),
                    home_dir,
                );
                if recovered.complete {
                    execution_context = recovered;
                }
            }
        }
    }
    let control_shape: Vec<&'static str> = execution_context
        .segments
        .iter()
        .map(|segment| control_context_label(segment.control_operator().map(|s| s.as_str())))
        .collect();
    let mut segments: Vec<CommandSegment> = Vec::new();
    for context_segment in &execution_context.segments {
        let raw_segment: Vec<String> = context_segment.tokens.clone();
        let normalized_tokens = normalize_segment(&raw_segment);
        if normalized_tokens.is_empty() {
            continue;
        }
        let redacted_tokens = redacted_segment(&raw_segment);
        let (modeled_cwd, validation_reason) =
            validate_shell_execution_segment(&execution_context, context_segment);
        let (effective_path, path_source, effective_cwd, cwd_source) = match modeled_cwd {
            None => (
                None,
                "cwd_unresolved".to_owned(),
                None,
                validation_reason
                    .clone()
                    .or_else(|| context_segment.reason_code.clone())
                    .unwrap_or_else(|| "cwd_unresolved".to_owned()),
            ),
            Some(modeled_cwd) => effective_execution_context(
                &raw_segment,
                workspace,
                &modeled_cwd,
                &context_segment.cwd_source,
                inherited_environment,
            ),
        };
        let context_complete = validation_reason.is_none() && context_segment.complete;
        let opaque_binding =
            opaque_unresolved_context_binding(&raw_segment, &path_source, &cwd_source);
        let context_hash = execution_context_hash(
            &execution_context,
            context_segment,
            &control_shape,
            effective_cwd.as_deref(),
            &cwd_source,
            &path_source,
            opaque_binding.as_deref(),
        );
        segments.push(CommandSegment {
            tokens: normalized_tokens,
            redacted_tokens,
            effective_path,
            path_source,
            effective_cwd,
            cwd_source,
            context_hash,
            context_complete,
            context_reason_code: validation_reason.or_else(|| context_segment.reason_code.clone()),
        });
    }
    segments
}

// package_intent_parser.py `_effective_execution_context`
fn effective_execution_context(
    raw_segment: &[String],
    workspace: Option<&Path>,
    initial_cwd: &Path,
    initial_cwd_source: &str,
    supplied_environment: &BTreeMap<String, String>,
) -> (Option<String>, String, Option<PathBuf>, String) {
    let mut effective_path: Option<String> = supplied_environment.get("PATH").cloned();
    let mut path_source = if effective_path.is_some() {
        "inherited".to_owned()
    } else {
        "inherited_unset".to_owned()
    };
    let mut effective_cwd: Option<PathBuf> = Some(initial_cwd.to_path_buf());
    let mut cwd_source = initial_cwd_source.to_owned();
    let _ = workspace;
    if raw_segment.is_empty() {
        return (
            effective_path
                .as_deref()
                .map(|path| path_for_resolution(path, effective_cwd.as_deref())),
            path_source,
            effective_cwd,
            cwd_source,
        );
    }
    let mut index = 0usize;
    let (next_index, next_path, next_source) = consume_path_assignments(
        raw_segment,
        index,
        effective_path.clone(),
        &path_source,
        "inline",
        supplied_environment,
    );
    index = next_index;
    effective_path = next_path;
    path_source = next_source;
    if index >= raw_segment.len() {
        return (
            effective_path
                .as_deref()
                .map(|path| path_for_resolution(path, effective_cwd.as_deref())),
            path_source,
            effective_cwd,
            cwd_source,
        );
    }
    let mut name = command_name(&raw_segment[index]);
    if name == "sudo" {
        return (
            None,
            "sudo_unresolved".to_owned(),
            effective_cwd,
            cwd_source,
        );
    }
    while matches!(name.as_str(), "command" | "time") {
        index += 1;
        if name == "command" {
            while index < raw_segment.len() && raw_segment[index].starts_with('-') {
                if raw_segment[index][1..].contains('p') {
                    effective_path = Some(default_path());
                    path_source = "command_default".to_owned();
                }
                index += 1;
            }
        } else if index < raw_segment.len() && raw_segment[index].starts_with('-') {
            return (
                None,
                "time_options_unresolved".to_owned(),
                effective_cwd,
                cwd_source,
            );
        }
        let (next_index, next_path, next_source) = consume_path_assignments(
            raw_segment,
            index,
            effective_path.clone(),
            &path_source,
            "inline",
            supplied_environment,
        );
        index = next_index;
        effective_path = next_path;
        path_source = next_source;
        if index >= raw_segment.len() {
            return (
                effective_path
                    .as_deref()
                    .map(|path| path_for_resolution(path, effective_cwd.as_deref())),
                path_source,
                effective_cwd,
                cwd_source,
            );
        }
        name = command_name(&raw_segment[index]);
    }
    if name != "env" {
        return (
            effective_path
                .as_deref()
                .map(|path| path_for_resolution(path, effective_cwd.as_deref())),
            path_source,
            effective_cwd,
            cwd_source,
        );
    }

    let mut inherited_environment = supplied_environment.clone();
    match &effective_path {
        None => {
            inherited_environment.remove("PATH");
        }
        Some(path) => {
            inherited_environment.insert("PATH".to_owned(), path.clone());
        }
    }
    let parsed_env = parse_env_wrapper(
        &raw_segment[index + 1..],
        Some(&inherited_environment),
        effective_cwd.as_deref(),
    );
    if !parsed_env.complete {
        return (
            None,
            format!(
                "env_{}",
                parsed_env.error.as_deref().unwrap_or("unresolved")
            ),
            effective_cwd,
            cwd_source,
        );
    }
    let path_was_unset = parsed_env
        .option_effects
        .unset_names
        .iter()
        .any(|n| n == "PATH");
    let path_assignment = parsed_env
        .environment_delta
        .assignments
        .iter()
        .rev()
        .find(|(n, _)| n == "PATH")
        .map(|(_, v)| v.clone());
    if let Some(search_path) = &parsed_env.option_effects.search_path {
        effective_path = expanded_path_assignment(
            search_path,
            effective_path.as_deref(),
            &inherited_environment,
        );
        path_source = if effective_path.is_some() {
            "env_search_path".to_owned()
        } else {
            "env_search_path_unresolved".to_owned()
        };
    } else if let Some(assignment) = &path_assignment {
        effective_path = expanded_path_assignment(
            assignment,
            effective_path.as_deref(),
            &inherited_environment,
        );
        path_source = if effective_path.is_some() {
            "env".to_owned()
        } else {
            "env_unresolved".to_owned()
        };
    } else if parsed_env.option_effects.ignore_environment || path_was_unset {
        effective_path = Some(default_path());
        path_source = "env_default".to_owned();
    }
    if let Some(chdir) = &parsed_env.option_effects.chdir {
        if chdir.contains('$') || chdir.contains('\0') {
            cwd_source = "env_chdir_unresolved".to_owned();
        } else if let Some(env_cwd) = &parsed_env.effective_cwd {
            match env_cwd.canonicalize() {
                Ok(resolved) => {
                    effective_cwd = Some(resolved);
                    cwd_source = "env_chdir".to_owned();
                }
                Err(_) => {
                    cwd_source = "env_chdir_unresolved".to_owned();
                }
            }
        }
    }
    (
        effective_path
            .as_deref()
            .map(|path| path_for_resolution(path, effective_cwd.as_deref())),
        path_source,
        effective_cwd,
        cwd_source,
    )
}

// package_intent_parser.py `_execution_context_hash`
#[allow(clippy::too_many_arguments)]
fn execution_context_hash(
    context: &ShellExecutionContext,
    segment: &ShellExecutionSegment,
    control_shape: &[&'static str],
    effective_cwd: Option<&Path>,
    cwd_source: &str,
    path_source: &str,
    opaque_context_binding: Option<&str>,
) -> String {
    let mut payload = Map::new();
    payload.insert(
        "schema".to_owned(),
        json!("local-package-execution-context-v2"),
    );
    payload.insert("control_shape".to_owned(), json!(control_shape));
    payload.insert("segment_index".to_owned(), json!(segment.segment_index));
    payload.insert("control_before".to_owned(), json!(segment.control_before));
    payload.insert("control_after".to_owned(), json!(segment.control_after));
    payload.insert(
        "workspace_root".to_owned(),
        context
            .workspace_root
            .as_ref()
            .map(|p| json!(p.to_string_lossy()))
            .unwrap_or(Value::Null),
    );
    payload.insert(
        "workspace_identity".to_owned(),
        shell_path_identity_payload(context.workspace_identity.as_ref()).unwrap_or(Value::Null),
    );
    payload.insert(
        "effective_cwd".to_owned(),
        effective_cwd
            .map(|p| json!(p.to_string_lossy()))
            .unwrap_or(Value::Null),
    );
    payload.insert(
        "cwd_identity".to_owned(),
        shell_path_identity_payload(segment.cwd_identity.as_ref()).unwrap_or(Value::Null),
    );
    payload.insert(
        "cwd_path_proofs".to_owned(),
        Value::Array(
            segment
                .cwd_path_proofs
                .iter()
                .map(|proof| {
                    let mut p = Map::new();
                    p.insert(
                        "lexical_path".to_owned(),
                        json!(proof.lexical_path.to_string_lossy()),
                    );
                    p.insert(
                        "resolved_path".to_owned(),
                        json!(proof.resolved_path.to_string_lossy()),
                    );
                    p.insert(
                        "identity".to_owned(),
                        shell_path_identity_payload(Some(&proof.identity)).unwrap_or(Value::Null),
                    );
                    Value::Object(p)
                })
                .collect(),
        ),
    );
    payload.insert(
        "directory_stack".to_owned(),
        Value::Array(
            segment
                .directory_stack
                .iter()
                .map(|p| json!(p.to_string_lossy()))
                .collect(),
        ),
    );
    payload.insert("cwd_source".to_owned(), json!(cwd_source));
    payload.insert("path_source".to_owned(), json!(path_source));
    payload.insert(
        "opaque_context_binding".to_owned(),
        opaque_context_binding
            .map(|s| json!(s))
            .unwrap_or(Value::Null),
    );
    // Python `json.dumps(payload, sort_keys=True, separators=(",", ":"))` —
    // `serde_json::to_string` emits compact JSON; `Value::Object` keys are
    // already BTreeMap-sorted.
    let payload_str = serde_json::to_string(&Value::Object(payload)).unwrap_or_default();
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(payload_str.as_bytes()))
    )
}

// package_intent_parser.py `_raw_command_segments`
#[allow(dead_code)]
fn raw_command_segments(tokens: &[String]) -> Vec<Vec<String>> {
    raw_command_segments_with_operators(tokens)
        .into_iter()
        .map(|(segment, _)| segment)
        .collect()
}

// package_intent_parser.py `_raw_command_segments_with_operators`
fn raw_command_segments_with_operators(tokens: &[String]) -> Vec<(Vec<String>, Option<String>)> {
    let mut segments: Vec<(Vec<String>, Option<String>)> = Vec::new();
    let mut segment: Vec<String> = Vec::new();
    for token in tokens {
        if CONTROL_TOKENS.contains(&token.as_str()) {
            if !segment.is_empty() {
                segments.push((std::mem::take(&mut segment), Some(token.clone())));
            }
            segment.clear();
            continue;
        }
        segment.push(token.clone());
    }
    if !segment.is_empty() {
        segments.push((segment, None));
    }
    segments
}

// package_intent_parser.py `_normalize_segment`
fn normalize_segment(raw_segment: &[String]) -> Vec<String> {
    if let Some(substitution_segment) = shell_substitution_segment(raw_segment) {
        return without_fd_merge_redirections(&substitution_segment);
    }
    if command_builtin_is_lookup(&strip_command_lookup_prefixes(raw_segment.to_vec())) {
        return Vec::new();
    }
    let mut segment = without_fd_merge_redirections(&strip_wrapper_tokens(raw_segment.to_vec()));
    if segment.len() >= 3
        && PYTHON_EXECUTABLES.contains(command_name(&segment[0]).as_str())
        && segment[1] == "-m"
    {
        segment = segment[2..].to_vec();
    }
    segment
}

// package_intent_parser.py `_consume_path_assignments`
fn consume_path_assignments(
    tokens: &[String],
    mut index: usize,
    mut current_path: Option<String>,
    current_source: &str,
    direct_source: &str,
    environment: &BTreeMap<String, String>,
) -> (usize, Option<String>, String) {
    let mut path_source = current_source.to_owned();
    while index < tokens.len() && ENV_ASSIGNMENT_RE.is_match(&tokens[index]) {
        let (name, _, value) = {
            let parts: Vec<&str> = tokens[index].splitn(2, '=').collect();
            (
                parts.first().copied().unwrap_or(""),
                "",
                parts.get(1).copied().unwrap_or(""),
            )
        };
        if name == "PATH" {
            current_path = expanded_path_assignment(value, current_path.as_deref(), environment);
            path_source = if current_path.is_some() {
                direct_source.to_owned()
            } else {
                format!("{direct_source}_unresolved")
            };
        }
        index += 1;
    }
    (index, current_path, path_source)
}

// package_intent_parser.py `_expanded_path_assignment`
fn expanded_path_assignment(
    value: &str,
    current_path: Option<&str>,
    environment: &BTreeMap<String, String>,
) -> Option<String> {
    let mut expansion_environment = environment.clone();
    expansion_environment.insert("PATH".to_owned(), current_path.unwrap_or("").to_owned());
    let expanded = ENV_REFERENCE_RE
        .replace_all(value, |caps: &regex::Captures<'_>| {
            let name = caps
                .name("braced")
                .or_else(|| caps.name("plain"))
                .map(|m| m.as_str())
                .unwrap_or("");
            expansion_environment.get(name).cloned().unwrap_or_else(|| {
                caps.get(0)
                    .map(|m| m.as_str().to_owned())
                    .unwrap_or_default()
            })
        })
        .into_owned();
    if expanded.contains('$') || expanded.contains('\0') {
        return None;
    }
    Some(expanded)
}

// package_intent_parser.py `_package_source_env_assignment`
fn package_source_env_assignment(token: &str) -> bool {
    let mut parts = token.splitn(2, '=');
    let name = parts.next().unwrap_or("");
    let value = parts.next();
    match value {
        Some(value) => {
            !value.is_empty() && PACKAGE_SOURCE_ENV_NAMES.contains(&*name.to_uppercase())
        }
        None => false,
    }
}

// package_intent_parser.py `_updated_effective_cwd`
#[allow(dead_code)]
fn updated_effective_cwd(current_cwd: &Path, value: &str) -> (PathBuf, String) {
    let expanded = expand_env_vars(value);
    if expanded.is_empty() || expanded.contains('$') || expanded.contains('\0') {
        return (current_cwd.to_path_buf(), "env_chdir_unresolved".to_owned());
    }
    let mut candidate = expand_user(&expanded);
    if !candidate.is_absolute() {
        candidate = current_cwd.join(&candidate);
    }
    match candidate.canonicalize() {
        Ok(resolved) => (resolved, "env_chdir".to_owned()),
        Err(_) => (current_cwd.to_path_buf(), "env_chdir_unresolved".to_owned()),
    }
}

/// `os.path.expandvars` equivalent — substitute `$NAME`/`${NAME}` against the
/// process environment.
fn expand_env_vars(value: &str) -> String {
    ENV_REFERENCE_RE
        .replace_all(value, |caps: &regex::Captures<'_>| {
            let name = caps
                .name("braced")
                .or_else(|| caps.name("plain"))
                .map(|m| m.as_str())
                .unwrap_or("");
            std::env::var(name).unwrap_or_default()
        })
        .into_owned()
}

/// `Path.expanduser` equivalent — `~`/`~user` prefix expansion.
fn expand_user(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix('~') {
        if rest.is_empty() || rest.starts_with('/') {
            if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
            {
                return PathBuf::from(home).join(rest.trim_start_matches('/'));
            }
        }
        // `~name/` form — not resolved without pwd database; leave as-is.
        return PathBuf::from(path);
    }
    PathBuf::from(path)
}

// package_intent_parser.py `_path_for_resolution`
fn path_for_resolution(path_value: &str, effective_cwd: Option<&Path>) -> String {
    let mut rendered: Vec<String> = Vec::new();
    for entry in path_value.split(':') {
        let mut rendered_entry = entry.to_owned();
        if rendered_entry.is_empty() {
            rendered_entry = ".".to_owned();
        }
        let mut path = PathBuf::from(&rendered_entry);
        if !path.is_absolute() {
            if let Some(cwd) = effective_cwd {
                path = cwd.join(&path);
            }
        }
        rendered.push(path.to_string_lossy().into_owned());
    }
    rendered.join(":")
}

// package_intent_parser.py `_command_builtin_is_lookup`
fn command_builtin_is_lookup(segment: &[String]) -> bool {
    if segment.is_empty() || command_name(&segment[0]) != "command" {
        return false;
    }
    let mut saw_lookup = false;
    let mut index = 1usize;
    while index < segment.len() && segment[index].starts_with('-') {
        let option = &segment[index];
        saw_lookup = saw_lookup || option[1..].contains('v') || option[1..].contains('V');
        index += 1;
    }
    let operands: Vec<&String> = segment[index..]
        .iter()
        .filter(|token| !token.contains('>') && !token.contains('<'))
        .collect();
    saw_lookup && operands.len() == 1
}

// package_intent_parser.py `_shell_substitution_segment`
fn shell_substitution_segment(segment: &[String]) -> Option<Vec<String>> {
    for (index, token) in segment.iter().enumerate() {
        if !token.contains('`') && !token.contains("$(") {
            continue;
        }
        let mut best: Option<(usize, usize)> = None;
        for marker in ["`", "$("] {
            if let Some(position) = token.find(marker) {
                let candidate = (position, marker.len());
                if best.map(|(p, _)| position < p).unwrap_or(true) {
                    best = Some(candidate);
                }
            }
        }
        let (position, marker_len) = best?;
        let command = &token[position + marker_len..];
        let mut seed = vec![command.to_owned()];
        seed.extend_from_slice(&segment[index + 1..]);
        let normalized = if command.is_empty() {
            Vec::new()
        } else {
            strip_wrapper_tokens(seed)
        };
        if !normalized.is_empty()
            && PACKAGE_COMMAND_NAMES.contains(command_name(&normalized[0]).as_str())
        {
            return Some(normalized);
        }
    }
    None
}

// package_intent_parser.py `_without_fd_merge_redirections`
fn without_fd_merge_redirections(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .filter(|token| token.as_str() != "1>&2" && token.as_str() != "2>&1")
        .cloned()
        .collect()
}

// package_intent_parser.py `_strip_wrapper_tokens`
fn strip_wrapper_tokens(mut segment: Vec<String>) -> Vec<String> {
    while !segment.is_empty() {
        if ENV_ASSIGNMENT_RE.is_match(&segment[0]) {
            segment.remove(0);
            continue;
        }
        let name = command_name(&segment[0]);
        if name == "sudo" {
            segment = strip_sudo_prefix(&segment[1..]);
            continue;
        }
        if name == "env" {
            segment = strip_env_prefix(&segment[1..]);
            continue;
        }
        if matches!(name.as_str(), "command" | "time") {
            segment = strip_plain_wrapper_flags(&segment[1..]);
            continue;
        }
        break;
    }
    segment
}

// package_intent_parser.py `_strip_command_lookup_prefixes`
fn strip_command_lookup_prefixes(mut segment: Vec<String>) -> Vec<String> {
    while !segment.is_empty() {
        if ENV_ASSIGNMENT_RE.is_match(&segment[0]) {
            if segment[0].contains('`') || segment[0].contains("$(") {
                return segment;
            }
            segment.remove(0);
            continue;
        }
        if command_name(&segment[0]) == "time" {
            segment = strip_plain_wrapper_flags(&segment[1..]);
            continue;
        }
        break;
    }
    segment
}

// package_intent_parser.py `_strip_sudo_prefix`
fn strip_sudo_prefix(tokens: &[String]) -> Vec<String> {
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if !token.starts_with('-') {
            break;
        }
        if matches!(
            token.as_str(),
            "-u" | "-g" | "-h" | "-p" | "-r" | "-t" | "-C"
        ) && index + 1 < tokens.len()
        {
            index += 2;
            continue;
        }
        index += 1;
    }
    tokens[index..].to_vec()
}

// package_intent_parser.py `_strip_redaction_wrappers`
fn strip_redaction_wrappers(mut segment: Vec<String>) -> Vec<String> {
    let mut preserved_env: Vec<String> = Vec::new();
    while !segment.is_empty() {
        if ENV_ASSIGNMENT_RE.is_match(&segment[0]) {
            if package_source_env_assignment(&segment[0]) {
                preserved_env.push(segment[0].clone());
            }
            segment.remove(0);
            continue;
        }
        let name = command_name(&segment[0]);
        if name == "sudo" {
            segment = strip_sudo_prefix(&segment[1..]);
            continue;
        }
        if name == "env" {
            let (env_preserved, next) = strip_env_prefix_for_redaction(&segment[1..]);
            preserved_env.extend(env_preserved);
            segment = next;
            continue;
        }
        if matches!(name.as_str(), "command" | "time") {
            segment = strip_plain_wrapper_flags(&segment[1..]);
            continue;
        }
        break;
    }
    preserved_env.extend(segment);
    preserved_env
}

// package_intent_parser.py `_strip_plain_wrapper_flags`
fn strip_plain_wrapper_flags(tokens: &[String]) -> Vec<String> {
    let mut index = 0usize;
    while index < tokens.len() && tokens[index].starts_with('-') {
        index += 1;
    }
    tokens[index..].to_vec()
}

// package_intent_parser.py `_strip_env_prefix`
fn strip_env_prefix(tokens: &[String]) -> Vec<String> {
    let parsed = parse_env_wrapper(tokens, None, None);
    if parsed.complete {
        parsed.executable_argv
    } else {
        Vec::new()
    }
}

// package_intent_parser.py `_strip_env_prefix_for_redaction`
fn strip_env_prefix_for_redaction(tokens: &[String]) -> (Vec<String>, Vec<String>) {
    let parsed = parse_env_wrapper(tokens, None, None);
    if !parsed.complete {
        return (Vec::new(), Vec::new());
    }
    let preserved_env: Vec<String> = parsed
        .environment_delta
        .assignments
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .filter(|token| package_source_env_assignment(token))
        .collect();
    (preserved_env, parsed.executable_argv)
}

// package_intent_parser.py `_redacted_segment`
fn redacted_segment(raw_segment: &[String]) -> Vec<String> {
    if let Some(substitution_segment) = shell_substitution_segment(raw_segment) {
        return without_fd_merge_redirections(&substitution_segment);
    }
    if command_builtin_is_lookup(&strip_command_lookup_prefixes(raw_segment.to_vec())) {
        return Vec::new();
    }
    let mut segment =
        without_fd_merge_redirections(&strip_redaction_wrappers(raw_segment.to_vec()));
    if segment.len() >= 3
        && PYTHON_EXECUTABLES.contains(command_name(&segment[0]).as_str())
        && segment[1] == "-m"
    {
        segment = segment[2..].to_vec();
    }
    redact_local_source_tokens(&segment)
}

// package_intent_parser.py `_redact_local_source_tokens`
fn redact_local_source_tokens(tokens: &[String]) -> Vec<String> {
    let mut redacted: Vec<String> = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "--path" && index + 1 < tokens.len() {
            redacted.push("--path".to_owned());
            redacted.push("<local-path>".to_owned());
            index += 2;
            continue;
        }
        if token.starts_with("--path=") {
            redacted.push("--path=<local-path>".to_owned());
            index += 1;
            continue;
        }
        if token.contains("://") || token.contains("git@") || token.contains("file:") {
            redacted.push("[REDACTED_URL]".to_owned());
        } else {
            redacted.push(token.clone());
        }
        index += 1;
    }
    redacted
}

// package_intent_parser.py `_redacted_command_text`
#[allow(dead_code)]
fn redacted_command_text(tokens: &[String]) -> String {
    crate::command_launcher_floors::shlex_join(&redact_local_source_tokens(tokens))
}

// package_intent_parser.py `_rebase_intent_paths`
fn rebase_intent_paths(
    mut intent: PackageIntent,
    from_directory: &Path,
    workspace: Option<&Path>,
) -> PackageIntent {
    let rebase = |paths: &[String]| -> Vec<String> {
        paths
            .iter()
            .map(|path| {
                let absolute = from_directory.join(path);
                match workspace {
                    Some(workspace) => {
                        match absolute
                            .canonicalize()
                            .or_else(|_| Ok(absolute.clone()))
                            .and_then(|p| {
                                p.strip_prefix(expand_resolve(workspace))
                                    .map(|r| r.to_path_buf())
                                    .map_err(|_| std::io::Error::other(""))
                            }) {
                            Ok(rel) => rel.to_string_lossy().into_owned(),
                            Err(_) => path.clone(),
                        }
                    }
                    None => path.clone(),
                }
            })
            .collect()
    };
    intent.manifest_paths = rebase(&intent.manifest_paths);
    intent.lockfile_paths = rebase(&intent.lockfile_paths);
    intent
}

fn expand_resolve(path: &Path) -> PathBuf {
    expand_user(&path.to_string_lossy())
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
}

// package_intent_parser.py `_normalized_command_tokens`
#[allow(dead_code)]
fn normalized_command_tokens(command_text: &str) -> Vec<Vec<String>> {
    normalized_command_segments(command_text, None, None, None)
        .into_iter()
        .map(|segment| segment.tokens)
        .collect()
}

// package_intent_parser.py `_combine_package_intents`
fn combine_package_intents(intents: &[PackageIntent]) -> Option<PackageIntent> {
    let meaningful: Vec<&PackageIntent> = intents
        .iter()
        .filter(|intent| !intent.command_tokens.is_empty())
        .collect();
    match meaningful.len() {
        0 => None,
        1 => Some(meaningful[0].clone()),
        _ => {
            let mut combined = meaningful[0].clone();
            combined.intent_kind = combined_intent_kind(&meaningful);
            combined.package_manager = combined_package_manager(&meaningful);
            combined.command_tokens = meaningful
                .iter()
                .flat_map(|intent| intent.command_tokens.iter().cloned())
                .collect();
            combined.redacted_command = meaningful
                .iter()
                .map(|intent| intent.redacted_command.clone())
                .collect::<Vec<_>>()
                .join(" ; ");
            combined.targets = meaningful
                .iter()
                .flat_map(|intent| intent.targets.iter().cloned())
                .collect();
            combined.manifest_paths = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.manifest_paths.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.lockfile_paths = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.lockfile_paths.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.flags = unique_joined_tokens(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.flags.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.notes = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.notes.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.local_executions = meaningful
                .iter()
                .flat_map(|intent| intent.local_executions.iter().cloned())
                .collect();
            combined.execution_context_hashes = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.execution_context_hashes.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.execution_context_cwds = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.execution_context_cwds.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.execution_context_reason_codes = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.execution_context_reason_codes.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            Some(combined)
        }
    }
}

// package_intent_parser.py `_combined_intent_kind`
fn combined_intent_kind(intents: &[&PackageIntent]) -> IntentKind {
    let kinds: HashSet<&str> = intents.iter().map(|intent| intent.intent_kind).collect();
    if kinds.len() == 1 {
        intents[0].intent_kind
    } else if kinds.contains("install") {
        "install"
    } else if kinds.contains("execute") {
        "execute"
    } else {
        "sync"
    }
}

// package_intent_parser.py `_combined_package_manager`
fn combined_package_manager(intents: &[&PackageIntent]) -> String {
    let managers: HashSet<&str> = intents
        .iter()
        .map(|intent| intent.package_manager.as_str())
        .collect();
    if managers.len() == 1 {
        intents[0].package_manager.clone()
    } else {
        "multi".to_owned()
    }
}

// package_intent_parser.py `_unique_joined_strings`
fn unique_joined_strings(values: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value.clone());
        }
    }
    out
}

// package_intent_parser.py `_unique_joined_tokens`
fn unique_joined_tokens(values: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value.clone());
        }
    }
    out
}

// package_intent_parser.py `_stat_identity`
#[cfg(unix)]
fn stat_identity(result: &std::fs::Metadata) -> String {
    [
        result.dev(),
        result.ino(),
        result.mode() as u64 & 0o7777,
        result.size(),
        result.mtime_nsec() as u64,
        result.ctime_nsec() as u64,
    ]
    .iter()
    .map(|value| value.to_string())
    .collect::<Vec<_>>()
    .join(":")
}

#[cfg(windows)]
fn stat_identity(result: &std::fs::Metadata) -> String {
    // Stable std surface only: `size`/`last_write_time` live on `MetadataExt`;
    // `file_attributes` mirrors st_mode bits used downstream. We keep the
    // tuple shape identical so the identity string remains a positional
    // contract — digests diverge across OSes either way, which Python already
    // tolerates (stat fields differ across platforms).
    [
        0u64, // no stable volume-serial equivalent
        0u64, // no stable file-index equivalent
        result.file_attributes() as u64 & 0o7777,
        result.len(),
        result.last_write_time(),
        result.last_write_time(),
    ]
    .iter()
    .map(|value| value.to_string())
    .collect::<Vec<_>>()
    .join(":")
}

// package_intent_parser.py `_path_identity`
fn path_identity(path: &Path) -> Option<String> {
    std::fs::metadata(path)
        .ok()
        .map(|metadata| stat_identity(&metadata))
}

// package_intent_parser.py `_execution_display_path`
fn execution_display_path(workspace: &Path, path: &Path) -> String {
    match path.strip_prefix(expand_resolve(workspace)) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

// package_intent_parser.py `_opaque_unresolved_context_binding`
fn opaque_unresolved_context_binding(
    raw_segment: &[String],
    path_source: &str,
    cwd_source: &str,
) -> Option<String> {
    if !(path_source.contains("unresolved")
        || path_source == "inherited_unset"
        || cwd_source.contains("unresolved")
        || cwd_source.contains("failed"))
    {
        return None;
    }
    let sensitive_context = raw_segment.join("\0");
    let mac = hmac_sha256(&EXECUTION_CONTEXT_HMAC_KEY, sensitive_context.as_bytes());
    Some(hex::encode(mac))
}

// package_intent_parser.py `_typescript_launch_inputs`
fn typescript_launch_inputs(
    tokens: &[String],
    evidence: &LocalPackageExecutionEvidence,
) -> TypeScriptLaunchInputs {
    let manager = &evidence.manager;
    let executable = &evidence.local_executable;
    let available_manifests: Vec<&PackageExecutionFileEvidence> = evidence
        .manifests
        .iter()
        .filter(|item| {
            item.status == "available"
                && item.resolved_path.is_some()
                && item.content_hash.is_some()
        })
        .collect();
    let available_lockfiles: Vec<&PackageExecutionFileEvidence> = evidence
        .lockfiles
        .iter()
        .filter(|item| {
            item.status == "available"
                && item.resolved_path.is_some()
                && item.content_hash.is_some()
        })
        .collect();
    TypeScriptLaunchInputs {
        tokens: tokens.to_vec(),
        manager_name: evidence.manager_name.clone(),
        local_only_requested: evidence.local_only_requested,
        package_name: evidence.package_name.clone(),
        executable_name: evidence.executable_name.clone(),
        declared_version: evidence.declared_version.clone(),
        manager_path: if manager.as_ref().map(|m| m.status) == Some("available") {
            manager.as_ref().and_then(|m| m.resolved_path.clone())
        } else {
            None
        },
        manager_hash: if manager.as_ref().map(|m| m.status) == Some("available") {
            manager.as_ref().and_then(|m| m.content_hash.clone())
        } else {
            None
        },
        executable_path: if executable.as_ref().map(|e| e.status) == Some("available") {
            executable.as_ref().and_then(|e| e.resolved_path.clone())
        } else {
            None
        },
        executable_hash: if executable.as_ref().map(|e| e.status) == Some("available") {
            executable.as_ref().and_then(|e| e.content_hash.clone())
        } else {
            None
        },
        manifest_paths: available_manifests
            .iter()
            .filter_map(|item| item.resolved_path.clone())
            .collect(),
        manifest_hashes: available_manifests
            .iter()
            .filter_map(|item| item.content_hash.clone())
            .collect(),
        lockfile_paths: available_lockfiles
            .iter()
            .filter_map(|item| item.resolved_path.clone())
            .collect(),
        lockfile_hashes: available_lockfiles
            .iter()
            .filter_map(|item| item.content_hash.clone())
            .collect(),
    }
}

// package_intent_parser.py `_local_execution_disables_install`
fn local_execution_disables_install(tokens: &[String]) -> bool {
    let name = if tokens.is_empty() {
        String::new()
    } else {
        command_name(&tokens[0])
    };
    let local_only_flags = local_execution_flags(&name);
    for token in &tokens[1..] {
        if !token.starts_with('-') {
            return false;
        }
        if !local_only_flags.contains(&token.as_str()) {
            return false;
        }
        if matches!(token.as_str(), "--no" | "--no-install") {
            return true;
        }
    }
    false
}

// package_intent_parser.py `_local_executable_name`
fn local_executable_name(
    tokens: &[String],
    package_name: Option<&str>,
    workspace: Option<&Path>,
    effective_cwd: &Path,
) -> Option<String> {
    let name = if tokens.is_empty() {
        String::new()
    } else {
        command_name(&tokens[0])
    };
    let allowed_flags = local_execution_flags(&name);
    let mut index = 1usize;
    while index < tokens.len() && tokens[index].starts_with('-') {
        if name == "npx" && tokens[index] == "--package" && index + 1 < tokens.len() {
            index += 2;
            continue;
        }
        if name == "npx" && tokens[index].starts_with("--package=") {
            index += 1;
            continue;
        }
        if !allowed_flags.contains(&tokens[index].as_str()) {
            return None;
        }
        index += 1;
    }
    if index >= tokens.len() {
        return None;
    }
    let executable = &tokens[index];
    let executable_re: &Regex = {
        static RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").expect("exec name"));
        &RE
    };
    if executable_re.is_match(executable) {
        return Some(executable.clone());
    }
    let package_name = package_name?;
    installed_package_bin_name(workspace, effective_cwd, package_name)
}

// package_intent_parser.py `_workspace_js_dependency_version`
fn workspace_js_dependency_version(
    workspace: &Path,
    effective_cwd: &Path,
    package_name: &str,
) -> Option<String> {
    let dependency_name = local_executable_package_alias(package_name);
    for root in node_resolution_roots(workspace, effective_cwd) {
        let payload: Value = match std::fs::read_to_string(root.join("package.json"))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
        {
            Some(payload) => payload,
            None => continue,
        };
        let Some(map) = payload.as_object() else {
            continue;
        };
        for key in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ] {
            if let Some(dependencies) = map.get(key).and_then(Value::as_object) {
                if let Some(version) = dependencies.get(dependency_name).and_then(Value::as_str) {
                    let version = version.trim();
                    return if version.is_empty() {
                        None
                    } else {
                        Some(version.to_owned())
                    };
                }
            }
        }
    }
    None
}

// package_intent_parser.py `_local_package_execution_evidence`
#[allow(clippy::too_many_arguments)]
fn local_package_execution_evidence(
    command: &str,
    tokens: &[String],
    workspace: Option<&Path>,
    effective_path: Option<&str>,
    path_source: &str,
    effective_cwd: Option<&Path>,
    cwd_source: &str,
    execution_context_hash: &str,
    manifest_paths: &[String],
    lockfile_paths: &[String],
) -> LocalPackageExecutionEvidence {
    let package_spec = exec_package_spec(tokens);
    let package_name = package_spec
        .as_deref()
        .and_then(|spec| js_target(spec).package_name);
    let Some(effective_cwd_path) = effective_cwd else {
        return LocalPackageExecutionEvidence {
            manager_name: command.to_owned(),
            path_source: path_source.to_owned(),
            effective_cwd: "<unresolved>".to_owned(),
            cwd_source: cwd_source.to_owned(),
            manager_is_guard_shim: false,
            local_only_requested: local_execution_disables_install(tokens),
            context_hash: execution_context_hash.to_owned(),
            package_name,
            executable_name: None,
            declared_version: None,
            manager: None,
            local_executable: None,
            manifests: Vec::new(),
            lockfiles: Vec::new(),
            typescript_launch: None,
        };
    };
    let executable_name = local_executable_name(
        tokens,
        package_name.as_deref(),
        workspace,
        effective_cwd_path,
    );
    let manager_path = effective_path.and_then(|path| which_on_path(command, path));
    let manager = manager_path
        .as_ref()
        .map(|path| execution_file_evidence(Path::new(path), path));
    let manager_is_guard_shim = manager_evidence_is_guard_shim(command, manager.as_ref());
    let local_executable = match (workspace, executable_name.as_deref()) {
        (Some(workspace), Some(name)) => Some(local_executable_evidence(
            workspace,
            effective_cwd_path,
            name,
        )),
        _ => None,
    };
    let declared_version = match (workspace, package_name.as_deref()) {
        (Some(workspace), Some(name)) => {
            workspace_js_dependency_version(workspace, effective_cwd_path, name)
        }
        _ => None,
    };
    LocalPackageExecutionEvidence {
        manager_name: command.to_owned(),
        path_source: path_source.to_owned(),
        effective_cwd: effective_cwd_path.to_string_lossy().into_owned(),
        cwd_source: cwd_source.to_owned(),
        manager_is_guard_shim,
        local_only_requested: local_execution_disables_install(tokens),
        context_hash: execution_context_hash.to_owned(),
        package_name,
        executable_name,
        declared_version,
        manager,
        local_executable,
        manifests: local_context_file_evidence(
            workspace,
            effective_cwd_path,
            manifest_paths,
            &["package.json".to_owned()],
        ),
        lockfiles: local_context_file_evidence(
            workspace,
            effective_cwd_path,
            lockfile_paths,
            &JS_LOCKFILE_NAMES
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        ),
        typescript_launch: None,
    }
}

/// `shutil.which(command, path=...)` — search `command` in a `:`-separated path.
fn which_on_path(command: &str, path: &str) -> Option<String> {
    if command.contains('/') {
        let candidate = Path::new(command);
        if is_executable(candidate) {
            return Some(command.to_owned());
        }
        return None;
    }
    for entry in path.split(':') {
        if entry.is_empty() {
            continue;
        }
        let candidate = Path::new(entry).join(command);
        if is_executable(&candidate) {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

// package_intent_parser.py `_manager_evidence_is_guard_shim`
fn manager_evidence_is_guard_shim(
    command: &str,
    manager: Option<&PackageExecutionFileEvidence>,
) -> bool {
    let Some(manager) = manager else {
        return false;
    };
    let Some(resolved_path) = &manager.resolved_path else {
        return false;
    };
    let home = match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        Some(home) => PathBuf::from(home),
        None => return false,
    };
    let expected_shim = home
        .join(".hol-guard")
        .join("package-shims")
        .join("bin")
        .join(command)
        .canonicalize();
    match expected_shim {
        Ok(expected) => Path::new(resolved_path) == expected,
        Err(_) => false,
    }
}

// package_intent_parser.py `_local_executable_evidence`
fn local_executable_evidence(
    workspace: &Path,
    effective_cwd: &Path,
    executable_name: &str,
) -> PackageExecutionFileEvidence {
    let suffixes: &[&str] = if cfg!(windows) {
        &["", ".cmd", ".ps1"]
    } else {
        &[""]
    };
    for root in node_resolution_roots(workspace, effective_cwd) {
        let executable_dir = root.join("node_modules").join(".bin");
        for suffix in suffixes {
            let candidate = executable_dir.join(format!("{executable_name}{suffix}"));
            if candidate.symlink_metadata().is_ok() {
                return execution_file_evidence(
                    &candidate,
                    &execution_display_path(workspace, &candidate),
                );
            }
        }
    }
    let expected = effective_cwd
        .join("node_modules")
        .join(".bin")
        .join(executable_name);
    PackageExecutionFileEvidence {
        path: execution_display_path(workspace, &expected),
        resolved_path: None,
        status: "missing",
        file_identity: None,
        content_hash: None,
    }
}

// package_intent_parser.py `_installed_package_bin_name`
fn installed_package_bin_name(
    workspace: Option<&Path>,
    effective_cwd: &Path,
    package_name: &str,
) -> Option<String> {
    let workspace = workspace?;
    for root in node_resolution_roots(workspace, effective_cwd) {
        let manifest = package_name
            .split('/')
            .fold(root.join("node_modules"), |acc, part| acc.join(part))
            .join("package.json");
        let payload: Value = match std::fs::read_to_string(&manifest)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
        {
            Some(payload) => payload,
            None => continue,
        };
        let Some(map) = payload.as_object() else {
            continue;
        };
        let bin_value = map.get("bin");
        let fallback = package_name.rsplit('/').next().unwrap_or(package_name);
        if let Some(bin_str) = bin_value.and_then(Value::as_str) {
            if !bin_str.trim().is_empty() {
                return Some(fallback.to_owned());
            }
        }
        if let Some(bin_map) = bin_value.and_then(Value::as_object) {
            let names: Vec<String> = bin_map
                .iter()
                .filter(|(_, value)| {
                    value
                        .as_str()
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false)
                })
                .map(|(name, _)| name.clone())
                .collect();
            if names.iter().any(|name| name == fallback) {
                return Some(fallback.to_owned());
            }
            if names.len() == 1 {
                return Some(names[0].clone());
            }
        }
    }
    let fallback = package_name.rsplit('/').next().unwrap_or(package_name);
    let re: &Regex = {
        static RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").expect("bin name"));
        &RE
    };
    if re.is_match(fallback) {
        Some(fallback.to_owned())
    } else {
        None
    }
}

// package_intent_parser.py `_node_resolution_roots`
fn node_resolution_roots(workspace: &Path, effective_cwd: &Path) -> Vec<PathBuf> {
    let workspace_root = expand_resolve(workspace);
    let mut current = expand_resolve(effective_cwd);
    let boundary = if current == workspace_root
        || current
            .ancestors()
            .any(|ancestor| ancestor == workspace_root)
    {
        workspace_root.clone()
    } else {
        PathBuf::from(
            current
                .components()
                .next()
                .map(|c| c.as_os_str())
                .unwrap_or_default(),
        )
    };
    let mut roots: Vec<PathBuf> = Vec::new();
    loop {
        roots.push(current.clone());
        if current == boundary {
            break;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => break,
        }
    }
    roots
}

// package_intent_parser.py `_local_context_file_evidence`
fn local_context_file_evidence(
    workspace: Option<&Path>,
    effective_cwd: &Path,
    declared_paths: &[String],
    candidate_names: &[String],
) -> Vec<PackageExecutionFileEvidence> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };
    let mut candidates: Vec<(PathBuf, String)> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for relative_path in declared_paths {
        let candidate = effective_cwd.join(relative_path);
        let normalized = absolute(&candidate);
        if seen.insert(normalized) {
            candidates.push((
                candidate.clone(),
                execution_display_path(workspace, &candidate),
            ));
        }
    }
    for root in node_resolution_roots(workspace, effective_cwd) {
        for name in candidate_names {
            let candidate = root.join(name);
            let normalized = absolute(&candidate);
            if seen.contains(&normalized) || candidate.symlink_metadata().is_err() {
                continue;
            }
            seen.insert(normalized);
            candidates.push((
                candidate.clone(),
                execution_display_path(workspace, &candidate),
            ));
        }
    }
    candidates
        .iter()
        .map(|(candidate, display)| execution_file_evidence(candidate, display))
        .collect()
}

fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

// package_intent_parser.py `_execution_file_evidence`
fn execution_file_evidence(path: &Path, display_path: &str) -> PackageExecutionFileEvidence {
    let resolved = match path.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => {
            return PackageExecutionFileEvidence {
                path: display_path.to_owned(),
                resolved_path: None,
                status: "missing",
                file_identity: None,
                content_hash: None,
            };
        }
    };
    // Python opens the resolved path with O_RDONLY|O_CLOEXEC|O_NOFOLLOW and
    // fstats+reads. Rust: open then metadata + read, treating symlink targets
    // as resolved already. `canonicalize` resolves symlinks so O_NOFOLLOW is
    // implicitly satisfied.
    let file = match std::fs::File::open(&resolved) {
        Ok(file) => file,
        Err(_) => {
            return PackageExecutionFileEvidence {
                path: display_path.to_owned(),
                resolved_path: Some(resolved.to_string_lossy().into_owned()),
                status: "unreadable",
                file_identity: path_identity(&resolved),
                content_hash: None,
            };
        }
    };
    let before = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => {
            return PackageExecutionFileEvidence {
                path: display_path.to_owned(),
                resolved_path: Some(resolved.to_string_lossy().into_owned()),
                status: "unreadable",
                file_identity: None,
                content_hash: None,
            };
        }
    };
    if !before.is_file() {
        return PackageExecutionFileEvidence {
            path: display_path.to_owned(),
            resolved_path: Some(resolved.to_string_lossy().into_owned()),
            status: "not_regular",
            file_identity: Some(stat_identity(&before)),
            content_hash: None,
        };
    }
    let mut file = file;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => digest.update(&buffer[..n]),
            Err(_) => {
                return PackageExecutionFileEvidence {
                    path: display_path.to_owned(),
                    resolved_path: Some(resolved.to_string_lossy().into_owned()),
                    status: "unreadable",
                    file_identity: None,
                    content_hash: None,
                };
            }
        }
    }
    let after = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => {
            return PackageExecutionFileEvidence {
                path: display_path.to_owned(),
                resolved_path: Some(resolved.to_string_lossy().into_owned()),
                status: "unreadable",
                file_identity: None,
                content_hash: None,
            };
        }
    };
    let identity_before = stat_identity(&before);
    let identity_after = stat_identity(&after);
    if identity_before != identity_after {
        return PackageExecutionFileEvidence {
            path: display_path.to_owned(),
            resolved_path: Some(resolved.to_string_lossy().into_owned()),
            status: "unstable",
            file_identity: Some(identity_after),
            content_hash: None,
        };
    }
    PackageExecutionFileEvidence {
        path: display_path.to_owned(),
        resolved_path: Some(resolved.to_string_lossy().into_owned()),
        status: "available",
        file_identity: Some(identity_after),
        content_hash: Some(format!("sha256:{}", hex::encode(digest.finalize()))),
    }
}

// package_intent_parser.py `_split_shell_tokens`
// `shlex` with `punctuation_chars=";&|"`, `whitespace_split=True`, `commenters=""`.
#[allow(dead_code)]
fn split_shell_tokens_local(command_text: &str) -> Vec<String> {
    split_shell_tokens(command_text).unwrap_or_default()
}

/// `os.defpath` equivalent — POSIX standard PATH fallback.
fn default_path() -> String {
    "/bin:/usr/bin".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_labels() {
        assert_eq!(control_context_label(Some("&&")), "and");
        assert_eq!(control_context_label(Some("|&")), "pipe-stderr");
        assert_eq!(control_context_label(None), "end");
    }

    // package_intent_parser.py `_redact_local_source_tokens`
    #[test]
    fn redact_local_source_tokens_hides_cargo_local_path() {
        let redacted = redacted_segment(&[
            "cargo".to_owned(),
            "add".to_owned(),
            "demo".to_owned(),
            "--path".to_owned(),
            "crates/demo".to_owned(),
        ]);
        assert!(redacted.contains(&"--path".to_owned()));
        assert!(redacted.contains(&"<local-path>".to_owned()));
        assert!(!redacted.iter().any(|token| token == "crates/demo"));

        let flag_form = redacted_segment(&[
            "cargo".to_owned(),
            "add".to_owned(),
            "demo".to_owned(),
            "--path=crates/demo".to_owned(),
        ]);
        assert!(flag_form.contains(&"--path=<local-path>".to_owned()));
        assert!(!flag_form.iter().any(|token| token.contains("crates/demo")));
    }
}
