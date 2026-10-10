//! Complete-or-fail lockfile parsing — port of
//! `runtime/lockfile_parse_result.py` (`parse_lockfile_text`,
//! `incomplete_lockfile_result`) and `runtime/lockfile_evaluation_support.py`
//! (`collect_lockfile_parse_results`), plus `_package_lock_entries`.
//!
//! A lockfile either parses completely or yields an `incomplete` result with an
//! `error_reason`; partial entries are never returned.

use std::time::{Duration, Instant};

use super::contracts::{
    LOCKFILE_PARSE_BUDGET_PER_MIB_SECONDS, LOCKFILE_PARSE_BUDGET_SECONDS,
    LOCKFILE_PARSE_MAX_BUDGET_SECONDS,
};
use super::lockfile_validate::validate_structure;
use super::*;
use crate::local_supply_chain::stable_digest_hex;
use crate::package_manifest_diff::try_dependency_map_for_path;

pub const LOCKFILE_PARSER_VERSION: &str = "complete-v1";
const LOCKFILE_MAX_BYTES: usize = 8 * 1024 * 1024;
pub(super) const LOCKFILE_MAX_ENTRIES: usize = 100_000;
pub(super) const LOCKFILE_MAX_NODES: usize = 250_000;
pub(super) const LOCKFILE_MAX_DEPTH: usize = 128;

pub(super) type Reason = String;

pub(super) fn reason(text: &str) -> Reason {
    text.to_owned()
}

/// `_lockfile_format` — the lowercase basename mapped to its format label.
pub(super) fn lockfile_format_label(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    match name.as_str() {
        "package-lock.json" => "npm-package-lock",
        "pnpm-lock.yaml" => "pnpm-lock",
        "yarn.lock" => "yarn-lock",
        "bun.lock" => "bun-lock",
        "cargo.lock" => "cargo-lock",
        "composer.lock" => "composer-lock",
        "gemfile.lock" => "bundler-lock",
        "poetry.lock" => "poetry-lock",
        "uv.lock" => "uv-lock",
        "pipfile.lock" => "pipenv-lock",
        _ => "unknown",
    }
}

/// `incomplete_lockfile_result` (lockfile_parse_result.py:90).
pub fn incomplete_lockfile_result(
    path: &str,
    source: &[u8],
    error_reason: &str,
    budget_ms: f64,
    elapsed_ms: f64,
) -> LockfileParseResult {
    LockfileParseResult {
        entries: Vec::new(),
        complete: false,
        format: lockfile_format_label(path).to_owned(),
        source_hash: stable_digest_hex(source),
        elapsed_ms,
        budget_ms,
        warnings: Vec::new(),
        error_reason: Some(error_reason.to_owned()),
        parser_version: LOCKFILE_PARSER_VERSION.to_owned(),
    }
}

/// `_lockfile_parse_budget_seconds` (:2372).
pub fn lockfile_parse_budget_for_bytes(byte_count: usize) -> f64 {
    let source_mib = byte_count as f64 / (1024.0 * 1024.0);
    LOCKFILE_PARSE_MAX_BUDGET_SECONDS
        .min(LOCKFILE_PARSE_BUDGET_SECONDS + LOCKFILE_PARSE_BUDGET_PER_MIB_SECONDS * source_mib)
}

/// `parse_lockfile_text` through `_parse_lockfile_text_result` (:2346).
pub fn parse_lockfile_text(path: &str, source: &[u8]) -> LockfileParseResult {
    parse_lockfile_with_budget(path, source, lockfile_parse_budget_for_bytes(source.len()))
}

/// `parse_lockfile_with_budget` (lockfile_evaluation_support.py:66).
pub fn parse_lockfile_with_budget(
    path: &str,
    source: &[u8],
    budget_seconds: f64,
) -> LockfileParseResult {
    let budget_ms = budget_seconds * 1000.0;
    let started = Instant::now();
    let deadline = started + Duration::from_secs_f64(budget_seconds);
    match parse_complete(path, source, deadline) {
        Ok(entries) => LockfileParseResult {
            entries,
            complete: true,
            format: lockfile_format_label(path).to_owned(),
            source_hash: stable_digest_hex(source),
            elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
            budget_ms,
            warnings: Vec::new(),
            error_reason: None,
            parser_version: LOCKFILE_PARSER_VERSION.to_owned(),
        },
        Err(error_reason) => incomplete_lockfile_result(
            path,
            source,
            &error_reason,
            budget_ms,
            started.elapsed().as_secs_f64() * 1000.0,
        ),
    }
}

pub(super) fn within(deadline: Instant) -> Result<(), Reason> {
    if Instant::now() > deadline {
        return Err(reason("deadline_exceeded"));
    }
    Ok(())
}

fn parse_complete(
    path: &str,
    source: &[u8],
    deadline: Instant,
) -> Result<Vec<LockfileDependencyEntry>, Reason> {
    within(deadline)?;
    if source.len() > LOCKFILE_MAX_BYTES {
        return Err(reason("byte_limit_exceeded"));
    }
    let text = std::str::from_utf8(source).map_err(|_| reason("decode_error"))?;
    let lower_name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    if !matches!(
        lower_name.as_str(),
        "package-lock.json"
            | "composer.lock"
            | "pipfile.lock"
            | "bun.lock"
            | "cargo.lock"
            | "poetry.lock"
            | "uv.lock"
            | "gemfile.lock"
            | "pnpm-lock.yaml"
            | "yarn.lock"
    ) {
        return Err(reason("unsupported_format"));
    }
    validate_structure(&lower_name, text, deadline)?;
    let entries: Vec<LockfileDependencyEntry> = if lower_name == "package-lock.json" {
        package_lock_entries(text, Some(deadline))?
            .into_iter()
            .map(
                |(dependency_path, package_name, version, direct)| LockfileDependencyEntry {
                    dependency_path,
                    package_name,
                    version,
                    direct,
                },
            )
            .collect()
    } else {
        let remaining_ms = deadline
            .saturating_duration_since(Instant::now())
            .as_millis() as u64;
        try_dependency_map_for_path(path, text, remaining_ms)
            .map_err(reason)?
            .into_iter()
            .map(|(package_name, version)| LockfileDependencyEntry {
                dependency_path: package_name.clone(),
                package_name,
                version,
                direct: false,
            })
            .collect()
    };
    within(deadline)?;
    if entries.len() > LOCKFILE_MAX_ENTRIES {
        return Err(reason("entry_limit_exceeded"));
    }
    Ok(entries)
}

/// `_package_lock_entries` (:3850) + `_walk_package_lock_entries` (:3880).
pub(super) fn package_lock_entries(
    text: &str,
    deadline: Option<Instant>,
) -> Result<Vec<(String, String, String, bool)>, Reason> {
    let source = if text.is_empty() { "{}" } else { text };
    let payload: Value = serde_json::from_str(source).map_err(|_| reason("syntax_error"))?;
    let mut entries = Vec::new();
    if let Some(Value::Object(packages)) = payload.get("packages") {
        for (package_path, value) in packages {
            if let Some(limit) = deadline {
                within(limit)?;
            }
            let Some(dependency_path) = package_path.strip_prefix("node_modules/") else {
                continue;
            };
            let Some(version) = value.get("version").and_then(Value::as_str) else {
                continue;
            };
            let package_name = optional_string(value.get("name")).unwrap_or_else(|| {
                dependency_path
                    .rsplit("node_modules/")
                    .next()
                    .unwrap_or(dependency_path)
                    .to_owned()
            });
            entries.push((
                dependency_path.to_owned(),
                package_name,
                version.to_owned(),
                !dependency_path.contains("node_modules/"),
            ));
        }
        return Ok(entries);
    }
    if let Some(Value::Object(legacy)) = payload.get("dependencies") {
        walk_legacy_entries(legacy, &mut entries, None, deadline)?;
    }
    Ok(entries)
}

fn walk_legacy_entries(
    payload: &Map<String, Value>,
    entries: &mut Vec<(String, String, String, bool)>,
    prefix: Option<&str>,
    deadline: Option<Instant>,
) -> Result<(), Reason> {
    for (package_name, value) in payload {
        if let Some(limit) = deadline {
            within(limit)?;
        }
        let Value::Object(value) = value else {
            continue;
        };
        let dependency_path = match prefix {
            None => package_name.clone(),
            Some(parent) => format!("{parent}/node_modules/{package_name}"),
        };
        if let Some(version) = value.get("version").and_then(Value::as_str) {
            entries.push((
                dependency_path.clone(),
                optional_string(value.get("name")).unwrap_or_else(|| package_name.clone()),
                version.to_owned(),
                prefix.is_none(),
            ));
        }
        if let Some(Value::Object(nested)) = value.get("dependencies") {
            walk_legacy_entries(nested, entries, Some(&dependency_path), deadline)?;
        }
    }
    Ok(())
}

/// Python `Path.resolve()` (non-strict): symlinks resolved while components
/// exist; remaining components are applied lexically (including `..`).
fn resolve_lenient(path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut current = PathBuf::new();
    let mut missing = false;
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                current.pop();
            }
            Component::Normal(name) => {
                current.push(name);
                if !missing {
                    match std::fs::canonicalize(&current) {
                        Ok(resolved) => current = resolved,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            missing = true;
                        }
                        Err(_) => return None,
                    }
                }
            }
        }
    }
    Some(current)
}

fn resolve_within(workspace: &Path, relative: &str) -> Option<PathBuf> {
    if relative.is_empty() || Path::new(relative).is_absolute() {
        return None;
    }
    let root = std::fs::canonicalize(workspace).ok()?;
    let resolved = resolve_lenient(&root.join(relative))?;
    resolved.starts_with(&root).then_some(resolved)
}

fn relative_path_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// `collect_lockfile_parse_results` (lockfile_evaluation_support.py:24).
pub fn collect_lockfile_parse_results(
    workspace_dir: Option<&Path>,
    lockfile_paths: Option<&Value>,
    budget_ms: f64,
    parse_text_result: &dyn Fn(&str, &[u8]) -> LockfileParseResult,
) -> Vec<LockfileParseResult> {
    let (Some(workspace), Some(Value::Array(paths))) = (workspace_dir, lockfile_paths) else {
        return Vec::new();
    };
    let mut results = Vec::new();
    for value in paths {
        let relative = relative_path_text(value);
        let Some(resolved) = resolve_within(workspace, &relative) else {
            results.push(incomplete_lockfile_result(
                &relative,
                b"",
                "traversal_error",
                budget_ms,
                0.0,
            ));
            continue;
        };
        let name = resolved
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !resolved.exists() || name.eq_ignore_ascii_case("bun.lockb") {
            continue;
        }
        match resolved
            .is_file()
            .then(|| std::fs::read(&resolved).ok())
            .flatten()
        {
            Some(bytes) => results.push(parse_text_result(&name, &bytes)),
            None => results.push(incomplete_lockfile_result(
                &name,
                b"",
                "read_error",
                budget_ms,
                0.0,
            )),
        }
    }
    results
}
