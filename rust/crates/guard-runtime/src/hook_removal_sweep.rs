//! `hook-removal-sweep --stdin`: find and strip Guard-owned hook handlers
//! from harness config files (`guard/hook_removal_sweep.py` frames the
//! request and lists the candidate paths).
//!
//! The per-harness adapters remove what Guard recorded at install time. This
//! sweep is the backstop for hooks the store no longer knows about: it scans
//! each candidate JSON or TOML file for hook handlers whose command carries a
//! Guard signature and removes only those handlers.
//!
//! - JSON is rewritten as `json.dumps(payload, indent=2)` renders it.
//! - TOML is edited in place, so comments and every unrelated line stay as
//!   they were. The edit is kept only when the re-parsed file equals the
//!   pruned payload; anything else is refused as `rewrite_not_lossless`.
//! - A symlinked config is reported, never edited through the link.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{json, Value};
use toml_edit::DocumentMut;

use crate::encrypted_secret_store::random_bytes;
use crate::hook_removal_prune::{
    prune_document, prune_guard_hooks, same, table_value, write_indented,
};
use crate::pyjson::{parse, parse_mapping_lone_surrogates, PyVal};

const SCHEMA: &str = "hook-removal-sweep.v1";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
const MAX_CANDIDATES: usize = 512;
const MAX_CONFIG_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    op: String,
    #[serde(default)]
    candidates: Vec<String>,
    #[serde(default)]
    roots: Vec<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    dry_run: bool,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == "hook-removal-sweep"
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "hook_removal_sweep_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("hook_removal_sweep_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    answer(&request).map(|value| value.to_string().into_bytes())
}

fn invalid() -> String {
    "hook_removal_sweep_request_invalid".to_owned()
}

fn absolute(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(invalid())
    }
}

fn answer(request: &Request) -> Result<Value, String> {
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    match request.op.as_str() {
        "sweep-file" if request.candidates.is_empty() && request.roots.is_empty() => {
            let path = absolute(request.path.as_deref().ok_or_else(invalid)?)?;
            let text = request.path.clone().unwrap_or_default();
            Ok(json!({ "file": sweep_config_file(&text, &path, request.dry_run).to_json() }))
        }
        "files" | "sweep" if request.path.is_none() => {
            if request.candidates.len() > MAX_CANDIDATES || request.roots.len() > 2 {
                return Err(invalid());
            }
            let candidates = request
                .candidates
                .iter()
                .map(|text| absolute(text).map(|path| (text.clone(), path)))
                .collect::<Result<Vec<_>, _>>()?;
            let roots = request
                .roots
                .iter()
                .map(|text| absolute(text.as_str()))
                .collect::<Result<Vec<_>, _>>()?;
            let (files, links) = split_candidates(candidates, &roots);
            if request.op == "files" {
                let names: Vec<&str> = files.iter().map(|(text, _)| text.as_str()).collect();
                return Ok(json!({ "files": names }));
            }
            let mut results: Vec<Value> = files
                .iter()
                .map(|(text, path)| sweep_config_file(text, path, request.dry_run).to_json())
                .collect();
            results.extend(
                links
                    .iter()
                    .filter_map(|(text, path)| inspect_symlinked(text, path, request.dry_run))
                    .map(|result| result.to_json()),
            );
            Ok(json!({ "files": results }))
        }
        _ => Err(invalid()),
    }
}

/// Candidate paths, each with the text the request spelled it as.
type Candidates = Vec<(String, PathBuf)>;

/// Existing candidates with a sweepable suffix, split into regular files
/// inside a root and symlinks, each kept once in request order.
fn split_candidates(candidates: Candidates, roots: &[PathBuf]) -> (Candidates, Candidates) {
    let roots: Vec<PathBuf> = roots
        .iter()
        .filter_map(|root| fs::canonicalize(root).ok())
        .collect();
    let mut files: Candidates = Vec::new();
    let mut links: Candidates = Vec::new();
    for (text, path) in candidates {
        let sweepable = matches!(
            path.extension().and_then(|suffix| suffix.to_str()),
            Some("json" | "toml")
        );
        let seen = files.iter().chain(&links).any(|(_, known)| *known == path);
        if !sweepable || seen {
            continue;
        }
        if fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            links.push((text, path));
        } else if fs::metadata(&path).is_ok_and(|metadata| metadata.is_file())
            && inside(&path, &roots)
        {
            files.push((text, path));
        }
    }
    (files, links)
}

fn inside(path: &Path, roots: &[PathBuf]) -> bool {
    fs::canonicalize(path).is_ok_and(|resolved| roots.iter().any(|root| resolved.starts_with(root)))
}

struct SweepResult<'a> {
    path: &'a str,
    removed: usize,
    wrote: bool,
    error: Option<&'static str>,
    events: Vec<String>,
}

impl<'a> SweepResult<'a> {
    fn failed(path: &'a str, error: &'static str) -> Self {
        Self {
            path,
            removed: 0,
            wrote: false,
            error: Some(error),
            events: Vec::new(),
        }
    }

    fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "removed": self.removed,
            "wrote": self.wrote,
            "error": self.error,
            "event_names": self.events,
        })
    }
}

enum Config {
    Json(PyVal, String),
    Toml(DocumentMut),
}

impl Config {
    fn payload(&self) -> PyVal {
        match self {
            Config::Json(payload, _) => payload.clone(),
            Config::Toml(document) => table_value(document.as_table()),
        }
    }
}

fn load(path: &Path) -> Result<Config, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "unreadable")?;
    if !metadata.is_file() {
        return Err("not_regular_file");
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err("too_large");
    }
    let raw = fs::read(path).map_err(|_| "unreadable")?;
    let text = String::from_utf8(raw).map_err(|_| "unparseable")?;
    if is_toml(path) {
        return text
            .parse::<DocumentMut>()
            .map(Config::Toml)
            .map_err(|_| "unparseable");
    }
    // CPython also decodes a lone surrogate escape in a key; the mapping
    // parser reads such a file so the sweep can find the hooks, and
    // `render` then refuses to write it back.
    let parsed = parse(&text).or_else(|_| {
        parse_mapping_lone_surrogates(&text)
            .ok()
            .filter(|parsed| parsed.mapped)
            .map(|parsed| parsed.value)
            .ok_or("unparseable")
    });
    match parsed {
        Ok(payload @ PyVal::Dict(_)) => Ok(Config::Json(payload, text)),
        Ok(_) => Err("unexpected_shape"),
        Err(_) => Err("unparseable"),
    }
}

fn is_toml(path: &Path) -> bool {
    path.extension().and_then(|suffix| suffix.to_str()) == Some("toml")
}

/// Distinct, non-empty event names in sorted order.
fn event_names(removed: &[String]) -> Vec<String> {
    let mut names: Vec<String> = removed
        .iter()
        .filter(|name| !name.is_empty())
        .cloned()
        .collect();
    names.sort();
    names.dedup();
    names
}

fn sweep_config_file<'a>(text: &'a str, path: &Path, dry_run: bool) -> SweepResult<'a> {
    let config = match load(path) {
        Ok(config) => config,
        Err(error) => return SweepResult::failed(text, error),
    };
    let mut result = SweepResult {
        path: text,
        removed: 0,
        wrote: false,
        error: None,
        events: Vec::new(),
    };
    let Some((pruned, removed)) = prune_guard_hooks(&config.payload()) else {
        return result;
    };
    result.events = event_names(&removed);
    if dry_run {
        result.removed = removed.len();
        return result;
    }
    match render(config, &pruned, removed.len()) {
        None => result.error = Some("rewrite_not_lossless"),
        Some(rendered) if replace(path, rendered.as_bytes()).is_err() => {
            result.error = Some("write_failed");
        }
        Some(_) => {
            result.removed = removed.len();
            result.wrote = true;
        }
    }
    result
}

fn render(config: Config, pruned: &PyVal, removed: usize) -> Option<String> {
    match config {
        Config::Json(_, text) => {
            // CPython keeps a lone surrogate escape, in a key or a value, and
            // writes it back; the decoder here cannot, so such a file is left
            // alone.
            if parse_mapping_lone_surrogates(&text).ok()?.mapped {
                return None;
            }
            let mut out = Vec::new();
            write_indented(pruned, 0, &mut out)?;
            out.push(b'\n');
            String::from_utf8(out).ok()
        }
        Config::Toml(mut document) => {
            if prune_document(&mut document) != removed {
                return None;
            }
            let rendered = document.to_string();
            let reparsed = rendered.parse::<DocumentMut>().ok()?;
            same(&table_value(reparsed.as_table()), pruned).then_some(rendered)
        }
    }
}

fn inspect_symlinked<'a>(text: &'a str, path: &Path, dry_run: bool) -> Option<SweepResult<'a>> {
    let target = fs::canonicalize(path).ok()?;
    let config = load(&target).ok()?;
    let (_, removed) = prune_guard_hooks(&config.payload())?;
    Some(SweepResult {
        path: text,
        removed: if dry_run { removed.len() } else { 0 },
        wrote: false,
        error: Some("symlink_not_followed"),
        events: event_names(&removed),
    })
}

/// Write `bytes` beside `path` and rename it over the original, keeping the
/// original's permissions.
fn replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let parent = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    let name = path
        .file_name()
        .ok_or(std::io::ErrorKind::InvalidInput)?
        .to_string_lossy();
    let temporary = parent.join(format!(".{name}.{}.tmp", hex::encode(random_bytes(8))));
    let result = write_temporary(&temporary, bytes, metadata.permissions())
        .and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn write_temporary(
    temporary: &Path,
    bytes: &[u8],
    permissions: fs::Permissions,
) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    // Owner-only until the rewrite is complete, as `mkstemp` created it.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::set_permissions(temporary, permissions)
}

#[cfg(test)]
#[path = "hook_removal_sweep_tests.rs"]
mod tests;
