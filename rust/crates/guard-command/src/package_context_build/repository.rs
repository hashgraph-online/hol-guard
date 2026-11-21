//! Git repository identity and workspace placement for the package context.

use std::collections::{BTreeMap, BTreeSet};

use crate::codex_output_py::{py_splitlines, py_strip, PyPath};
use crate::hook_adapter_value::OValue;

use super::fs::{ContextFiles, Fs, MAX_CONFIG_FILE_BYTES, MAX_GIT_POINTER_BYTES};
use super::{object, text, BuildError, Built};

const UNAVAILABLE: &str = "repository_identity_unavailable";

pub(super) struct Repository {
    pub(super) root: Option<String>,
    pub(super) material: OValue,
    pub(super) failure: Option<&'static str>,
}

fn unavailable() -> BuildError {
    BuildError::Unavailable(UNAVAILABLE)
}

/// `repository_material`: the nearest enclosing `.git` of the workspace.
pub(super) fn repository_material(
    fs: &Fs,
    files: &mut ContextFiles,
    workspace: &str,
) -> Built<Repository> {
    let start = PyPath::new(workspace);
    let mut candidates = vec![start.clone()];
    candidates.extend(start.pop_parent_components());
    for candidate in candidates {
        let marker = candidate.join(".git").to_string();
        if !fs.exists(&marker)? {
            continue;
        }
        return match identify(fs, files, &marker) {
            Ok(material) => Ok(Repository {
                root: Some(candidate.to_string()),
                material,
                failure: None,
            }),
            Err(BuildError::Unavailable(reason)) => Ok(Repository {
                root: None,
                material: object(vec![("workspace_path", text(workspace))]),
                failure: Some(reason),
            }),
            Err(fatal) => Err(fatal),
        };
    }
    Ok(Repository {
        root: None,
        material: object(vec![("workspace_path", text(workspace))]),
        failure: Some(UNAVAILABLE),
    })
}

/// The repository a checkout belongs to, as named by its `origin` remote.
///
/// Linked worktrees, fresh clones and checkouts at another path all name the
/// same `origin`, so a saved package approval follows the codebase rather than
/// the directory it was approved in. Adding unrelated remotes, or switching
/// `origin` between its SSH and HTTPS spellings, leaves the identity alone. A
/// repository without remotes has nothing portable to name and falls back to
/// its common Git directory, which its linked worktrees still share.
fn identify(fs: &Fs, files: &mut ContextFiles, marker: &str) -> Built<OValue> {
    let git_dir = resolve_git_dir(fs, files, marker)?;
    let common_dir = resolve_git_common_dir(fs, files, &git_dir)?;
    let config = PyPath::new(&common_dir).join("config").to_string();
    let remotes = git_remote_urls(fs, files, &config)?;
    let base = PyPath::new(&common_dir).parent().to_string();
    let names = |urls: &BTreeSet<String>| {
        OValue::List(
            urls.iter()
                .map(|url| remote_identity(url, &base))
                .collect::<BTreeSet<_>>()
                .iter()
                .map(|url| text(url))
                .collect(),
        )
    };
    if let Some(origin) = remotes.get("origin") {
        return Ok(object(vec![("origin_urls", names(origin))]));
    }
    let all: BTreeSet<String> = remotes.into_values().flatten().collect();
    if !all.is_empty() {
        return Ok(object(vec![("remote_urls", names(&all))]));
    }
    Ok(object(vec![("common_git_dir", text(&common_dir))]))
}

/// A remote as it identifies the repository. A local path written relative
/// (`../upstream`) names a different repository beside every checkout, so it
/// is resolved against the directory holding the common Git directory: linked
/// worktrees still agree, while `../upstream` next to `/a/app` and next to
/// `/b/app` do not.
fn remote_identity(raw: &str, base: &str) -> String {
    let url = py_strip(raw);
    if url.starts_with('/') || url.contains("://") || scp_like(url).is_some() {
        return normalized_remote_url(url);
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in base.split('/').chain(url.split('/')) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    normalized_remote_url(&format!("/{}", parts.join("/")))
}

/// One remote URL reduced to the host and path it names: credentials, port,
/// scheme, a trailing `/` and a `.git` suffix are dropped and the host is
/// lowercased, so `git@github.com:org/repo.git` and
/// `https://user@github.com/org/repo` agree. Local paths are kept as written.
pub(super) fn normalized_remote_url(raw: &str) -> String {
    let url = py_strip(raw);
    let (host, path) = if let Some((scheme, rest)) = url.split_once("://") {
        if scheme.eq_ignore_ascii_case("file") {
            return trim_repository_suffix(rest).to_owned();
        }
        match rest.split_once('/') {
            Some((authority, path)) => (authority, path),
            None => (rest, ""),
        }
    } else if let Some((authority, path)) = scp_like(url) {
        (authority, path)
    } else {
        return trim_repository_suffix(url).to_owned();
    };
    let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
    let host = match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) => name,
        _ => host,
    };
    let path = trim_repository_suffix(path.trim_start_matches('/'));
    format!("{}/{}", host.to_ascii_lowercase(), path)
}

/// `[user@]host:path`, Git's scp-like syntax: a colon before any slash.
fn scp_like(url: &str) -> Option<(&str, &str)> {
    let colon = url.find(':')?;
    if url[..colon].contains('/') || colon == 0 {
        return None;
    }
    Some((&url[..colon], &url[colon + 1..]))
}

fn trim_repository_suffix(path: &str) -> &str {
    let path = path.trim_end_matches('/');
    path.strip_suffix(".git")
        .unwrap_or(path)
        .trim_end_matches('/')
}

fn decode(payload: Vec<u8>) -> Built<String> {
    String::from_utf8(payload).map_err(|_| unavailable())
}

fn existing_directory(fs: &Fs, candidate: &PyPath) -> Built<String> {
    let resolved = match fs.resolve(&candidate.to_string(), true) {
        Ok(resolved) => resolved,
        Err(super::fs::ResolveError::Os) => return Err(unavailable()),
        Err(other) => return Err(other.into_fatal(&candidate.to_string())),
    };
    if !fs.is_dir(&resolved)? {
        return Err(unavailable());
    }
    Ok(resolved)
}

fn resolve_git_dir(fs: &Fs, files: &mut ContextFiles, marker: &str) -> Built<String> {
    if fs.is_dir(marker)? {
        return fs
            .resolve(marker, false)
            .map_err(|error| error.into_fatal(marker));
    }
    let text = decode(files.read(fs, marker, MAX_GIT_POINTER_BYTES, false)?)?;
    let text = py_strip(&text);
    let Some(raw) = text.strip_prefix("gitdir:") else {
        return Err(unavailable());
    };
    let raw = py_strip(raw);
    if raw.is_empty() {
        return Err(unavailable());
    }
    let mut candidate = PyPath::new(raw);
    if !candidate.is_absolute() {
        candidate = PyPath::new(marker).parent().join(raw);
    }
    existing_directory(fs, &candidate)
}

fn resolve_git_common_dir(fs: &Fs, files: &mut ContextFiles, git_dir: &str) -> Built<String> {
    let marker = PyPath::new(git_dir).join("commondir").to_string();
    if !fs.exists(&marker)? {
        return fs
            .resolve(git_dir, false)
            .map_err(|error| error.into_fatal(git_dir));
    }
    let text = decode(files.read(fs, &marker, MAX_GIT_POINTER_BYTES, false)?)?;
    let raw = py_strip(&text);
    let mut candidate = PyPath::new(raw);
    if !candidate.is_absolute() {
        candidate = PyPath::new(git_dir).join(raw);
    }
    existing_directory(fs, &candidate)
}

/// Every `[remote "<name>"]` section's `url` values, by remote name.
fn git_remote_urls(
    fs: &Fs,
    files: &mut ContextFiles,
    config: &str,
) -> Built<BTreeMap<String, BTreeSet<String>>> {
    let mut remotes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if !fs.exists(config)? {
        return Ok(remotes);
    }
    let text = decode(files.read(fs, config, MAX_CONFIG_FILE_BYTES, false)?)?;
    let mut remote: Option<String> = None;
    for line in py_splitlines(&text) {
        let stripped = py_strip(&line);
        if stripped.starts_with('[') && stripped.ends_with(']') {
            let section = &stripped[1..stripped.len() - 1];
            remote = section
                .get(..6)
                .filter(|keyword| keyword.eq_ignore_ascii_case("remote"))
                .and_then(|_| section.get(6..))
                .map(py_strip)
                .and_then(|name| name.strip_prefix('"'))
                .and_then(|name| name.strip_suffix('"'))
                .map(str::to_owned);
            continue;
        }
        let Some(name) = &remote else {
            continue;
        };
        let Some((key, value)) = stripped.split_once('=') else {
            continue;
        };
        if py_strip(key).to_lowercase() == "url" && !py_strip(value).is_empty() {
            remotes
                .entry(name.clone())
                .or_default()
                .insert(py_strip(value).to_owned());
        }
    }
    Ok(remotes)
}

/// `workspace_material`.
pub(super) fn workspace_material(
    workspace: &str,
    repository_root: Option<&str>,
    portable: bool,
) -> OValue {
    if let (true, Some(root)) = (portable, repository_root) {
        let relative = match PyPath::new(workspace).relative_to(&PyPath::new(root)) {
            Some(parts) if !parts.is_empty() => parts.join("/"),
            Some(_) => ".".to_owned(),
            None => workspace.to_owned(),
        };
        return object(vec![("repository_relative_path", text(&relative))]);
    }
    object(vec![("exact_path", text(workspace))])
}
