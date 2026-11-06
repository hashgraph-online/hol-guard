//! Git repository identity and workspace placement for the package context.

use std::collections::BTreeSet;

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

fn identify(fs: &Fs, files: &mut ContextFiles, marker: &str) -> Built<OValue> {
    let git_dir = resolve_git_dir(fs, files, marker)?;
    let common_dir = resolve_git_common_dir(fs, files, &git_dir)?;
    let config = PyPath::new(&common_dir).join("config").to_string();
    let remotes = git_remote_urls(fs, files, &config)?;
    let remote_urls = OValue::List(remotes.iter().map(|url| text(url)).collect());
    Ok(object(vec![
        ("common_git_dir", text(&common_dir)),
        ("remote_urls", remote_urls),
    ]))
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

fn git_remote_urls(fs: &Fs, files: &mut ContextFiles, config: &str) -> Built<Vec<String>> {
    if !fs.exists(config)? {
        return Ok(Vec::new());
    }
    let text = decode(files.read(fs, config, MAX_CONFIG_FILE_BYTES, false)?)?;
    let mut in_remote = false;
    let mut urls: BTreeSet<String> = BTreeSet::new();
    for line in py_splitlines(&text) {
        let stripped = py_strip(&line);
        if stripped.starts_with('[') && stripped.ends_with(']') {
            in_remote = stripped.to_lowercase().starts_with("[remote \"");
            continue;
        }
        if !in_remote {
            continue;
        }
        let Some((key, value)) = stripped.split_once('=') else {
            continue;
        };
        if py_strip(key).to_lowercase() == "url" && !py_strip(value).is_empty() {
            urls.insert(py_strip(value).to_owned());
        }
    }
    Ok(urls.into_iter().collect())
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
