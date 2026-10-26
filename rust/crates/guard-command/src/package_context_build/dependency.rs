//! Manifest and lockfile digests (`dependency_material`).

use crate::launch_identity_common::sha256_hex;
use serde_json::{Map, Value};

use crate::codex_output_py::{py_strip, PyPath};
use crate::hook_adapter_value::OValue;

use super::fs::{ContextFiles, Fs, ResolveError, MAX_DEPENDENCY_FILE_BYTES};
use super::{object, string_items, string_value, text, BuildError, Built};

fn default_dependency_paths(manager: &str, kind: &str) -> &'static [&'static str] {
    let normalized = py_strip(manager).to_lowercase();
    if kind == "manifest" {
        match normalized.as_str() {
            "bun" | "bunx" | "npm" | "npx" | "yarn" => &["package.json"],
            "pnpm" => &["package.json", "pnpm-workspace.yaml"],
            "pip" | "pip3" => &[
                "pyproject.toml",
                "requirements.txt",
                "setup.py",
                "setup.cfg",
            ],
            "poetry" => &["pyproject.toml"],
            "uv" => &["pyproject.toml", "requirements.txt"],
            _ => &[],
        }
    } else {
        match normalized.as_str() {
            "bun" | "bunx" => &["bun.lock", "bun.lockb"],
            "npm" | "npx" => &["package-lock.json", "npm-shrinkwrap.json"],
            "pnpm" => &["pnpm-lock.yaml"],
            "yarn" => &["yarn.lock"],
            "pip" | "pip3" => &["uv.lock", "poetry.lock", "Pipfile.lock"],
            "poetry" => &["poetry.lock"],
            "uv" => &["uv.lock"],
            _ => &[],
        }
    }
}

/// `resolve_path_within_workspace` for an already resolved workspace.
fn resolve_within_workspace(fs: &Fs, workspace: &str, relative: &str) -> Built<Option<String>> {
    if relative.is_empty() || PyPath::new(relative).is_absolute() {
        return Ok(None);
    }
    let joined = PyPath::new(workspace).join(relative).to_string();
    let resolved = match fs.resolve(&joined, false) {
        Ok(resolved) => resolved,
        Err(ResolveError::Os) => return Ok(None),
        Err(other) => return Err(other.into_fatal(&joined)),
    };
    if PyPath::new(&resolved)
        .relative_to(&PyPath::new(workspace))
        .is_none()
    {
        return Ok(None);
    }
    Ok(Some(resolved))
}

fn entry(kind: &str, path: &str, key: &str, value: &str) -> OValue {
    object(vec![
        (key, text(value)),
        ("kind", text(kind)),
        ("path", text(path)),
    ])
}

pub(super) fn dependency_material(
    fs: &Fs,
    files: &mut ContextFiles,
    workspace: &str,
    metadata: &Map<String, Value>,
) -> Built<(OValue, Option<&'static str>)> {
    let mut entries: Vec<OValue> = Vec::new();
    let mut failure: Option<&'static str> = None;
    let manager = string_value(metadata.get("package_manager")).unwrap_or_default();
    for (kind, key) in [
        ("manifest", "manifest_paths"),
        ("lockfile", "lockfile_paths"),
    ] {
        let configured = string_items(metadata.get(key));
        let paths: Vec<String> = if configured.is_empty() {
            let mut inferred = Vec::new();
            for relative in default_dependency_paths(&manager, kind) {
                let candidate = PyPath::new(workspace).join(relative).to_string();
                if fs.is_file(&candidate)? {
                    inferred.push((*relative).to_owned());
                }
            }
            inferred
        } else {
            configured
        };
        for relative in paths {
            let mut resolved = resolve_within_workspace(fs, workspace, &relative)?;
            if let Some(path) = &resolved {
                if !fs.exists(path)? {
                    resolved = None;
                }
            }
            let Some(resolved) = resolved else {
                entries.push(entry(kind, &relative, "status", "missing"));
                failure = failure.or(Some("dependency_file_unavailable"));
                continue;
            };
            match files.read(fs, &resolved, MAX_DEPENDENCY_FILE_BYTES, false) {
                Ok(payload) => {
                    let digest = sha256_hex(&payload);
                    entries.push(entry(kind, &relative, "digest", &digest));
                }
                Err(BuildError::Unavailable(reason)) => {
                    entries.push(entry(kind, &relative, "status", reason));
                    failure = failure.or(Some(reason));
                }
                Err(fatal) => return Err(fatal),
            }
        }
    }
    Ok((object(vec![("files", OValue::List(entries))]), failure))
}
