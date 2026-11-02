//! `supply_chain_audit_workspace_dir`: which workspace a supply-chain audit
//! or scan request runs against.
//!
//! An explicit `workspace_dir` or `workspace` wins when it resolves to a
//! directory under one of the allowed roots. Without one, the audit infers the
//! workspace from `CURSOR_PROJECT_DIR`, then the caller's working directory,
//! then the active managed installs, and takes only a directory that holds a
//! dependency manifest. The caller passes its working directory, home and
//! environment value, so the answer never depends on the resident's own.

use std::path::{Path, PathBuf};

use guard_command::local_supply_chain::MANIFEST_CANDIDATES;
use serde_json::{json, Map, Value};

use crate::aibom_paths::{is_dir, resolve, resolves_within_root};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const MAX_LIST_ITEMS: usize = 4_096;

struct Context {
    roots: Vec<PathBuf>,
    cwd: Option<PathBuf>,
    user_home: Option<PathBuf>,
}

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let explicit = strings(args, "explicit")?;
    let managed = strings(args, "managed_workspace_dirs")?;
    let reject_invalid_explicit = match args.get("reject_invalid_explicit") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return Err(ERR_INVALID),
    };
    let mut context = Context {
        cwd: optional(args, "cwd")?.and_then(absolute),
        user_home: optional(args, "user_home")?.and_then(absolute),
        roots: Vec::new(),
    };
    context.roots = strings(args, "allowed_roots")?
        .into_iter()
        .filter_map(|root| context.absolute_or_relative(root))
        .collect();

    for candidate in explicit.iter().filter(|value| !value.trim().is_empty()) {
        if let Some(resolved) = context.within_allowed_roots(candidate) {
            return Ok(answer(Some(&resolved)));
        }
        if reject_invalid_explicit {
            return Ok(json!({ "workspace_dir": null, "invalid_explicit": true }));
        }
    }
    if let Some(cursor_project) = optional(args, "cursor_project_dir")? {
        let cursor_project = cursor_project.trim();
        if !cursor_project.is_empty() {
            if let Some(resolved) = context
                .within_allowed_roots(cursor_project)
                .filter(|path| has_project_markers(path))
            {
                return Ok(answer(Some(&resolved)));
            }
        }
    }
    if let Some(cwd) = context.cwd.as_deref().and_then(resolve_path) {
        if has_project_markers(&cwd)
            && context
                .roots
                .iter()
                .any(|root| resolves_within_root(root, &cwd, true))
        {
            return Ok(answer(Some(&cwd)));
        }
    }
    let inferred = managed.iter().find_map(|workspace| {
        context
            .within_allowed_roots(workspace)
            .filter(|path| has_project_markers(path))
    });
    Ok(answer(inferred.as_deref()))
}

fn answer(workspace: Option<&Path>) -> Value {
    json!({ "workspace_dir": workspace.map(|path| path.to_string_lossy().into_owned()) })
}

fn optional<'a>(args: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, &'static str> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(ERR_INVALID),
    }
}

/// A list of strings; non-string entries are skipped, as the Python caller
/// skipped any value that was not a string.
fn strings<'a>(args: &'a Map<String, Value>, key: &str) -> Result<Vec<&'a str>, &'static str> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) if items.len() <= MAX_LIST_ITEMS => {
            Ok(items.iter().filter_map(Value::as_str).collect())
        }
        Some(_) => Err(ERR_INVALID),
    }
}

fn absolute(text: &str) -> Option<PathBuf> {
    let path = PathBuf::from(text);
    (!text.contains('\0') && path.is_absolute()).then_some(path)
}

/// Non-strict `Path.resolve()`; `None` for a link loop or a relative path.
fn resolve_path(path: &Path) -> Option<PathBuf> {
    resolve(path).ok()
}

/// `Path(workspace).resolve()` holds one of the dependency manifests.
fn has_project_markers(workspace: &Path) -> bool {
    resolve_path(workspace).is_some_and(|resolved| {
        MANIFEST_CANDIDATES
            .iter()
            .any(|marker| std::fs::metadata(resolved.join(marker)).is_ok())
    })
}

/// `~\\name` is a home-relative path only where `\\` separates components.
fn home_relative_windows(value: &str) -> bool {
    cfg!(windows) && value.starts_with("~\\")
}

impl Context {
    /// `os.path.expanduser`, then `os.path.realpath` against the caller's
    /// working directory. A `~user` form, or `~` without a home, is never
    /// guessed at.
    fn absolute_or_relative(&self, value: &str) -> Option<PathBuf> {
        if value.contains('\0') {
            return None;
        }
        let expanded = if value == "~" || value.starts_with("~/") || home_relative_windows(value) {
            let home = self.user_home.as_deref()?;
            let rest = value
                .strip_prefix('~')
                .unwrap_or_default()
                .trim_start_matches(|c: char| c == '/' || (cfg!(windows) && c == '\\'));
            if rest.is_empty() {
                home.to_path_buf()
            } else {
                home.join(rest)
            }
        } else if value.starts_with('~') {
            return None;
        } else {
            PathBuf::from(value)
        };
        let absolute = if expanded.is_absolute() {
            expanded
        } else {
            self.cwd.as_deref()?.join(expanded)
        };
        resolve_path(&absolute)
    }

    /// `resolve_path_within_allowed_roots(value, roots, require_exists=True)`:
    /// the resolved path, when an allowed root contains it and it is a
    /// directory.
    fn within_allowed_roots(&self, value: &str) -> Option<PathBuf> {
        let stripped = value.trim();
        if stripped.is_empty() || matches!(stripped.to_lowercase().as_str(), "none" | "null") {
            return None;
        }
        let resolved = self.absolute_or_relative(stripped)?;
        let contained = self.roots.iter().any(|root| resolved.starts_with(root));
        (contained && is_dir(&resolved)).then_some(resolved)
    }
}

#[cfg(test)]
#[path = "supply_chain_audit_workspace_tests.rs"]
mod tests;
