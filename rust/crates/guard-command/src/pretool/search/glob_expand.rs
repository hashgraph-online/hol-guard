//! Shell glob expansion for read operands, done here component by component.
//!
//! `glob_scope` decides where expansion starts and how strictly it matches.
//! The literal prefix and every literal component must be plain: no `..`
//! after the prefix, no hidden name other than benign project metadata, and
//! no links between the screening root and any match.
#[path = "glob_scope.rs"]
mod glob_scope;

use super::{
    hidden_allowed, ReadContext, HAZARDS, MAX_GLOB_ENTRIES, MAX_GLOB_MATCHES, MAX_WALK_DEPTH,
    SECRET_EXTENSIONS,
};
use crate::pretool::search::glob_matches;
use std::path::{Path, PathBuf};

const GLOB_CHARACTERS: [char; 3] = ['*', '?', '['];

/// Expand a glob. `None` when any step is ambiguous: dot components, `..`,
/// links to directories, an absolute or `~` prefix outside a repository below
/// home, or too many matches. A pattern matching nothing is an empty list, so
/// a caller can tell it apart from an unsafe match.
///
/// A component made only of `*` (such as `**`) is expanded as the union of
/// what shells do with it: zero or more nested directories with `globstar`,
/// and a single `*` without it. A wildcard before the last component only
/// descends into directories, as the shell does.
pub(super) fn expand_glob_matches(value: &str, context: ReadContext<'_>) -> Option<Vec<PathBuf>> {
    expand(value, context, Mode::SHELL)
}

/// [`expand_glob_matches`] under the strict superset model, so an empty list
/// proves that no shell option can make the pattern match anything.
pub(super) fn expand_glob_matches_strict(
    value: &str,
    context: ReadContext<'_>,
) -> Option<Vec<PathBuf>> {
    expand(value, context, Mode::STRICT)
}

/// [`expand_glob_matches`] with the strict model's case folding but without
/// its refusal of a bracket class, for a caller that has already screened the
/// class itself. An empty list then also covers `nocaseglob`, under which
/// `app/[slug]` would match a directory named `S`.
pub(super) fn expand_glob_matches_folded(
    value: &str,
    context: ReadContext<'_>,
) -> Option<Vec<PathBuf>> {
    expand(value, context, Mode::FOLDED)
}

/// How closely a component has to match the name of an entry.
#[derive(Clone, Copy)]
struct Mode {
    /// Match ASCII names regardless of case, as `nocaseglob` does.
    fold_case: bool,
    /// Refuse a class or `**`, whose match depends on options this matcher
    /// does not model.
    refuse_ambiguous: bool,
}

impl Mode {
    const SHELL: Self = Self {
        fold_case: false,
        refuse_ambiguous: false,
    };
    const STRICT: Self = Self {
        fold_case: true,
        refuse_ambiguous: true,
    };
    const FOLDED: Self = Self {
        fold_case: true,
        refuse_ambiguous: false,
    };
}

fn expand(value: &str, context: ReadContext<'_>, mode: Mode) -> Option<Vec<PathBuf>> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(HAZARDS)
        || value.contains(['{', '}', '#', '^', '(', ')'])
        || value.starts_with('-')
        || !crate::pretool::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return None;
    }
    let scope = glob_scope::glob_base(value, context)?;
    let mode = if scope.strict { Mode::STRICT } else { mode };
    let components: Vec<&str> = scope
        .pattern
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    // A pattern ending in `/` matches only directories, as `src/*/` does in
    // the shell, so its last component descends like an inner one.
    let directories_only = scope.pattern.ends_with('/');
    let mut current = vec![scope.base.clone()];
    let mut inspected = 0_usize;
    for (index, component) in components.iter().enumerate() {
        let last = index + 1 == components.len();
        let is_pattern = component.contains(GLOB_CHARACTERS);
        let keeps_files = last && !(directories_only && is_pattern);
        if *component == ".."
            || (component.starts_with('.') && (is_pattern || !hidden_allowed(component)))
            || (mode.refuse_ambiguous
                && is_pattern
                && (component.contains('[') || component.contains("**")))
        {
            return None;
        }
        let mut next = Vec::new();
        for directory in &current {
            if !is_pattern {
                // The shell keeps only literal continuations that exist.
                let path = directory.join(component);
                let exists = std::fs::symlink_metadata(&path).is_ok();
                if (last && exists) || traversable(&path)? {
                    next.push(path);
                }
                continue;
            }
            if !keeps_files && component.len() > 1 && component.bytes().all(|byte| byte == b'*') {
                nested_directories(directory, &mut next, &mut inspected)?;
                continue;
            }
            for entry in std::fs::read_dir(directory).ok()? {
                inspected += 1;
                if inspected > MAX_GLOB_ENTRIES {
                    return None;
                }
                let name = entry.ok()?.file_name();
                let name = name.to_str()?;
                if !component_matches(component, name, mode.fold_case)? {
                    continue;
                }
                let path = directory.join(name);
                if keeps_files || traversable(&path)? {
                    next.push(path);
                }
            }
        }
        if next.len() > MAX_GLOB_MATCHES {
            return None;
        }
        current = next;
    }
    let mut matches = Vec::new();
    for path in current {
        let sibling =
            !scope.siblings || glob_scope::in_sibling_repository(&path, &scope.root, context)?;
        if !sibling || !screened_match(&path, &scope.root, context)? {
            return None;
        }
        matches.push(path);
    }
    Some(matches)
}

/// Whether one directory entry matches one pattern component. Folding case
/// matches ASCII names the way `nocaseglob` does and refuses (`None`) a hidden
/// entry the pattern could match under `dotglob` or a non-ASCII name, where
/// `?` means a byte or a character depending on the locale.
fn component_matches(component: &str, name: &str, fold_case: bool) -> Option<bool> {
    if !fold_case {
        return Some(!name.starts_with('.') && glob_matches(component.as_bytes(), name.as_bytes()));
    }
    if !name.is_ascii() {
        return None;
    }
    let matched = glob_matches(
        component.to_ascii_lowercase().as_bytes(),
        name.to_ascii_lowercase().as_bytes(),
    );
    if matched && name.starts_with('.') {
        return None;
    }
    Some(matched)
}

/// Every match is a regular file or a real directory reached through real
/// directories, and clears the sensitive-path and credential-name screens.
/// Credential names are judged below `root`, so the screen covers the literal
/// prefix of a repository glob as well as the expanded part.
fn screened_match(path: &Path, root: &Path, context: ReadContext<'_>) -> Option<bool> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !(metadata.is_dir() || metadata.is_file()) {
        return None;
    }
    // Each intermediate component must be a real directory, never a link.
    let mut ancestor = path.parent();
    while let Some(parent) = ancestor.filter(|parent| parent.starts_with(root) && *parent != root) {
        if !std::fs::symlink_metadata(parent).ok()?.is_dir() {
            return None;
        }
        ancestor = parent.parent();
    }
    let relative = path.strip_prefix(root).ok()?;
    let secret_extension = metadata.is_file()
        && path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| {
                SECRET_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
            });
    Some(
        guard_secure_fs::sensitive_path_family(path).is_none()
            && !guard_secure_fs::credential_named_path(relative)
            && !secret_extension
            && crate::pretool::read_paths::resolved_path_allowed(
                &std::fs::canonicalize(path).ok()?,
                context.home_dir,
                context.cwd,
            ),
    )
}

/// Whether the shell continues below this path: `Some(true)` for a real
/// directory, `Some(false)` for anything it skips, `None` for a link to a
/// directory, which a shell without `globstar` would follow.
fn traversable(path: &Path) -> Option<bool> {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return Some(false);
    };
    if metadata.file_type().is_symlink() {
        return std::fs::metadata(path)
            .map_or(Some(false), |target| (!target.is_dir()).then_some(false));
    }
    Some(metadata.is_dir())
}

/// `directory` and every non-hidden real directory below it.
fn nested_directories(
    directory: &Path,
    found: &mut Vec<PathBuf>,
    inspected: &mut usize,
) -> Option<()> {
    let mut pending = vec![(directory.to_path_buf(), 0_usize)];
    while let Some((path, depth)) = pending.pop() {
        if depth > MAX_WALK_DEPTH || found.len() >= MAX_GLOB_MATCHES {
            return None;
        }
        for entry in std::fs::read_dir(&path).ok()? {
            *inspected += 1;
            if *inspected > MAX_GLOB_ENTRIES {
                return None;
            }
            let entry = entry.ok()?;
            let name = entry.file_name();
            if name.to_str()?.starts_with('.') {
                continue;
            }
            let child = entry.path();
            if traversable(&child)? {
                pending.push((child, depth + 1));
            }
        }
        found.push(path);
    }
    Some(())
}
