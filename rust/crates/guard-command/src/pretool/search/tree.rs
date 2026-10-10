//! Bounded metadata walks for recursive readers (`grep -r`, `ls -R`).
//!
//! `rg` skips hidden and ignored entries by default, so a lexical operand
//! check is enough for it. `grep -r` and `ls -R` visit every entry, so the
//! walk classifies each descendant by metadata only: it never follows links
//! and never opens a file to decide.
//!
//! Descendants are judged by what the program can emit, not by shell syntax.
//! A name containing `[` or `]` is data the program reads itself, not a glob,
//! so framework route directories such as `[slug]` are fine. A hidden entry
//! must be on a short benign list, because recursion would otherwise reach
//! `.env`, `.ssh` or `.git`. A credential-named file is refused unless it is
//! source code, matching `credential_named_path`; the name is judged on the
//! path below the walk root so a credential-named ancestor of the operand does
//! not poison it, but a credential-named directory inside the tree still
//! blocks its non-source files.
use super::{glob_matches, ReadContext};
use std::path::{Path, PathBuf};

const MAX_WALK_ENTRIES: usize = 10_000;
const MAX_WALK_DEPTH: usize = 64;
const MAX_GLOB_MATCHES: usize = 256;
const MAX_GLOB_ENTRIES: usize = 20_000;

/// Hidden names that carry no credentials and are common in source trees.
const BENIGN_HIDDEN_NAMES: &[&str] = &[
    ".ds_store",
    ".well-known",
    ".gitignore",
    ".gitkeep",
    ".nvmrc",
    ".editorconfig",
];

/// Key and certificate containers whose names carry no credential word.
pub(in crate::pretool) const SECRET_EXTENSIONS: &[&str] = &[
    "pem", "p12", "pfx", "jks", "keystore", "asc", "gpg", "kdbx", "ppk",
];

pub(in crate::pretool) fn safe_recursive_target(value: &str, context: ReadContext<'_>) -> bool {
    safe_recursive_target_excluding(value, context, &[], &[])
}

pub(super) fn safe_recursive_target_excluding(
    value: &str,
    context: ReadContext<'_>,
    excluded_files: &[&str],
    excluded_directories: &[&str],
) -> bool {
    if !super::super::safe_reads::bounded_read_target(value, context.home_dir, context.cwd, true) {
        return false;
    }
    let Some(root) = expanded_operand(value, context) else {
        return false;
    };
    walk(root, excluded_files, excluded_directories)
}

/// A recursive `ls` operand that the shell passes through literally. Only
/// bracket characters may differ from an ordinary bounded target.
pub(in crate::pretool) fn safe_literal_bracket_tree(
    value: &str,
    context: ReadContext<'_>,
    recursive: bool,
) -> bool {
    let Some(root) = checked_directory(value, context) else {
        return false;
    };
    !recursive || walk(root, &[], &[])
}

/// A glob operand that is expanded here, component by component. Every
/// match must be a non-hidden directory entry that clears the same screens as
/// a literal operand, and recursive listings walk each matched directory.
pub(in crate::pretool) fn safe_glob_operand(
    value: &str,
    context: ReadContext<'_>,
    recursive: bool,
) -> bool {
    let Some(matches) = expand_glob(value, context) else {
        return false;
    };
    matches.into_iter().all(|path| {
        if recursive {
            walk(path, &[], &[])
        } else {
            true
        }
    })
}

fn home_relative(value: &str, home: Option<&str>) -> Option<PathBuf> {
    if value == "~" || value.starts_with("~/") {
        Some(Path::new(home?).join(value.strip_prefix("~/").unwrap_or("")))
    } else {
        Some(PathBuf::from(value))
    }
}

fn expanded_operand(value: &str, context: ReadContext<'_>) -> Option<PathBuf> {
    let expanded = if value == "~" || value.starts_with("~/") {
        home_relative(value, context.home_dir)?
    } else if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        home_relative(context.cwd?, context.home_dir)?.join(value)
    };
    // Remove trailing separators so symlink_metadata cannot follow a directory link.
    Some(expanded.components().collect())
}

/// Characters that make a word mean more than one literal path.
const HAZARDS: [char; 11] = ['$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '\\'];

/// A relative, quoted operand naming an existing real directory.
fn checked_directory(value: &str, context: ReadContext<'_>) -> Option<PathBuf> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(HAZARDS)
        || value.contains(['{', '}', '*', '?'])
        || value.starts_with(['/', '~', '-'])
        || value.split('/').any(|part| part == "..")
        || !super::super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return None;
    }
    let path = expanded_operand(value, context)?;
    real_allowed_directory(&path, context)
}

fn real_allowed_directory(path: &Path, context: ReadContext<'_>) -> Option<PathBuf> {
    if !std::fs::symlink_metadata(path).ok()?.is_dir() {
        return None;
    }
    let canonical = std::fs::canonicalize(path).ok()?;
    super::super::read_paths::resolved_path_allowed(&canonical, context.home_dir, context.cwd)
        .then(|| path.to_path_buf())
}

fn hidden_allowed(name: &str) -> bool {
    BENIGN_HIDDEN_NAMES.contains(&name.to_ascii_lowercase().as_str())
}

fn descendant_allowed(path: &Path, root: &Path, is_file: bool) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if (name.starts_with('.') && !hidden_allowed(name))
        || guard_secure_fs::sensitive_path_family(path).is_some()
    {
        return false;
    }
    if !is_file {
        return true;
    }
    let relative = path.strip_prefix(root).unwrap_or(path);
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !SECRET_EXTENSIONS.contains(&extension.as_str())
        && !guard_secure_fs::credential_named_path(relative)
}

fn walk(root: PathBuf, excluded_files: &[&str], excluded_directories: &[&str]) -> bool {
    let mut pending = vec![(root.clone(), 0_usize)];
    let mut inspected = 0_usize;
    // Inspect metadata only. Never follow links or read a secret to classify it.
    while let Some((path, depth)) = pending.pop() {
        inspected += 1;
        if inspected > MAX_WALK_ENTRIES || depth > MAX_WALK_DEPTH {
            return false;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            return false;
        };
        // Only descendants are excluded: explicit operands and links still
        // require proof. Exact basenames avoid approximating grep's glob rules.
        if depth > 0 {
            let basename = path.file_name().and_then(|name| name.to_str());
            if basename.is_some_and(|name| {
                (metadata.is_dir() && excluded_directories.contains(&name))
                    || (metadata.is_file() && excluded_files.contains(&name))
            }) {
                continue;
            }
            if !descendant_allowed(&path, &root, metadata.is_file()) {
                return false;
            }
        }
        if metadata.is_dir() {
            let Ok(entries) = std::fs::read_dir(&path) else {
                return false;
            };
            for entry in entries {
                let Ok(entry) = entry else { return false };
                if pending.len() + inspected >= MAX_WALK_ENTRIES {
                    return false;
                }
                pending.push((entry.path(), depth + 1));
            }
        } else if !metadata.is_file() {
            return false;
        }
    }
    true
}

/// Expand a relative glob below the cwd. `None` when any step is ambiguous:
/// absolute or `~` operands, dot components, `..`, links, no match, or too
/// many matches.
fn expand_glob(value: &str, context: ReadContext<'_>) -> Option<Vec<PathBuf>> {
    if value.is_empty()
        || value.len() > 4096
        || value.contains(HAZARDS)
        || value.contains(['{', '}'])
        || value.starts_with(['/', '~', '-'])
        || !super::super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return None;
    }
    let base = real_allowed_directory(&home_relative(context.cwd?, context.home_dir)?, context)?;
    let mut current = vec![base];
    let mut inspected = 0_usize;
    for component in value
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
    {
        if component == ".." || component.starts_with('.') {
            return None;
        }
        let is_pattern = component.contains(['*', '?', '[']);
        let mut next = Vec::new();
        for directory in &current {
            if !is_pattern {
                next.push(directory.join(component));
                continue;
            }
            for entry in std::fs::read_dir(directory).ok()? {
                inspected += 1;
                if inspected > MAX_GLOB_ENTRIES {
                    return None;
                }
                let name = entry.ok()?.file_name();
                let name = name.to_str()?;
                if !name.starts_with('.') && glob_matches(component.as_bytes(), name.as_bytes()) {
                    next.push(directory.join(name));
                }
            }
        }
        if next.len() > MAX_GLOB_MATCHES {
            return None;
        }
        current = next;
    }
    let root = home_relative(context.cwd?, context.home_dir)?;
    let mut matches = Vec::new();
    for path in current {
        let metadata = std::fs::symlink_metadata(&path).ok()?;
        if !(metadata.is_dir() || metadata.is_file()) {
            return None;
        }
        // Each intermediate component must be a real directory, never a link.
        let mut ancestor = path.parent();
        while let Some(parent) =
            ancestor.filter(|parent| parent.starts_with(&root) && *parent != root)
        {
            if !std::fs::symlink_metadata(parent).ok()?.is_dir() {
                return None;
            }
            ancestor = parent.parent();
        }
        let relative = path.strip_prefix(&root).ok()?;
        if guard_secure_fs::sensitive_path_family(&path).is_some()
            || guard_secure_fs::credential_named_path(relative)
            || (metadata.is_file()
                && path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| {
                        SECRET_EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
                    }))
            || !super::super::read_paths::resolved_path_allowed(
                &std::fs::canonicalize(&path).ok()?,
                context.home_dir,
                context.cwd,
            )
        {
            return None;
        }
        matches.push(path);
    }
    (!matches.is_empty()).then_some(matches)
}
