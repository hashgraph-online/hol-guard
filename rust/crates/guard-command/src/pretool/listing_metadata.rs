//! Metadata-only `ls` operands that the general read screens reject.
//!
//! `ls` prints names, sizes, modes and times, never file content. Two shapes
//! qualify here:
//!
//! * one existing regular file whose name marks it as a credential, such as
//!   `~/kubeconfig.yaml`. Reading it stays reviewed; confirming it exists
//!   does not expose it. Symlinks, directories (whose entries could name
//!   further secrets) and paths inside credential stores stay guarded.
//! * a global package tree below a node version manager or runtime in the
//!   home directory, such as `~/.bun/install/global/node_modules` or
//!   `~/.nvm/versions/node/<v>/lib/node_modules`. The path must pass through
//!   a `node_modules` component, so the tool's caches, settings and
//!   credential files beside it stay guarded.

use std::path::{Component, Path, PathBuf};

const PACKAGE_ROOTS: [&str; 6] = [".bun", ".nvm", ".volta", ".fnm", ".npm-global", ".asdf"];

fn plain_operand(value: &str, context: crate::pretool::PathContext<'_>) -> Option<PathBuf> {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '\\', '*', '?', '[', ']', '{', '}',
        ])
        || value.split('/').any(|part| part == "..")
        || !crate::pretool::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return None;
    }
    let expanded = crate::pretool::read_paths::expand_home_read_path(value, context.home_dir)
        .unwrap_or_else(|| value.to_owned());
    let expanded = Path::new(&expanded);
    if expanded.is_absolute() {
        return Some(expanded.to_path_buf());
    }
    if value.starts_with('~') {
        return None;
    }
    let cwd = context.cwd?;
    let cwd = crate::pretool::read_paths::expand_home_read_path(cwd, context.home_dir)
        .unwrap_or_else(|| cwd.to_owned());
    Some(Path::new(&cwd).join(expanded))
}

/// `ls -la ~/kubeconfig.yaml`: one regular, non-symlink file whose only
/// screen failure is its credential-like name.
pub(in crate::pretool) fn credential_file_metadata_operand(
    value: &str,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    let Some(path) = plain_operand(value, context) else {
        return false;
    };
    if !std::fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.file_type().is_file()) {
        return false;
    }
    let Ok(canonical) = std::fs::canonicalize(&path) else {
        return false;
    };
    let Some(parent) = canonical.parent() else {
        return false;
    };
    canonical.is_file()
        && guard_secure_fs::sensitive_path_family(&canonical).is_none()
        && crate::pretool::read_paths::resolved_path_allowed_for_operation(
            parent,
            context.home_dir,
            context.cwd,
            false,
            true,
        )
}

/// Component names that hold a tool's download or build caches rather than
/// installed packages. A cache may hold its own `node_modules` tree.
const CACHE_PARTS: [&str; 7] = [
    "cache", ".cache", "caches", "_cacache", "_npx", "tmp", ".tmp",
];

fn path_names(path: &Path) -> Option<Vec<&str>> {
    path.components()
        .map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect()
}

/// `<root>/.../node_modules/...` with no hidden directory before
/// `node_modules`, and no cache, sensitive or credential-named component.
fn package_tree_parts(root: &str, rest: &[&str]) -> bool {
    let Some(modules) = rest.iter().position(|name| *name == "node_modules") else {
        return false;
    };
    PACKAGE_ROOTS.contains(&root)
        && !rest[..modules].iter().any(|name| name.starts_with('.'))
        && !rest.iter().any(|name| {
            CACHE_PARTS.contains(&name.to_ascii_lowercase().as_str())
                || guard_secure_fs::sensitive_external_filename(Path::new(name))
                || guard_secure_fs::credential_named_path(Path::new(name))
        })
}

/// `ls ~/.bun/install/global/node_modules`: a listing inside a global
/// `node_modules` tree of a home-level runtime or version manager. Both the
/// spelled and the resolved path must be such a tree, so a link from a
/// global tree into the tool's cache stays reviewed. A target that resolves
/// outside the tool root must also pass the ordinary read location screens.
pub(in crate::pretool) fn global_package_listing_operand(
    value: &str,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    let (Some(path), Some(home_dir)) = (plain_operand(value, context), context.home_dir) else {
        return false;
    };
    let Some(names) = path.strip_prefix(home_dir).ok().and_then(path_names) else {
        return false;
    };
    let Some((root, rest)) = names.split_first() else {
        return false;
    };
    if !package_tree_parts(root, rest) {
        return false;
    }
    let (Ok(canonical), Ok(tool_root)) = (
        std::fs::canonicalize(&path),
        std::fs::canonicalize(Path::new(home_dir).join(root)),
    ) else {
        return false;
    };
    if guard_secure_fs::sensitive_path_family(&canonical).is_some()
        || guard_secure_fs::credential_named_path(&canonical)
    {
        return false;
    }
    match canonical.strip_prefix(&tool_root).ok().and_then(path_names) {
        Some(resolved) => package_tree_parts(root, &resolved),
        None => {
            // Only names below home can mark a tool cache; the home path
            // itself may sit under a directory such as /tmp.
            let home = std::fs::canonicalize(home_dir).unwrap_or_else(|_| home_dir.into());
            let below_home = canonical.strip_prefix(&home).unwrap_or(&canonical);
            below_home.components().all(|component| match component {
                Component::Normal(name) => name
                    .to_str()
                    .is_some_and(|name| !CACHE_PARTS.contains(&name.to_ascii_lowercase().as_str())),
                _ => true,
            }) && crate::pretool::read_paths::resolved_path_allowed_for_operation(
                &canonical,
                context.home_dir,
                context.cwd,
                false,
                true,
            )
        }
    }
}
