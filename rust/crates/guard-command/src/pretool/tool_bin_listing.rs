//! Metadata-only `ls` of well-known tool bin directories below hidden home
//! components (`~/.bun/bin/bun`, `~/.cargo/bin`, `~/.local/bin/tool`).
//!
//! A listing prints names and metadata, never file content. Only the exact
//! `~/.<tool>/bin` directory and its direct children qualify, so the sibling
//! credential, cache and state directories of the same tool stay guarded. A
//! symlink child is judged by its canonical target, which must stay inside the
//! same bin directory or clear every read screen. A project's
//! `node_modules/.bin` gets the same treatment below a readable root.

use std::path::{Component, Path};

#[path = "listing_metadata.rs"]
mod metadata;
pub(super) use metadata::{credential_file_metadata_operand, global_package_listing_operand};

const TOOL_ROOTS: [&str; 4] = [".bun", ".cargo", ".deno", ".local"];

pub(super) fn tool_bin_listing_operand(value: &str, context: super::PathContext<'_>) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.contains(['$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '\\'])
        || value.contains(['*', '?', '[', ']', '{', '}'])
        || !super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    let Some(home_dir) = context.home_dir else {
        return false;
    };
    let expanded = super::read_paths::expand_home_read_path(value, context.home_dir)
        .unwrap_or_else(|| value.to_owned());
    let expanded = Path::new(&expanded);
    if !expanded.is_absolute() {
        return false;
    }
    let Ok(relative) = expanded.strip_prefix(home_dir) else {
        return false;
    };
    let names: Vec<String> = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Option<_>>()
        .unwrap_or_default();
    let (root, child) = match names.as_slice() {
        [root, bin] if bin == "bin" => (root, None),
        [root, bin, child] if bin == "bin" => (root, Some(child)),
        _ => return false,
    };
    if !TOOL_ROOTS.contains(&root.as_str()) {
        return false;
    }
    let bin_dir = Path::new(home_dir).join(root).join("bin");
    if !std::fs::symlink_metadata(&bin_dir).is_ok_and(|metadata| metadata.is_dir()) {
        return false;
    }
    let Some(child) = child else {
        return true;
    };
    if child.starts_with('.')
        || guard_secure_fs::sensitive_external_filename(Path::new(child))
        || guard_secure_fs::credential_named_path(Path::new(child))
    {
        return false;
    }
    let leaf = bin_dir.join(child);
    let Ok(metadata) = std::fs::symlink_metadata(&leaf) else {
        return false;
    };
    if !metadata.file_type().is_symlink() {
        return metadata.is_file();
    }
    let Ok(canonical) = std::fs::canonicalize(&leaf) else {
        return false;
    };
    if guard_secure_fs::sensitive_path_family(&canonical).is_some()
        || guard_secure_fs::credential_named_path(&canonical)
    {
        return false;
    }
    canonical.is_file()
        && (std::fs::canonicalize(&bin_dir).is_ok_and(|bin| canonical.starts_with(bin))
            || super::read_paths::resolved_path_allowed_for_operation(
                &canonical,
                context.home_dir,
                context.cwd,
                false,
                true,
            ))
}

/// `ls <root>/node_modules/.bin` or `ls <root>/node_modules/.bin/<name>`:
/// checking whether a package bin is installed in a readable checkout. The
/// root must clear the ordinary directory read screens. `node_modules` and
/// `.bin` must each be absent or a real directory, so neither can redirect the
/// listing elsewhere. The named child may be absent, a regular file, or a link
/// to a file inside the same `node_modules` or one that clears every read
/// screen. A directory child is refused, because `ls` would list its contents.
pub(super) fn node_bin_listing_operand(value: &str, context: super::PathContext<'_>) -> bool {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('-')
        || value.contains(['$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '\\'])
        || value.contains(['*', '?', '[', ']', '{', '}'])
        || value.split('/').any(|part| part == "." || part == "..")
        || !super::safe_reads::verified_path_context(context.home_dir, context.cwd)
    {
        return false;
    }
    let expanded = super::read_paths::expand_home_read_path(value, context.home_dir)
        .unwrap_or_else(|| value.to_owned());
    let path = if Path::new(&expanded).is_absolute() {
        Path::new(&expanded).to_path_buf()
    } else {
        let Some(cwd) = context.cwd else {
            return false;
        };
        let cwd = super::read_paths::expand_home_read_path(cwd, context.home_dir)
            .unwrap_or_else(|| cwd.to_owned());
        Path::new(&cwd).join(&expanded)
    };
    let names: Vec<&str> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect();
    let (tail, child) = match names.as_slice() {
        [.., modules, bin] if *modules == "node_modules" && *bin == ".bin" => (2, None),
        [.., modules, bin, child] if *modules == "node_modules" && *bin == ".bin" => {
            (3, Some(*child))
        }
        _ => return false,
    };
    let mut root = path.to_path_buf();
    for _ in 0..tail {
        root.pop();
    }
    let Some(root_text) = root.to_str() else {
        return false;
    };
    if root_text.is_empty()
        || !std::fs::symlink_metadata(&root).is_ok_and(|metadata| metadata.is_dir())
        || !super::read_paths::bounded_read_target(root_text, context.home_dir, context.cwd, true)
    {
        return false;
    }
    let modules = root.join("node_modules");
    let bin_dir = modules.join(".bin");
    let absent_or_directory = |path: &Path| match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata.is_dir(),
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    };
    if !absent_or_directory(&modules) || !absent_or_directory(&bin_dir) {
        return false;
    }
    let Some(child) = child else {
        return true;
    };
    if child.starts_with('.')
        || guard_secure_fs::sensitive_external_filename(Path::new(child))
        || guard_secure_fs::credential_named_path(Path::new(child))
    {
        return false;
    }
    let leaf = bin_dir.join(child);
    let metadata = match std::fs::symlink_metadata(&leaf) {
        Ok(metadata) => metadata,
        Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
    };
    if !metadata.file_type().is_symlink() {
        return metadata.is_file();
    }
    let Ok(canonical) = std::fs::canonicalize(&leaf) else {
        return false;
    };
    if guard_secure_fs::sensitive_path_family(&canonical).is_some()
        || guard_secure_fs::credential_named_path(&canonical)
    {
        return false;
    }
    canonical.is_file()
        && (std::fs::canonicalize(&modules).is_ok_and(|modules| canonical.starts_with(modules))
            || super::read_paths::resolved_path_allowed_for_operation(
                &canonical,
                context.home_dir,
                context.cwd,
                false,
                true,
            ))
}
