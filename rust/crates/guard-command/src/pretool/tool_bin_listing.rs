//! Metadata-only `ls` of well-known tool bin directories below hidden home
//! components (`~/.bun/bin/bun`, `~/.cargo/bin`, `~/.local/bin/tool`).
//!
//! A listing prints names and metadata, never file content. Only the exact
//! `~/.<tool>/bin` directory and its direct children qualify, so the sibling
//! credential, cache and state directories of the same tool stay guarded. A
//! symlink child is judged by its canonical target, which must stay inside the
//! same bin directory or clear every read screen.

use std::path::{Component, Path};

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
