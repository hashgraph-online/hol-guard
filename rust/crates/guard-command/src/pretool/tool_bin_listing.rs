//! Metadata-only `ls` of the bin directories a tool is installed into
//! (`~/.bun/bin/bun`, `~/.cargo/bin`, `/opt/homebrew/bin/jq`).
//!
//! A listing prints names and metadata, never file content. Only a known bin
//! directory and its direct children qualify, so the sibling credential, cache
//! and state directories of the same tool stay guarded. The named child may be
//! absent, since naming every bin directory a tool could live in is how a
//! presence probe asks which one has it. A symlink child is judged by its
//! canonical target, which must stay inside the same bin directory or clear
//! every read screen. A project's `node_modules/.bin` gets the same treatment
//! below a readable root.

use std::path::{Component, Path, PathBuf};

#[path = "listing_metadata.rs"]
mod metadata;
pub(super) use metadata::{credential_file_metadata_operand, global_package_listing_operand};

/// Home components holding a `bin` directory of installed tools.
const TOOL_ROOTS: [&str; 6] = [".bun", ".cargo", ".deno", ".local", ".npm-global", "go"];

/// Bin directories a probe spells in full, outside home. Package managers own
/// these paths, so a name below one of them is an installed tool rather than a
/// file the agent chose the location of.
const SYSTEM_BIN_DIRS: [&str; 6] = [
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/opt/local/bin",
    "/usr/bin",
    "/bin",
    "/home/linuxbrew/.linuxbrew/bin",
];

/// Split an operand into the bin directory it names and the single child below
/// it, if any. Anything deeper, or below another directory, is not a probe.
fn split_bin_target(expanded: &str, home_dir: &str) -> Option<(PathBuf, Option<String>)> {
    if let Ok(relative) = Path::new(expanded).strip_prefix(home_dir) {
        let names: Vec<String> = relative
            .components()
            .map(|component| match component {
                Component::Normal(name) => Some(name.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect::<Option<_>>()?;
        let (root, child) = match names.as_slice() {
            [root, bin] if bin == "bin" => (root, None),
            [root, bin, child] if bin == "bin" => (root, Some(child.clone())),
            _ => return None,
        };
        if !TOOL_ROOTS.contains(&root.as_str()) {
            return None;
        }
        return Some((Path::new(home_dir).join(root).join("bin"), child));
    }
    let directory = SYSTEM_BIN_DIRS.iter().find(|directory| {
        expanded == **directory || expanded.starts_with(&format!("{directory}/"))
    })?;
    let child = expanded[directory.len()..].trim_start_matches('/');
    if child.is_empty() {
        return Some((PathBuf::from(directory), None));
    }
    if child.contains('/') {
        return None;
    }
    Some((PathBuf::from(directory), Some(child.to_owned())))
}

/// Whether the bin directory an operand names is one a listing may print.
///
/// A prefix this machine does not have holds nothing to list, and naming the
/// prefixes a tool could be installed into is how a presence probe asks which
/// one has it, so an absent directory qualifies. A present one is judged by
/// where it resolves rather than by its spelling: on a merged-`/usr` system
/// `/bin` is a link to `/usr/bin`, which is a bin directory of this list all
/// the same, while a link planted at a recognized prefix, or at one of its
/// parents, resolves outside the list and cannot present a guarded tree as a
/// bin directory. A dangling link resolves nowhere and gives no proof.
fn listable_bin_directory(bin_dir: &Path, home_dir: &str) -> bool {
    if let Err(error) = std::fs::symlink_metadata(bin_dir) {
        return error.kind() == std::io::ErrorKind::NotFound;
    }
    let Ok(canonical) = std::fs::canonicalize(bin_dir) else {
        return false;
    };
    if !canonical.is_dir() {
        return false;
    }
    // Home itself is often reached through a link, so both spellings are
    // resolved before they are compared.
    let home = std::fs::canonicalize(home_dir).unwrap_or_else(|_| PathBuf::from(home_dir));
    let (Some(home), Some(resolved)) = (home.to_str(), canonical.to_str()) else {
        return false;
    };
    matches!(split_bin_target(resolved, home), Some((_, None)))
}

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
    if !Path::new(&expanded).is_absolute() {
        return false;
    }
    let Some((bin_dir, child)) = split_bin_target(&expanded, home_dir) else {
        return false;
    };
    if !listable_bin_directory(&bin_dir, home_dir) {
        return false;
    }
    let Some(child) = child else {
        return true;
    };
    if child.starts_with('.')
        || guard_secure_fs::sensitive_external_filename(Path::new(&child))
        || guard_secure_fs::credential_named_path(Path::new(&child))
    {
        return false;
    }
    let leaf = bin_dir.join(&child);
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
