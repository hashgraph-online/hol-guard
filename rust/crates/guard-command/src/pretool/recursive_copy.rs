//! `cp -R <directory> <new path>` inside the workspace.
//!
//! A recursive copy duplicates a tree the agent could already search, so the
//! source passes the same metadata walk as `grep -r`: a real directory with no
//! links, no hidden entries outside a short benign list and no
//! credential-named files. The copy must create a new path. An existing target
//! would merge into or overwrite files, so it stays reviewed. The new path
//! lands in the workspace under the same write screen as `mkdir`, and never
//! inside the source tree.
use super::read_paths::expand_home_read_path;
use std::path::{Path, PathBuf};

pub(super) fn safe_recursive_copy_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let (source, destination) = match arguments {
        [flag, source, destination] if recursive_flag(flag) => (source, destination),
        [flag, separator, source, destination] if recursive_flag(flag) && separator == "--" => {
            (source, destination)
        }
        _ => return false,
    };
    if source.starts_with('-')
        || destination.starts_with('-')
        || source.trim() != source
        || destination.trim() != destination
        || !super::search::safe_recursive_search_target(source, context)
    {
        return false;
    }
    let (Some(source_path), Some(destination_path)) = (
        operand_path(source, context),
        operand_path(destination, context),
    ) else {
        return false;
    };
    if guard_secure_fs::contains_symlink_component(&source_path) {
        return false;
    }
    let Ok(metadata) = source_path.symlink_metadata() else {
        return false;
    };
    let Ok(source_root) = std::fs::canonicalize(&source_path) else {
        return false;
    };
    if !metadata.is_dir() {
        return false;
    }
    let target = match destination_path.symlink_metadata() {
        // cp places the tree under an existing directory. A source spelled
        // with a trailing slash (BSD cp) or ending in `.` or `..` copies only
        // its contents, merging them into the directory, so those spellings
        // are not a new path.
        Ok(existing) if existing.is_dir() && names_the_tree(source) => {
            let Some(name) = source_root.file_name() else {
                return false;
            };
            destination_path.join(name)
        }
        Ok(_) => return false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => destination_path,
        Err(_) => return false,
    };
    if !matches!(
        target.symlink_metadata(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ) {
        return false;
    }
    let Some(target_text) = target.to_str() else {
        return false;
    };
    super::safe_writes::bounded_new_directory_write_target(
        target_text,
        context.home_dir,
        context.cwd,
    ) && super::worktree_writes::canonical_write_target(&target)
        .is_some_and(|canonical| !canonical.starts_with(&source_root))
}

fn names_the_tree(source: &str) -> bool {
    source
        .rsplit('/')
        .next()
        .is_some_and(|last| !matches!(last, "" | "." | ".."))
}

fn recursive_flag(flag: &str) -> bool {
    matches!(flag, "-R" | "-r" | "--recursive")
}

fn operand_path(value: &str, context: super::PathContext<'_>) -> Option<PathBuf> {
    let expanded =
        expand_home_read_path(value, context.home_dir).unwrap_or_else(|| value.to_owned());
    let supplied = Path::new(&expanded);
    if supplied.is_absolute() {
        return Some(supplied.to_path_buf());
    }
    let cwd = context.cwd?;
    let root = expand_home_read_path(cwd, context.home_dir).unwrap_or_else(|| cwd.to_owned());
    Some(Path::new(&root).join(supplied))
}
