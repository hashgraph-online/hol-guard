use super::ReadContext;
use std::path::{Path, PathBuf};

pub(super) fn safe_recursive_target(value: &str, context: ReadContext<'_>) -> bool {
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
    let expanded = if value == "~" || value.starts_with("~/") {
        let Some(home) = context.home_dir else {
            return false;
        };
        Path::new(home).join(value.strip_prefix("~/").unwrap_or(""))
    } else if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        let Some(cwd) = context.cwd else { return false };
        let expanded_cwd = if cwd == "~" || cwd.starts_with("~/") {
            let Some(home) = context.home_dir else {
                return false;
            };
            Path::new(home).join(cwd.strip_prefix("~/").unwrap_or(""))
        } else {
            PathBuf::from(cwd)
        };
        expanded_cwd.join(value)
    };
    // Remove trailing separators so symlink_metadata cannot follow a directory link.
    let expanded: PathBuf = expanded.components().collect();
    let mut pending = vec![(expanded, 0_usize)];
    let mut inspected = 0_usize;
    // Inspect metadata only. Never follow links or read a secret to classify it.
    while let Some((path, depth)) = pending.pop() {
        inspected += 1;
        if inspected > 10_000 || depth > 64 {
            return false;
        }
        let Some(rendered) = path.to_str() else {
            return false;
        };
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
        }
        if !super::super::safe_reads::bounded_read_target(
            rendered,
            context.home_dir,
            context.cwd,
            true,
        ) {
            return false;
        }
        if metadata.is_dir() {
            let Ok(entries) = std::fs::read_dir(&path) else {
                return false;
            };
            for entry in entries {
                let Ok(entry) = entry else { return false };
                if pending.len() + inspected >= 10_000 {
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
