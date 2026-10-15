use super::*;

pub(super) fn restricted_pythonpath(
    value: &str,
    workspace: &Path,
    cwd: &Path,
) -> Result<String, RestrictedPytestError> {
    let mut entries: Vec<String> = Vec::new();
    for raw_entry in value.split(':') {
        let resolved = if raw_entry.is_empty() {
            cwd.to_path_buf()
        } else {
            let candidate = expand_user(Path::new(raw_entry));
            let joined = if candidate.is_absolute() {
                candidate
            } else {
                cwd.join(&candidate)
            };
            let resolved = resolve_nonstrict(&joined).map_err(|_| {
                RestrictedPytestError::new(
                    PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE,
                    "Restricted pytest rejected PYTHONPATH because it references a path outside the workspace.",
                )
            })?;
            if resolved.strip_prefix(workspace).is_err() {
                return Err(RestrictedPytestError::new(
                    PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE,
                    "Restricted pytest rejected PYTHONPATH because it references a path outside the workspace.",
                ));
            }
            resolved
        };
        let text = resolved.to_string_lossy().into_owned();
        if !entries.contains(&text) {
            entries.push(text);
        }
    }
    Ok(entries.join(":"))
}

/// `_first_symlink_expansion` (:437-455).
pub(super) fn first_symlink_expansion(path: &Path) -> Option<PathBuf> {
    let parts: Vec<PathBuf> = path
        .components()
        .map(|c| PathBuf::from(c.as_os_str()))
        .collect();
    if parts.is_empty() {
        return None;
    }
    let mut current = parts[0].clone();
    for index in 1..parts.len() {
        current = current.join(&parts[index]);
        if !current.is_symlink() {
            continue;
        }
        let raw_target = match fs::read_link(&current) {
            Ok(target) => target,
            Err(_) => return None,
        };
        let target = if raw_target.is_absolute() {
            raw_target
        } else {
            current
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .join(&raw_target)
        };
        let mut expanded = target;
        for part in &parts[index + 1..] {
            expanded = expanded.join(part);
        }
        return Some(normpath(&path_absolute(&expanded)));
    }
    None
}

/// `_runtime_distribution_root` (:456-462).
pub(super) fn runtime_distribution_root(executable: &Path) -> PathBuf {
    let parts: Vec<&OsStr> = executable.components().map(|c| c.as_os_str()).collect();
    let bin_indexes: Vec<usize> = parts
        .iter()
        .enumerate()
        .filter(|(_, part)| **part == OsStr::new("bin"))
        .map(|(index, _)| index)
        .collect();
    if bin_indexes.is_empty() {
        return executable
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/"));
    }
    let last = *bin_indexes.last().unwrap();
    let mut root = PathBuf::new();
    for part in &parts[..last] {
        root.push(part);
    }
    root
}

pub(super) fn host_home_directory() -> Option<PathBuf> {
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()?
        .dir
        .canonicalize()
        .ok()
}

/// `_path_is_within` (:476-483).
pub(super) fn path_is_within(path: &Path, root: &Path) -> bool {
    match (resolve_nonstrict(path).ok(), resolve_nonstrict(root).ok()) {
        (Some(resolved), Some(root_resolved)) => resolved.strip_prefix(root_resolved).is_ok(),
        _ => false,
    }
}

/// `_path_is_within_lexically` (:484-491).
pub(super) fn path_is_within_lexically(path: &Path, root: &Path) -> bool {
    match resolve_nonstrict(root).ok() {
        Some(root_resolved) => path_absolute(path).strip_prefix(&root_resolved).is_ok(),
        None => false,
    }
}

/// `_path_is_within_any` (:492-495).
pub(super) fn path_is_within_any(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path_is_within(path, root))
}

/// `_path_is_within_any_lexically` (:496-497).
pub(super) fn path_is_within_any_lexically(path: &Path, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|root| path_is_within_lexically(path, root))
}

/// `re.Pattern.fullmatch` — anchored case-insensitive compare (Python's
/// pattern is compiled with `re.IGNORECASE`).
pub(super) fn regex_is_match(pattern: &Regex, text: &str) -> bool {
    // `re.IGNORECASE` is baked into the Python pattern; the Rust port
    // case-folds input instead (pattern literals are all lowercase).
    pattern.is_match(&text.to_lowercase())
}
