use super::*;

pub(super) fn normalize_absolute_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory path cannot contain parent components",
                ))
            }
            Component::CurDir => {}
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir | Component::Normal(_) => normalized.push(component.as_os_str()),
        }
    }
    // Windows can represent the same path with different prefixes (for
    // example, `C:\\...` versus the `\\\\?\\C:\\...` form returned by
    // `canonicalize`). Resolve the existing portion of every input so the
    // boundary check compares equivalent path representations. The final
    // private directory may not exist yet, so retain any missing tail.
    canonicalize_existing_prefix(&normalized)
}

pub(super) fn canonicalize_existing_prefix(path: &Path) -> io::Result<PathBuf> {
    let mut existing = path.to_owned();
    let mut missing_tail = Vec::new();

    let canonical_existing = loop {
        match existing.canonicalize() {
            Ok(canonical) => {
                break long_path_if_same_shape(&win32_path(&canonical)).unwrap_or(canonical);
            }
            Err(error) => {
                // `\\?\` disables 8.3 expansion, so canonicalize returns
                // NotFound for an existing short name. GetLongPathNameW on
                // the Win32 form still resolves it when the component count
                // is unchanged. A junction that changes depth still fails.
                if let Some(long) = long_path_if_same_shape(&win32_path(&existing)) {
                    break long;
                }
                let Some(name) = existing.file_name() else {
                    return Err(error);
                };
                missing_tail.push(name.to_owned());
                let Some(parent) = existing.parent() else {
                    return Err(error);
                };
                if parent == existing {
                    return Err(error);
                }
                existing = parent.to_owned();
            }
        }
    };

    let verbatim = canonical_existing
        .as_os_str()
        .to_string_lossy()
        .starts_with(r"\\?\");
    let mut canonical = if missing_tail.is_empty() {
        canonical_existing
    } else {
        win32_path(&canonical_existing)
    };
    for component in missing_tail.iter().rev() {
        canonical.push(existing_alias_or_name(&canonical, component));
    }
    if verbatim && !missing_tail.is_empty() {
        // A successful canonicalize restores the verbatim form. If it fails,
        // keep the Win32 spelling: re-adding `\\?\` disables 8.3 expansion
        // and makes an existing short-name tail look missing.
        if let Ok(resolved) = std::fs::canonicalize(&canonical) {
            canonical = resolved;
        }
    }
    if let Some(long) = long_path_if_same_shape(&win32_path(&canonical)) {
        canonical = long;
    }
    Ok(extended_path_if_long(&canonical))
}

fn existing_alias_or_name(parent: &Path, name: &OsStr) -> std::ffi::OsString {
    let candidate = win32_path(parent).join(name);
    let Some(long) = long_path_if_same_shape(&candidate) else {
        return name.to_owned();
    };
    let Some(long_name) = long.file_name() else {
        return name.to_owned();
    };
    let Some(long_parent) = long.parent() else {
        return name.to_owned();
    };
    if path_has_prefix(long_parent, &win32_path(parent))
        && path_has_prefix(&win32_path(parent), long_parent)
    {
        long_name.to_owned()
    } else {
        name.to_owned()
    }
}

pub(super) fn win32_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path.to_owned()
}

pub(super) fn long_path_if_same_shape(path: &Path) -> Option<PathBuf> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return None;
    }
    wide.push(0);
    let mut buffer = vec![0u16; 512];
    let mut length =
        unsafe { GetLongPathNameW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    if length as usize > buffer.len() {
        buffer.resize(length as usize, 0);
        length =
            unsafe { GetLongPathNameW(wide.as_ptr(), buffer.as_mut_ptr(), buffer.len() as u32) };
    }
    if length == 0 || length as usize > buffer.len() {
        return None;
    }
    buffer.truncate(length as usize);
    let long = PathBuf::from(std::ffi::OsString::from_wide(&buffer));
    if !long.is_absolute() || long.components().count() != path.components().count() {
        return None;
    }
    Some(long)
}

pub(super) fn extended_path_if_long(path: &Path) -> PathBuf {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    let path = win32_path(path);
    let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if wide.len() < MAX_PATH {
        return path;
    }
    let mut extended = Vec::with_capacity(wide.len() + 8);
    if wide.starts_with(&[92, 92]) {
        extended.extend_from_slice(&[92, 92, 63, 92, 85, 78, 67, 92]);
        extended.extend_from_slice(&wide[2..]);
    } else {
        extended.extend_from_slice(&[92, 92, 63, 92]);
        extended.extend_from_slice(&wide);
    }
    PathBuf::from(std::ffi::OsString::from_wide(&extended))
}

/// Open the same directory under a spelling CreateFileW can resolve.
///
/// `\\?\` disables 8.3 expansion, so an existing short name returns
/// NotFound. The Win32 form and a same-shape long path are the only
/// retries. A junction that changes depth is rejected by the long-path check.
pub(super) fn open_equivalent_directory(
    path: &Path,
    allow_add_file: bool,
) -> Option<(std::fs::File, PathBuf)> {
    let win32 = win32_path(path);
    if win32 != path {
        if let Ok(handle) = open_directory_bound(&win32, false, allow_add_file) {
            return Some((handle, win32));
        }
    }
    let long = long_path_if_same_shape(&win32)?;
    if long == path || long == win32 {
        return None;
    }
    open_directory_bound(&long, false, allow_add_file)
        .ok()
        .map(|handle| (handle, long))
}
/// True when `path` is `root` or a descendant. `\\?\` and Win32 spellings name
/// the same directory. A long-path lookup is accepted only when it keeps the
/// same component count, so a junction to another depth still fails.
pub fn path_is_within(path: &Path, root: &Path) -> bool {
    if path_has_prefix(path, root) {
        return true;
    }
    let Some(long_path) = long_path_if_same_shape(&win32_path(path)) else {
        return false;
    };
    path_has_prefix(&long_path, root) || path_has_prefix(&long_path, &win32_path(root))
}

pub(super) fn validate_boundary(
    path: &Path,
    trusted_base: &Path,
    private_root: &Path,
) -> io::Result<()> {
    if !path.is_absolute() || !trusted_base.is_absolute() || !private_root.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory binding paths must be absolute",
        ));
    }
    if !path_has_prefix(private_root, trusted_base) || !path_has_prefix(path, private_root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory binding path is outside its trusted private boundary",
        ));
    }
    if !path
        .components()
        .any(|component| matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private directory path has no directory component",
        ));
    }
    if !private_root
        .components()
        .any(|component| matches!(component, Component::Normal(_)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private directory boundary has no directory component",
        ));
    }
    Ok(())
}

pub(super) fn path_has_prefix(path: &Path, prefix: &Path) -> bool {
    let path_components = boundary_components(path);
    let prefix_components = boundary_components(prefix);
    if prefix_components.len() > path_components.len() {
        return false;
    }
    path_components
        .iter()
        .zip(prefix_components.iter())
        .all(|(actual, expected)| boundary_component_eq(actual, expected))
}

pub(super) fn boundary_components(path: &Path) -> Vec<Component<'_>> {
    path.components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect()
}

/// Win32 canonical forms name the same directory with different prefixes
/// (`C:\` vs `\\?\C:\`, `\\server\share` vs `\\?\UNC\server\share`) and with
/// filesystem case. Guard homes are created by this process; a case variant is
/// the same NTFS directory, not a sibling escape. `..` is rejected earlier.
pub(super) fn os_eq_ignore_ascii_case(left: &OsStr, right: &OsStr) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

pub(super) fn boundary_component_eq(actual: &Component<'_>, expected: &Component<'_>) -> bool {
    match (actual, expected) {
        (Component::Prefix(left), Component::Prefix(right)) => windows_prefix_eq(left, right),
        (Component::RootDir, Component::RootDir) => true,
        (Component::Normal(left), Component::Normal(right)) => os_eq_ignore_ascii_case(left, right),
        _ => false,
    }
}

pub(super) fn windows_prefix_eq(left: &PrefixComponent<'_>, right: &PrefixComponent<'_>) -> bool {
    if windows_prefix_kind_eq(left.kind(), right.kind()) {
        return true;
    }
    os_eq_ignore_ascii_case(left.as_os_str(), right.as_os_str())
}

pub(super) fn windows_prefix_kind_eq(left: Prefix<'_>, right: Prefix<'_>) -> bool {
    let left_disk = match left {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Some(letter),
        _ => None,
    };
    let right_disk = match right {
        Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Some(letter),
        _ => None,
    };
    if let (Some(left_letter), Some(right_letter)) = (left_disk, right_disk) {
        return left_letter.eq_ignore_ascii_case(&right_letter);
    }
    let left_unc = match left {
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => Some((server, share)),
        _ => None,
    };
    let right_unc = match right {
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => Some((server, share)),
        _ => None,
    };
    if let (Some((left_server, left_share)), Some((right_server, right_share))) =
        (left_unc, right_unc)
    {
        return os_eq_ignore_ascii_case(left_server, right_server)
            && os_eq_ignore_ascii_case(left_share, right_share);
    }
    false
}
