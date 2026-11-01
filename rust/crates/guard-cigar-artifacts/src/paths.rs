use crate::InstallError;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path};

pub fn private_directory(path: &Path) -> Result<(), InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| InstallError::DestinationUnsafe)?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        || fs::canonicalize(path).map_err(|_| InstallError::DestinationUnsafe)? != path
    {
        return Err(InstallError::DestinationUnsafe);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(InstallError::DestinationUnsafe);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err(InstallError::PlatformUnsupported)
    }
}
pub fn private_child(path: &Path) -> Result<(), InstallError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        match fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(InstallError::WriteFailed),
        }
        private_directory(path)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(InstallError::PlatformUnsupported)
    }
}

// Deliberately narrow portable names: wheel metadata is not a path authority.
// Refuse platform aliases (case, ADS, device names, trailing dots/spaces),
// import hooks and unsupported wheel .data relocation before writing bytes.
pub fn admit_name(
    raw: &[u8],
    directory: bool,
    namespace: &mut BTreeMap<String, (String, bool)>,
) -> Result<String, InstallError> {
    admit_name_folding(raw, directory, namespace, true)
}

/// Interpreter trees are only unpacked on the host they were built for.
/// Linux CPython ships names that differ only by case (terminfo), so case
/// aliases are refused only where the host filesystem folds case.
pub fn admit_interpreter_name(
    raw: &[u8],
    directory: bool,
    namespace: &mut BTreeMap<String, (String, bool)>,
) -> Result<String, InstallError> {
    admit_name_folding(
        raw,
        directory,
        namespace,
        cfg!(any(target_os = "macos", windows)),
    )
}

fn admit_name_folding(
    raw: &[u8],
    directory: bool,
    namespace: &mut BTreeMap<String, (String, bool)>,
    fold_case: bool,
) -> Result<String, InstallError> {
    let raw = std::str::from_utf8(raw).map_err(|_| InstallError::EntryUnsafe)?;
    let name = if directory {
        raw.strip_suffix('/').ok_or(InstallError::EntryUnsafe)?
    } else {
        raw
    };
    if name.is_empty() || name.len() > 1024 || !name.is_ascii() || name.split('/').count() > 24 {
        return Err(InstallError::EntryUnsafe);
    }
    let mut prefix = String::new();
    let parts: Vec<_> = name.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        let lower = part.to_ascii_lowercase();
        let stem = lower.split('.').next().unwrap_or("");
        if part.is_empty()
            || part.len() > 240
            || *part == "."
            || *part == ".."
            || part.ends_with(['.', ' '])
            || part
                .bytes()
                .any(|b| b < 32 || b == 127 || b"\\:<>\"|?*".contains(&b))
            || matches!(stem, "con" | "prn" | "aux" | "nul" | "clock$")
            || (stem.len() == 4
                && (stem.starts_with("com") || stem.starts_with("lpt"))
                && stem.as_bytes()[3].is_ascii_digit())
            || lower.ends_with(".pth")
            || lower.ends_with(".egg-link")
            || lower.ends_with(".data")
        {
            return Err(InstallError::EntryUnsafe);
        }
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        let is_directory = index + 1 < parts.len() || directory;
        let key = if fold_case {
            prefix.to_ascii_lowercase()
        } else {
            prefix.clone()
        };
        if let Some((previous, previous_directory)) = namespace.get(&key) {
            if previous != &prefix || !previous_directory || !is_directory {
                return Err(InstallError::EntryUnsafe);
            }
        } else {
            namespace.insert(key, (prefix.clone(), is_directory));
        }
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_aliases_are_refused_only_where_the_host_folds_case() {
        let mut namespace = BTreeMap::new();
        admit_name(b"share/terminfo/e/eterm", false, &mut namespace).unwrap();
        assert!(admit_name(b"share/terminfo/E/Eterm", false, &mut namespace).is_err());
        let mut namespace = BTreeMap::new();
        admit_interpreter_name(b"share/terminfo/e/eterm", false, &mut namespace).unwrap();
        let alias = admit_interpreter_name(b"share/terminfo/E/Eterm", false, &mut namespace);
        assert_eq!(alias.is_err(), cfg!(any(target_os = "macos", windows)));
        assert!(admit_interpreter_name(b"share/terminfo/e/eterm", false, &mut namespace).is_err());
    }
}
