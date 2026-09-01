#![forbid(unsafe_code)]

use guard_rules::MAX_SCAN_BYTES;
use sha2::{Digest, Sha256};
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

mod secure_open;
mod source_path;

use secure_open::{secure_open, SecureOpenError};
pub use source_path::{classify_source_path, sensitive_path_family, source_like};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: Option<u64>,
    pub ino: Option<u64>,
    pub size: u64,
    pub mtime_ns: u128,
    /// The permission/type bits are part of identity so a permission change
    /// during a read cannot be mistaken for an unchanged source file.
    pub mode: u32,
    /// A decision-critical source read must not follow a multiply-linked file:
    /// another pathname could mutate the bytes after the path was classified.
    pub nlink: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureRead {
    pub bytes: Vec<u8>,
    pub identity: FileIdentity,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourcePathDecision {
    pub allowed: bool,
    pub reason_code: &'static str,
    pub resolved_path: Option<PathBuf>,
}

impl SourcePathDecision {
    fn allow(reason_code: &'static str, path: PathBuf) -> Self {
        Self {
            allowed: true,
            reason_code,
            resolved_path: Some(path),
        }
    }

    fn deny(reason_code: &'static str) -> Self {
        Self {
            allowed: false,
            reason_code,
            resolved_path: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum SecureReadError {
    #[error("unresolved_path")]
    UnresolvedPath,
    #[error("symlink_in_path")]
    SymlinkInPath,
    #[error("not_regular_file")]
    NotRegularFile,
    #[error("hard_linked_file")]
    HardLinkedFile,
    #[error("permission_denied")]
    PermissionDenied,
    #[error("source_file_too_large")]
    TooLarge,
    #[error("read_failed")]
    ReadFailed,
    #[error("source_stat_changed")]
    Changed,
    #[error("source_path_changed")]
    PathChanged,
}

pub fn resolve_candidate(
    target: &str,
    cwd: Option<&Path>,
    home: &Path,
) -> Result<PathBuf, SecureReadError> {
    let stripped = target.trim().trim_matches(['\'', '"']);
    if stripped.is_empty() {
        return Err(SecureReadError::UnresolvedPath);
    }
    if stripped == "~" {
        return Ok(home.to_path_buf());
    }
    if let Some(rest) = stripped.strip_prefix("~/") {
        return Ok(home.join(rest));
    }
    if stripped.starts_with('~') {
        return Err(SecureReadError::UnresolvedPath);
    }
    let path = PathBuf::from(stripped);
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(cwd.unwrap_or_else(|| Path::new(".")).join(path))
}

pub fn contains_symlink_component(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        let should_stat = match component {
            Component::Prefix(prefix) => {
                current.push(prefix.as_os_str());
                false
            }
            Component::RootDir => {
                current.push(Path::new(std::path::MAIN_SEPARATOR_STR));
                false
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                current.push("..");
                false
            }
            Component::Normal(part) => {
                current.push(part);
                true
            }
        };
        if !should_stat {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return true,
        }
    }
    false
}

fn identity(metadata: &Metadata) -> FileIdentity {
    let mtime_ns = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map_or(0, |value| value.as_nanos());
    #[cfg(unix)]
    let (dev, ino) = (Some(metadata.dev()), Some(metadata.ino()));
    #[cfg(not(unix))]
    let (dev, ino) = (None, None);
    #[cfg(unix)]
    let (mode, nlink) = (metadata.mode(), metadata.nlink());
    #[cfg(not(unix))]
    let (mode, nlink) = (0, 0);
    FileIdentity {
        dev,
        ino,
        size: metadata.len(),
        mtime_ns,
        mode,
        nlink,
    }
}

fn map_secure_open_error(error: SecureOpenError) -> SecureReadError {
    match error {
        SecureOpenError::PathChanged => SecureReadError::PathChanged,
        #[cfg(unix)]
        SecureOpenError::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            SecureReadError::PermissionDenied
        }
        #[cfg(unix)]
        SecureOpenError::Io(_) => SecureReadError::ReadFailed,
    }
}

pub fn read_bounded(path: &Path, max_bytes: usize) -> Result<SecureRead, SecureReadError> {
    let max_bytes = max_bytes.min(MAX_SCAN_BYTES);
    if contains_symlink_component(path) {
        return Err(SecureReadError::SymlinkInPath);
    }
    // Resolve once before opening and once after reading.  O_NOFOLLOW closes
    // the final-component race on Unix; the paired canonical checks also
    // catch a parent-directory replacement or a path substitution observed
    // after the descriptor was opened.  The descriptor remains the source of
    // truth for bytes and stat identity.
    let canonical_before = fs::canonicalize(path).map_err(|_| SecureReadError::ReadFailed)?;
    let mut file = secure_open(path, &canonical_before).map_err(map_secure_open_error)?;
    let before_metadata = file.metadata().map_err(|_| SecureReadError::ReadFailed)?;
    if !before_metadata.is_file() {
        return Err(SecureReadError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        let mode = before_metadata.mode();
        if mode & 0o444 == 0 {
            return Err(SecureReadError::PermissionDenied);
        }
        if before_metadata.nlink() != 1 {
            return Err(SecureReadError::HardLinkedFile);
        }
    }
    if before_metadata.len() > max_bytes as u64 {
        return Err(SecureReadError::TooLarge);
    }
    let before = identity(&before_metadata);
    let mut bytes = Vec::with_capacity(before.size as usize);
    file.by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SecureReadError::ReadFailed)?;
    if bytes.len() > max_bytes {
        return Err(SecureReadError::TooLarge);
    }
    let after = identity(&file.metadata().map_err(|_| SecureReadError::ReadFailed)?);
    if before != after {
        return Err(SecureReadError::Changed);
    }
    if contains_symlink_component(path) {
        return Err(SecureReadError::SymlinkInPath);
    }
    let canonical_after = fs::canonicalize(path).map_err(|_| SecureReadError::PathChanged)?;
    if canonical_before != canonical_after {
        return Err(SecureReadError::PathChanged);
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(SecureRead {
        bytes,
        identity: after,
        sha256: hex::encode(hasher.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    fn fixture_root(name: &str) -> PathBuf {
        #[cfg(unix)]
        let temporary_root =
            fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
        #[cfg(not(unix))]
        let temporary_root = std::env::temp_dir();
        temporary_root.join(format!("guard-secure-fs-{name}-{}", std::process::id()))
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_hashes_regular_file() {
        let dir = fixture_root("read");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.rs");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"fn main() {}\n").unwrap();
        drop(file);
        let read = read_bounded(&path, MAX_SCAN_BYTES).unwrap();
        assert_eq!(read.bytes, b"fn main() {}\n");
        assert_eq!(read.sha256.len(), 64);
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(not(unix))]
    #[test]
    fn bounded_read_fails_closed_without_descriptor_path_walk() {
        let dir = fixture_root("read");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.rs");
        fs::write(&path, b"fn main() {}\n").unwrap();
        assert!(matches!(
            read_bounded(&path, MAX_SCAN_BYTES),
            Err(SecureReadError::PathChanged)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_rejects_hard_linked_source() {
        let dir = fixture_root("hard-link");
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source.rs");
        let alias = dir.join("alias.rs");
        fs::write(&source, b"fn source() {}\n").unwrap();
        fs::hard_link(&source, &alias).unwrap();
        assert!(matches!(
            read_bounded(&alias, MAX_SCAN_BYTES),
            Err(SecureReadError::HardLinkedFile)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_rejects_file_without_read_permission_even_for_root() {
        let dir = fixture_root("permissions");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("source.rs");
        fs::write(&path, b"fn source() {}\n").unwrap();
        let original_mode = path.metadata().unwrap().permissions().mode();
        let mut permissions = path.metadata().unwrap().permissions();
        permissions.set_mode(original_mode & !0o444);
        fs::set_permissions(&path, permissions).unwrap();
        assert!(matches!(
            read_bounded(&path, MAX_SCAN_BYTES),
            Err(SecureReadError::PermissionDenied)
        ));
        let mut permissions = path.metadata().unwrap().permissions();
        permissions.set_mode(original_mode);
        fs::set_permissions(&path, permissions).unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_rejects_symlink_source() {
        let dir = fixture_root("symlink");
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.rs");
        let link = dir.join("source.rs");
        fs::write(&target, b"fn target() {}\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(matches!(
            read_bounded(&link, MAX_SCAN_BYTES),
            Err(SecureReadError::SymlinkInPath)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_rejects_parent_symlink_source_replacement() {
        let dir = fixture_root("parent-replacement");
        let real = dir.join("real");
        let alias = dir.join("alias");
        fs::create_dir_all(&real).unwrap();
        fs::write(real.join("source.rs"), b"fn source() {}\n").unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        assert!(matches!(
            read_bounded(&alias.join("source.rs"), MAX_SCAN_BYTES),
            Err(SecureReadError::SymlinkInPath)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn file_identity_changes_when_source_permissions_change() {
        let dir = fixture_root("identity-permissions");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("source.rs");
        fs::write(&path, b"fn source() {}\n").unwrap();
        let before = identity(&path.metadata().unwrap());
        let original_mode = before.mode;

        let mut permissions = path.metadata().unwrap().permissions();
        permissions.set_mode(original_mode ^ 0o001);
        fs::set_permissions(&path, permissions).unwrap();
        let after = identity(&path.metadata().unwrap());

        assert_ne!(before, after);
        assert_ne!(before.mode, after.mode);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn sensitive_paths_are_classified() {
        assert_eq!(
            sensitive_path_family(Path::new("/home/u/.aws/credentials"))
                .unwrap()
                .0,
            "AWS shared credentials file"
        );
        assert_eq!(
            sensitive_path_family(Path::new(".env.local")).unwrap().1,
            "critical"
        );
    }

    #[test]
    fn source_classifier_rejects_hidden_sensitive_and_escape_paths() {
        let root = fixture_root("classifier");
        let home = root.join("home");
        let workspace = home.join("workspace");
        fs::create_dir_all(workspace.join("src")).unwrap();
        fs::create_dir_all(workspace.join(".secret")).unwrap();
        fs::write(workspace.join("src/main.rs"), "fn main() {}\n").unwrap();
        fs::write(workspace.join(".secret/config.ts"), "value = 1\n").unwrap();
        fs::write(workspace.join(".env"), "fixture=value\n").unwrap();
        let skill = home.join(".claude/skills/safe");
        fs::create_dir_all(skill.join("credentials")).unwrap();
        fs::write(skill.join("SKILL.md"), "# Safe\n").unwrap();
        fs::write(skill.join("credentials/config.ts"), "value = 1\n").unwrap();

        assert!(classify_source_path("src/main.rs", &workspace, Some(&home), false).allowed);
        assert_eq!(
            classify_source_path(".secret/config.ts", &workspace, Some(&home), false).reason_code,
            "unsafe_hidden_dir"
        );
        assert_eq!(
            classify_source_path(".env", &workspace, Some(&home), false).reason_code,
            "sensitive_basename"
        );
        assert_eq!(
            classify_source_path("../../outside.rs", &workspace, Some(&home), true).reason_code,
            "path_traversal"
        );
        assert_eq!(
            classify_source_path(
                "~/.claude/skills/safe/../../src/app.py",
                &workspace,
                Some(&home),
                false,
            )
            .reason_code,
            "path_traversal"
        );
        assert_eq!(
            classify_source_path(
                "~/.claude/skills/safe/credentials/config.ts",
                &workspace,
                Some(&home),
                false,
            )
            .reason_code,
            "sensitive_basename"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn source_classifier_allows_workflow_and_sibling_git_source() {
        let root = fixture_root("external");
        let home = root.join("home");
        let workspace = home.join("workspace");
        let workflow = workspace.join(".github/workflows/publish.yml");
        fs::create_dir_all(workflow.parent().unwrap()).unwrap();
        fs::write(&workflow, "jobs: {}\n").unwrap();
        let sibling = home.join("sibling");
        let sibling_file = sibling.join("src/main.py");
        fs::create_dir_all(sibling_file.parent().unwrap()).unwrap();
        fs::create_dir_all(sibling.join(".git")).unwrap();
        fs::write(&sibling_file, "value = 1\n").unwrap();

        assert!(
            classify_source_path(
                ".github/workflows/publish.yml",
                &workspace,
                Some(&home),
                false
            )
            .allowed
        );
        let external = classify_source_path(
            sibling_file.to_str().unwrap(),
            &workspace,
            Some(&home),
            true,
        );
        assert!(external.allowed);
        assert_eq!(external.reason_code, "external_source_path");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn source_classifier_rejects_sensitive_external_filename_without_substring_false_positive() {
        let root = fixture_root("external-sensitive");
        let home = root.join("home");
        let workspace = home.join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let sibling = home.join("sibling");
        fs::create_dir_all(sibling.join(".git")).unwrap();
        let sensitive = sibling.join("auth_token.ts");
        let benign = sibling.join("authentication.ts");
        fs::write(&sensitive, "value = 1\n").unwrap();
        fs::write(&benign, "value = 1\n").unwrap();

        assert_eq!(
            classify_source_path(sensitive.to_str().unwrap(), &workspace, Some(&home), true)
                .reason_code,
            "sensitive_basename"
        );
        assert!(
            classify_source_path(benign.to_str().unwrap(), &workspace, Some(&home), true).allowed
        );
        let _ = fs::remove_dir_all(root);
    }
}
