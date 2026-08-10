#![forbid(unsafe_code)]

use guard_rules::MAX_SCAN_BYTES;
use sha2::{Digest, Sha256};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: Option<u64>,
    pub ino: Option<u64>,
    pub size: u64,
    pub mtime_ns: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureRead {
    pub bytes: Vec<u8>,
    pub identity: FileIdentity,
    pub sha256: String,
}

#[derive(Debug, Error)]
pub enum SecureReadError {
    #[error("unresolved_path")]
    UnresolvedPath,
    #[error("symlink_in_path")]
    SymlinkInPath,
    #[error("not_regular_file")]
    NotRegularFile,
    #[error("source_file_too_large")]
    TooLarge,
    #[error("read_failed")]
    ReadFailed,
    #[error("source_stat_changed")]
    Changed,
}

pub fn resolve_candidate(target: &str, cwd: Option<&Path>, home: &Path) -> Result<PathBuf, SecureReadError> {
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
    let path = PathBuf::from(stripped);
    if path.is_absolute() {
        return Ok(path);
    }
    Ok(cwd.unwrap_or_else(|| Path::new(".")).join(path))
}

pub fn contains_symlink_component(path: &Path) -> bool {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => continue,
            Component::ParentDir => current.push(".."),
            Component::Normal(part) => current.push(part),
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
    FileIdentity { dev, ino, size: metadata.len(), mtime_ns }
}

fn secure_open(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

pub fn read_bounded(path: &Path, max_bytes: usize) -> Result<SecureRead, SecureReadError> {
    let max_bytes = max_bytes.min(MAX_SCAN_BYTES);
    if contains_symlink_component(path) {
        return Err(SecureReadError::SymlinkInPath);
    }
    let mut file = secure_open(path).map_err(|_| SecureReadError::ReadFailed)?;
    let before_metadata = file.metadata().map_err(|_| SecureReadError::ReadFailed)?;
    if !before_metadata.is_file() {
        return Err(SecureReadError::NotRegularFile);
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
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(SecureRead { bytes, identity: after, sha256: hex::encode(hasher.finalize()) })
}

pub fn sensitive_path_family(path: &Path) -> Option<(&'static str, &'static str)> {
    let normalized = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    let parts: Vec<&str> = normalized.split('/').filter(|part| !part.is_empty()).collect();
    let basename = parts.last().copied().unwrap_or_default();
    if basename == ".env" || basename.starts_with(".env.") {
        return Some(("local .env file", "critical"));
    }
    let direct = [
        (".npmrc", "npm registry credentials", "high"),
        (".pypirc", "Python package credentials", "high"),
        (".netrc", "netrc credentials", "high"),
        (".git-credentials", "Git credential store", "high"),
        ("terraform.tfvars", "Terraform variable secrets", "high"),
        ("private-key.pem", "wallet/private-key file", "critical"),
        ("private.key", "wallet/private-key file", "critical"),
        ("wallet.key", "wallet/private-key file", "critical"),
    ];
    if let Some((_, family, sensitivity)) = direct.iter().find(|(name, _, _)| *name == basename) {
        return Some((*family, *sensitivity));
    }
    if basename.contains("private-key") || basename.contains("private_key") || basename.contains("wallet-key") || basename.contains("wallet_key") {
        return Some(("wallet/private-key file", "critical"));
    }
    if parts.windows(2).any(|window| window == [".aws", "credentials"]) {
        return Some(("AWS shared credentials file", "high"));
    }
    if parts.windows(2).any(|window| window == [".aws", "config"]) {
        return Some(("AWS shared config file", "high"));
    }
    if parts.windows(2).any(|window| window == [".docker", "config.json"]) {
        return Some(("Docker client config", "high"));
    }
    if parts.windows(2).any(|window| window == [".kube", "config"]) {
        return Some(("Kubernetes config", "high"));
    }
    if parts.contains(&".gnupg") {
        return Some(("GnuPG key material", "high"));
    }
    if let Some(index) = parts.iter().position(|part| *part == ".ssh") {
        if parts.get(index + 1).is_some_and(|name| matches!(*name, "id_rsa" | "id_ed25519" | "id_ecdsa")) {
            return Some(("SSH private key", "critical"));
        }
        if parts.get(index + 1).is_some_and(|name| *name == "config") {
            return Some(("SSH client config", "high"));
        }
    }
    None
}

pub fn source_like(path: &Path) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    let parts: Vec<&str> = normalized.split('/').filter(|part| !part.is_empty()).collect();
    if parts.iter().any(|part| matches!(*part, ".env" | ".ssh" | ".gnupg" | "credentials" | "secrets" | "tokens")) {
        return false;
    }
    let source_parts = ["src", "lib", "app", "packages", "tests", "test", "docs", "spec", "examples", ".github"];
    if parts.iter().any(|part| source_parts.contains(part)) {
        return true;
    }
    let suffix = path.extension().and_then(|value| value.to_str()).unwrap_or_default().to_ascii_lowercase();
    matches!(suffix.as_str(), "py" | "pyi" | "js" | "jsx" | "ts" | "tsx" | "rs" | "go" | "java" | "kt" | "rb" | "php" | "swift" | "c" | "h" | "cc" | "cpp" | "hpp" | "md" | "mdx" | "rst" | "txt" | "toml" | "yaml" | "yml" | "json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn bounded_read_hashes_regular_file() {
        let dir = std::env::temp_dir().join(format!("guard-secure-fs-{}", std::process::id()));
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

    #[test]
    fn sensitive_paths_are_classified() {
        assert_eq!(sensitive_path_family(Path::new("/home/u/.aws/credentials")).unwrap().0, "AWS shared credentials file");
        assert_eq!(sensitive_path_family(Path::new(".env.local")).unwrap().1, "critical");
    }
}
