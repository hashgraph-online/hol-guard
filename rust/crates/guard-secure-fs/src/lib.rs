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

const SOURCE_INSPECTION_PARTS: &[&str] = &[
    "__tests__",
    "app",
    "constants",
    "dashboard",
    "docs",
    "lib",
    "packages",
    "scripts",
    "src",
    "test",
    "tests",
    "workers",
];
const SOURCE_EXTENSIONS: &[&str] = &[
    "c", "cc", "cpp", "css", "go", "h", "hpp", "html", "java", "js", "jsx", "json", "md", "mjs",
    "py", "rs", "sh", "toml", "ts", "tsx", "yaml", "yml",
];
const BENIGN_SOURCE_DOTFILES: &[&str] = &[".nvmrc", ".worktrees"];
const SENSITIVE_SEARCH_BASENAMES: &[&str] = &[
    ".aws",
    ".docker",
    ".env",
    ".git-credentials",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh",
    "credentials",
    "id_rsa",
];
const EXTERNAL_SENSITIVE_PARTS: &[&str] = &[
    ".aws",
    ".docker",
    ".env",
    ".git-credentials",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh",
    "auth",
    "authorization",
    "credential",
    "credentials",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "passwd",
    "password",
    "private-key",
    "private_key",
    "secret",
    "secrets",
    "token",
    "tokens",
];
const KNOWN_SKILL_DOC_ROOTS: &[&str] = &[
    ".codex/superpowers/skills",
    ".codex/skills",
    ".agents/skills",
    ".claude/skills",
];

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
    #[error("source_file_too_large")]
    TooLarge,
    #[error("read_failed")]
    ReadFailed,
    #[error("source_stat_changed")]
    Changed,
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
    FileIdentity {
        dev,
        ino,
        size: metadata.len(),
        mtime_ns,
    }
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
    Ok(SecureRead {
        bytes,
        identity: after,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn lowered_parts(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

fn hidden_parts_allowed(parts: &[String]) -> bool {
    let hidden: Vec<&str> = parts
        .iter()
        .map(String::as_str)
        .filter(|part| part.starts_with('.'))
        .collect();
    if hidden.is_empty()
        || hidden
            .iter()
            .all(|part| BENIGN_SOURCE_DOTFILES.contains(part))
    {
        return true;
    }
    let workflow_prefix = parts
        .windows(2)
        .any(|window| window[0] == ".github" && window[1] == "workflows");
    workflow_prefix && hidden == [".github"]
}

fn sensitive_external_filename(path: &Path) -> bool {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if EXTERNAL_SENSITIVE_PARTS.contains(&filename.as_str())
        || EXTERNAL_SENSITIVE_PARTS.contains(&stem.as_str())
    {
        return true;
    }
    stem.replace(['-', '.'], "_")
        .split('_')
        .any(|token| !token.is_empty() && EXTERNAL_SENSITIVE_PARTS.contains(&token))
}

fn source_shape_allowed(path: &Path, parts: &[String]) -> bool {
    if parts
        .iter()
        .any(|part| SOURCE_INSPECTION_PARTS.contains(&part.as_str()))
    {
        return true;
    }
    if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| {
            let lowered = name.to_ascii_lowercase();
            BENIGN_SOURCE_DOTFILES.contains(&lowered.as_str())
        })
    {
        return true;
    }
    path.extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|suffix| SOURCE_EXTENSIONS.contains(&suffix.as_str()))
}

fn canonical_dir(path: &Path) -> Option<PathBuf> {
    let canonical = fs::canonicalize(path).ok()?;
    canonical.is_dir().then_some(canonical)
}

fn immediate_sibling_git_checkout(path: &Path, workspace: &Path) -> bool {
    let parent = match workspace.parent() {
        Some(parent) => parent,
        None => return false,
    };
    let relative = match path.strip_prefix(parent) {
        Ok(relative) => relative,
        Err(_) => return false,
    };
    let Some(first) = relative.components().next() else {
        return false;
    };
    let Component::Normal(first) = first else {
        return false;
    };
    let checkout = parent.join(first);
    if checkout == workspace {
        return false;
    }
    let marker = checkout.join(".git");
    match fs::symlink_metadata(&marker) {
        Ok(metadata) => {
            !metadata.file_type().is_symlink() && (metadata.is_file() || metadata.is_dir())
        }
        Err(_) => false,
    }
}

fn known_skill_doc_path(target: &str, home: &Path) -> Option<PathBuf> {
    if target
        .chars()
        .any(|character| matches!(character, '$' | '`' | '<' | '>' | '|' | ';' | '&'))
    {
        return None;
    }
    if let Some(skill_name) = target.strip_prefix("skill://") {
        let skill_name = skill_name.trim().trim_matches(['\'', '"']);
        let candidate = Path::new(skill_name);
        if skill_name.is_empty()
            || candidate.is_absolute()
            || candidate
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return None;
        }
        for root in KNOWN_SKILL_DOC_ROOTS {
            let skill_dir = home.join(root).join(candidate);
            let skill_file = skill_dir.join("SKILL.md");
            let Ok(real_dir) = fs::canonicalize(&skill_dir) else {
                continue;
            };
            let Ok(real_file) = fs::canonicalize(&skill_file) else {
                continue;
            };
            if real_file.is_file() && real_file.starts_with(&real_dir) {
                return Some(real_file);
            }
        }
        return None;
    }

    let lexical = resolve_candidate(target, None, home).ok()?;
    for root in KNOWN_SKILL_DOC_ROOTS {
        let lexical_root = home.join(root);
        if !lexical.starts_with(&lexical_root) || contains_symlink_component(&lexical) {
            continue;
        }
        if let Ok(real) = fs::canonicalize(&lexical) {
            return Some(real);
        }
    }
    None
}

pub fn classify_source_path(
    target: &str,
    cwd: &Path,
    home: Option<&Path>,
    allow_external: bool,
) -> SourcePathDecision {
    let stripped = target.trim().trim_matches(['\'', '"']);
    if stripped.is_empty() {
        return SourcePathDecision::deny("empty_path");
    }
    if let Some(home) = home {
        if let Some(skill_path) = known_skill_doc_path(stripped, home) {
            return SourcePathDecision::allow("known_skill_doc_path", skill_path);
        }
        let safety = home.join(".hol-support").join("SAFETY.md");
        if (stripped == "~/.hol-support/SAFETY.md" || Path::new(stripped) == safety)
            && fs::symlink_metadata(&safety)
                .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        {
            if let Ok(real) = fs::canonicalize(safety) {
                return SourcePathDecision::allow("guard_safety_doc_path", real);
            }
        }
    }
    if stripped
        .chars()
        .any(|character| matches!(character, '*' | '?' | '{' | '}'))
    {
        return SourcePathDecision::deny("glob_pattern");
    }

    let Ok(workspace) = fs::canonicalize(cwd) else {
        return SourcePathDecision::deny("unresolved_path");
    };
    let external_requested = Path::new(stripped).is_absolute() || stripped.starts_with("~/");
    let home_for_resolution = home.unwrap_or_else(|| Path::new(""));
    let Ok(lexical) = resolve_candidate(stripped, Some(&workspace), home_for_resolution) else {
        return SourcePathDecision::deny("unresolved_path");
    };

    if contains_symlink_component(&lexical) {
        return SourcePathDecision::deny("symlink_in_path");
    }
    let Ok(candidate) = fs::canonicalize(&lexical) else {
        return SourcePathDecision::deny("external_target_not_readable");
    };

    let inside_workspace = candidate.starts_with(&workspace);
    if !inside_workspace {
        if !allow_external || !external_requested {
            return SourcePathDecision::deny("absolute_path_outside_workspace");
        }
        let Some(home) = home.and_then(canonical_dir) else {
            return SourcePathDecision::deny("external_home_unavailable");
        };
        if !candidate.starts_with(&home) {
            return SourcePathDecision::deny("external_target_outside_home");
        }
        if !immediate_sibling_git_checkout(&candidate, &workspace) {
            return SourcePathDecision::deny("external_target_not_sibling_git_checkout");
        }
        let parts = lowered_parts(&candidate);
        if parts
            .iter()
            .any(|part| EXTERNAL_SENSITIVE_PARTS.contains(&part.as_str()))
            || sensitive_external_filename(&candidate)
        {
            return SourcePathDecision::deny("sensitive_basename");
        }
        if !hidden_parts_allowed(&parts) {
            return SourcePathDecision::deny("unsafe_hidden_dir");
        }
        if !source_shape_allowed(Path::new(stripped), &parts) {
            return SourcePathDecision::deny("not_source_like");
        }
        return SourcePathDecision::allow("external_source_path", candidate);
    }

    let relative = match candidate.strip_prefix(&workspace) {
        Ok(relative) => relative,
        Err(_) => return SourcePathDecision::deny("resolved_outside_workspace"),
    };
    let parts = lowered_parts(relative);
    if parts.is_empty() {
        return SourcePathDecision::deny("empty_resolved_path");
    }
    if parts
        .iter()
        .any(|part| SENSITIVE_SEARCH_BASENAMES.contains(&part.as_str()))
    {
        return SourcePathDecision::deny("sensitive_basename");
    }
    if !hidden_parts_allowed(&parts) {
        return SourcePathDecision::deny("unsafe_hidden_dir");
    }
    if !source_shape_allowed(relative, &parts) {
        return SourcePathDecision::deny("not_source_like");
    }
    let reason = if parts
        .first()
        .is_some_and(|part| SOURCE_INSPECTION_PARTS.contains(&part.as_str()))
    {
        "source_prefix"
    } else if parts
        .iter()
        .any(|part| SOURCE_INSPECTION_PARTS.contains(&part.as_str()))
    {
        "source_inspection_part"
    } else if relative
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| {
            let lowered = name.to_ascii_lowercase();
            BENIGN_SOURCE_DOTFILES.contains(&lowered.as_str())
        })
    {
        "benign_source_dotfile"
    } else {
        "source_extension"
    };
    SourcePathDecision::allow(reason, candidate)
}

pub fn sensitive_path_family(path: &Path) -> Option<(&'static str, &'static str)> {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let parts: Vec<&str> = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
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
    if basename.contains("private-key")
        || basename.contains("private_key")
        || basename.contains("wallet-key")
        || basename.contains("wallet_key")
    {
        return Some(("wallet/private-key file", "critical"));
    }
    if parts
        .windows(2)
        .any(|window| window == [".aws", "credentials"])
    {
        return Some(("AWS shared credentials file", "high"));
    }
    if parts.windows(2).any(|window| window == [".aws", "config"]) {
        return Some(("AWS shared config file", "high"));
    }
    if parts
        .windows(2)
        .any(|window| window == [".docker", "config.json"])
    {
        return Some(("Docker client config", "high"));
    }
    if parts.windows(2).any(|window| window == [".kube", "config"]) {
        return Some(("Kubernetes config", "high"));
    }
    if parts.contains(&".gnupg") {
        return Some(("GnuPG key material", "high"));
    }
    if let Some(index) = parts.iter().position(|part| *part == ".ssh") {
        if parts
            .get(index + 1)
            .is_some_and(|name| matches!(*name, "id_rsa" | "id_ed25519" | "id_ecdsa"))
        {
            return Some(("SSH private key", "critical"));
        }
        if parts.get(index + 1).is_some_and(|name| *name == "config") {
            return Some(("SSH client config", "high"));
        }
    }
    None
}

pub fn source_like(path: &Path) -> bool {
    let parts = lowered_parts(path);
    if parts
        .iter()
        .any(|part| SENSITIVE_SEARCH_BASENAMES.contains(&part.as_str()))
        || !hidden_parts_allowed(&parts)
    {
        return false;
    }
    source_shape_allowed(path, &parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("guard-secure-fs-{name}-{}", std::process::id()))
    }

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
            "external_target_not_readable"
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
