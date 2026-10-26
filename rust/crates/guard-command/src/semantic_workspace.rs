//! Bounded workspace capture, staging, drift detection, tool-path
//! sanitising and exclusive atomic promotion for the structured
//! workspace-write operations.
//!
//! Capture mirrors the retired Python workspace snapshot: `.git` and `.guard`
//! state is skipped, protected content, symlinks and hard-linked files make the
//! whole workspace ineligible, and file, byte, entry and time budgets bound the
//! walk. Staging copies exactly the captured files, so nothing protected ever
//! reaches the contained tool.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::fcntl::{openat, renameat, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::{unlinkat, UnlinkatFlags};
use sha2::{Digest, Sha256};

use crate::shell_secret_read_support::classify_secret_path;

const MAX_FILES: usize = 20_000;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 50_000;
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TOOL_PATH_ENTRIES: usize = 64;
const MAX_TOOL_PATH_ENTRY_BYTES: usize = 4096;
const DEFAULT_TOOL_PATH: &[&str] = &["/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"];
const SKIPPED_STATE_NAMES: &[&str] = &[".git", ".guard"];
const PROTECTED_NAMES: &[&str] = &[
    ".aws",
    ".azure",
    ".docker",
    ".gnupg",
    ".kube",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh",
    ".vault-token",
    "auth.json",
    "credentials",
    "credentials.json",
    "guard-home",
    "secrets.json",
];
const PROTECTED_SUFFIXES: &[&str] = &[".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"];
const SSH_PRIVATE_KEY_NAMES: &[&str] = &["id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"];
const SOURCE_SUFFIXES: &[&str] = &[".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"];
const PROTECTED_WORDS: &[&str] = &[
    "credential",
    "credentials",
    "passwd",
    "password",
    "passwords",
    "secret",
    "secrets",
    "token",
    "tokens",
];
const PROTECTED_WORD_PAIRS: &[(&str, &str)] =
    &[("api", "key"), ("private", "key"), ("service", "account")];

/// Digest of every eligible workspace file; two captures are equal only when
/// no eligible file was added, removed or changed between them.
#[derive(Debug)]
pub(crate) struct WorkspaceCapture {
    pub(crate) digest: String,
}

/// Removes the staged workspace when dropped.
#[derive(Debug)]
pub(crate) struct StageGuard(pub(crate) PathBuf);

impl Drop for StageGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Walk<'a> {
    root: &'a Path,
    files: Vec<(String, String)>,
    exclusions: Vec<(String, &'static str)>,
    total_bytes: u64,
    entries: usize,
    started: Instant,
}

fn words(part: &str) -> Vec<String> {
    let chars: Vec<char> = part.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut current = String::new();
    for (index, character) in chars.iter().enumerate() {
        if !character.is_ascii_alphanumeric() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }
        if !current.is_empty() {
            let previous = chars[index - 1];
            let lower_then_upper = (previous.is_ascii_lowercase() || previous.is_ascii_digit())
                && character.is_ascii_uppercase();
            let acronym_end = previous.is_ascii_uppercase()
                && character.is_ascii_uppercase()
                && chars
                    .get(index + 1)
                    .is_some_and(|next| next.is_ascii_lowercase());
            if lower_then_upper || acronym_end {
                out.push(std::mem::take(&mut current));
            }
        }
        current.push(character.to_ascii_lowercase());
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn has_protected_words(part: &str) -> bool {
    let parts = words(part);
    parts
        .iter()
        .any(|word| PROTECTED_WORDS.contains(&word.as_str()))
        || parts.windows(2).any(|pair| {
            PROTECTED_WORD_PAIRS
                .iter()
                .any(|(left, right)| pair[0] == *left && pair[1] == *right)
        })
}

fn is_protected_part(part: &str, include_generic_words: bool) -> bool {
    let lowered = part.to_lowercase();
    PROTECTED_NAMES.contains(&lowered.as_str())
        || SSH_PRIVATE_KEY_NAMES.contains(&lowered.as_str())
        || lowered.starts_with(".env")
        || PROTECTED_SUFFIXES
            .iter()
            .any(|suffix| lowered.ends_with(suffix))
        || (include_generic_words && has_protected_words(part))
}

/// Protect dependency content; exempt only generic words in package
/// directory names.
fn is_protected(relative: &Path, is_directory: bool) -> bool {
    let text = relative.to_string_lossy();
    if classify_secret_path(&text, None, None).is_some() {
        return true;
    }
    let parts: Vec<String> = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    let mut package_directory_expected = false;
    let mut in_dependency_tree = false;
    for (index, part) in parts.iter().enumerate() {
        if part.to_lowercase() == "node_modules" {
            package_directory_expected = true;
            in_dependency_tree = true;
            continue;
        }
        let directory_component = index + 1 < parts.len() || is_directory;
        let package_directory = package_directory_expected && directory_component;
        let skip_generic_words = package_directory
            || (in_dependency_tree
                && !directory_component
                && SOURCE_SUFFIXES
                    .iter()
                    .any(|suffix| part.to_lowercase().ends_with(suffix)));
        if is_protected_part(part, !skip_generic_words) {
            return true;
        }
        if package_directory_expected {
            package_directory_expected = package_directory && part.starts_with('@');
        }
    }
    false
}

fn copy_and_hash(
    source: &Path,
    destination: Option<&Path>,
    metadata: &fs::Metadata,
) -> Result<String, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)
        .map_err(|_| "workspace_stage_copy_failed".to_owned())?;
    let opened = file
        .metadata()
        .map_err(|_| "workspace_stage_copy_failed".to_owned())?;
    if !opened.is_file() || opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err("workspace_stage_changed".to_owned());
    }
    let mut output = match destination {
        Some(path) => Some(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode((metadata.mode() & 0o777) | 0o200)
                .open(path)
                .map_err(|_| "workspace_stage_copy_failed".to_owned())?,
        ),
        None => None,
    };
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut copied: u64 = 0;
    let mut reader = (&mut file).take(opened.len() + 1);
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| "workspace_stage_copy_failed".to_owned())?;
        if read == 0 {
            break;
        }
        copied += read as u64;
        hasher.update(&buffer[..read]);
        if let Some(out) = output.as_mut() {
            out.write_all(&buffer[..read])
                .map_err(|_| "workspace_stage_copy_failed".to_owned())?;
        }
    }
    if copied != opened.len() {
        return Err("workspace_stage_changed".to_owned());
    }
    Ok(hex::encode(hasher.finalize()))
}

fn walk_directory(
    state: &mut Walk<'_>,
    directory: &Path,
    stage_directory: Option<&Path>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(directory)
        .map_err(|_| "workspace_stage_read_failed".to_owned())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "workspace_stage_read_failed".to_owned())?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        state.entries += 1;
        if state.entries > MAX_ENTRIES || state.started.elapsed() > DISCOVERY_TIMEOUT {
            return Err("workspace_stage_budget".to_owned());
        }
        let path = entry.path();
        let relative = path
            .strip_prefix(state.root)
            .map_err(|_| "workspace_stage_read_failed".to_owned())?
            .to_path_buf();
        let relative_text = relative
            .to_str()
            .ok_or_else(|| "workspace_stage_non_utf8".to_owned())?
            .to_owned();
        let lowered_name = entry.file_name().to_string_lossy().to_lowercase();
        if SKIPPED_STATE_NAMES.contains(&lowered_name.as_str()) {
            state.exclusions.push((relative_text, "protected-state"));
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|_| "workspace_stage_read_failed".to_owned())?;
        if is_protected(&relative, file_type.is_dir()) {
            return Err("workspace_stage_protected".to_owned());
        }
        if file_type.is_dir()
            && lowered_name == ".bin"
            && relative
                .components()
                .any(|part| part.as_os_str().to_string_lossy().to_lowercase() == "node_modules")
        {
            state.exclusions.push((relative_text, "package-bin-links"));
            continue;
        }
        if file_type.is_symlink() {
            return Err("workspace_stage_symlink".to_owned());
        }
        let child_stage = stage_directory.map(|dir| dir.join(entry.file_name()));
        if file_type.is_dir() {
            if let Some(child) = &child_stage {
                fs::create_dir(child).map_err(|_| "workspace_stage_create_failed".to_owned())?;
            }
            walk_directory(state, &path, child_stage.as_deref())?;
            continue;
        }
        if !file_type.is_file() {
            return Err("workspace_stage_entry_unsupported".to_owned());
        }
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "workspace_stage_read_failed".to_owned())?;
        if metadata.nlink() != 1 {
            return Err("workspace_stage_hardlink".to_owned());
        }
        state.total_bytes += metadata.len();
        if state.files.len() >= MAX_FILES || state.total_bytes > MAX_BYTES {
            return Err("workspace_stage_too_large".to_owned());
        }
        let digest = copy_and_hash(&path, child_stage.as_deref(), &metadata)?;
        state.files.push((relative_text, digest));
    }
    Ok(())
}

fn capture(root: &Path, stage: Option<&Path>) -> Result<WorkspaceCapture, String> {
    let mut state = Walk {
        root,
        files: Vec::new(),
        exclusions: Vec::new(),
        total_bytes: 0,
        entries: 0,
        started: Instant::now(),
    };
    walk_directory(&mut state, root, stage)?;
    state.files.sort();
    state.exclusions.sort();
    let mut hasher = Sha256::new();
    for (path, digest) in &state.files {
        hasher.update(format!("f\0{path}\0{digest}\n").as_bytes());
    }
    for (path, reason) in &state.exclusions {
        hasher.update(format!("x\0{path}\0{reason}\n").as_bytes());
    }
    Ok(WorkspaceCapture {
        digest: format!("sha256:{}", hex::encode(hasher.finalize())),
    })
}

/// Capture the eligible workspace without staging it.
pub(crate) fn capture_workspace(root: &Path) -> Result<WorkspaceCapture, String> {
    capture(root, None)
}

/// Copy exactly the eligible workspace files into a private stage under the
/// guard home and return the capture they were copied from.
pub(crate) fn stage_workspace(
    workspace: &Path,
    guard_home: &Path,
    run_id: &str,
) -> Result<(StageGuard, WorkspaceCapture), String> {
    let parent = guard_home.join("containment");
    fs::create_dir_all(&parent).map_err(|_| "workspace_stage_create_failed".to_owned())?;
    let parent = parent
        .canonicalize()
        .map_err(|_| "workspace_stage_create_failed".to_owned())?;
    if parent.starts_with(workspace) {
        return Err("workspace_stage_inside_workspace".to_owned());
    }
    let stage = parent.join(format!("{run_id}-workspace"));
    fs::create_dir(&stage).map_err(|_| "workspace_stage_create_failed".to_owned())?;
    let guard = StageGuard(stage.clone());
    let captured = capture(workspace, Some(&stage))?;
    Ok((guard, captured))
}

/// Keep only absolute, bounded search directories that are not inside any of
/// `excluded_roots` (a planted tool in the workspace must never be resolved).
pub(crate) fn sanitize_tool_path(raw: Option<&str>, excluded_roots: &[&Path]) -> String {
    let mut kept: Vec<String> = Vec::new();
    for entry in raw.unwrap_or_default().split(':') {
        if kept.len() >= MAX_TOOL_PATH_ENTRIES {
            break;
        }
        let candidate = Path::new(entry);
        if entry.is_empty()
            || entry.len() > MAX_TOOL_PATH_ENTRY_BYTES
            || !candidate.is_absolute()
            || kept.iter().any(|existing| existing == entry)
        {
            continue;
        }
        let resolved = candidate
            .canonicalize()
            .unwrap_or_else(|_| candidate.to_path_buf());
        if excluded_roots
            .iter()
            .any(|root| resolved.starts_with(root) || candidate.starts_with(root))
        {
            continue;
        }
        kept.push(entry.to_owned());
    }
    if kept.is_empty() {
        return DEFAULT_TOOL_PATH.join(":");
    }
    kept.join(":")
}

/// Replace `target` with `content` through an exclusively created, randomly
/// named temporary file opened relative to the target's directory without
/// following links. An existing regular target keeps its permission bits.
pub(crate) fn write_atomic(
    target: &Path,
    content: &[u8],
    explicit_mode: Option<u32>,
) -> Result<(), String> {
    let parent = target.parent().ok_or_else(|| "write_parent".to_owned())?;
    let name = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "write_failed".to_owned())?;
    let existing_mode = match fs::symlink_metadata(target) {
        Ok(metadata) if metadata.is_file() => Some(metadata.mode() & 0o7777),
        Ok(_) => return Err("write_target_not_regular".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("write_failed".to_owned()),
    };
    let mode = explicit_mode.or(existing_mode).unwrap_or(0o644) & 0o7777;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|_| "write_parent".to_owned())?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| "write_failed".to_owned())?;
    let temp_name = format!(".{name}.{}.contained.tmp", hex::encode(random));
    let descriptor = openat(
        &directory,
        temp_name.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| "write_failed".to_owned())?;
    let mut file = File::from(descriptor);
    let outcome = (|| -> Result<(), String> {
        file.write_all(content)
            .map_err(|_| "write_failed".to_owned())?;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| "write_failed".to_owned())?;
        file.sync_all().map_err(|_| "write_failed".to_owned())?;
        renameat(&directory, temp_name.as_str(), &directory, name)
            .map_err(|_| "write_failed".to_owned())?;
        // Persist the rename. The replacement is already committed, so a
        // failed directory sync must not turn into a reported failure.
        let _ = directory.sync_all();
        Ok(())
    })();
    if outcome.is_err() {
        let _ = unlinkat(&directory, temp_name.as_str(), UnlinkatFlags::NoRemoveDir);
    }
    outcome
}

#[cfg(test)]
#[path = "semantic_workspace_tests.rs"]
mod tests;
