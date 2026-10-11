//! Complete bounded workspace snapshots for result-only contained commands.
//!
//! Faithful port of `runtime/workspace_snapshot_inputs.py`.

use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use nix::dir::Dir;
use nix::fcntl::{openat, AtFlags, OFlag};
use nix::sys::stat::{fstatat, Mode, SFlag};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::common::{canonical_workspace, framed_digest};
use super::contract::Input;
use crate::shell_secret_read_support::classify_secret_path;

const MAX_FILES: usize = 20_000;
/// Open directory handles are bounded by depth, not breadth.
const MAX_DEPTH: usize = 128;
const MAX_BYTES: u64 = 256 * 1024 * 1024;
pub(super) const MAX_ENTRIES: usize = 50_000;
pub(super) const DISCOVERY_TIMEOUT_SECONDS: f64 = 5.0;
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
const SSH_PRIVATE_KEY_NAMES: &[&str] = &["id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"];

/// Entry and wall-clock discovery budget shared by one tree walk.
pub(super) struct Budget {
    started_at: Instant,
    pub(super) visited: usize,
}

impl Budget {
    pub(super) fn new() -> Self {
        Self {
            started_at: Instant::now(),
            visited: 0,
        }
    }

    pub(super) fn check(&self, entry_message: &str, time_message: &str) -> Result<(), String> {
        if self.visited > MAX_ENTRIES {
            return Err(entry_message.to_owned());
        }
        if self.started_at.elapsed().as_secs_f64() > DISCOVERY_TIMEOUT_SECONDS {
            return Err(time_message.to_owned());
        }
        Ok(())
    }
}

/// One directory being walked depth-first, holding its handle and unvisited names.
struct Frame {
    path: PathBuf,
    handle: Dir,
    names: std::vec::IntoIter<CString>,
}

/// Kind of a directory entry, read without following links.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

fn entry_kind(directory: &Dir, name: &CStr) -> Result<EntryKind, String> {
    let stat = fstatat(directory.as_fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|error| error.to_string())?;
    let kind = SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT;
    Ok(if kind == SFlag::S_IFDIR {
        EntryKind::Directory
    } else if kind == SFlag::S_IFREG {
        EntryKind::File
    } else if kind == SFlag::S_IFLNK {
        EntryKind::Symlink
    } else {
        EntryKind::Other
    })
}

/// Open one child relative to its already-verified parent handle, never
/// following a link, so a swapped path component cannot redirect discovery.
fn open_child(directory: &Dir, name: &CStr, as_directory: bool) -> Result<File, String> {
    let mut flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK;
    if as_directory {
        flags |= OFlag::O_DIRECTORY;
    }
    let descriptor: OwnedFd = openat(directory.as_fd(), name, flags, Mode::empty())
        .map_err(|_| "workspace snapshot discovery failed".to_owned())?;
    Ok(File::from(descriptor))
}

fn open_root(canonical: &Path) -> Result<Dir, String> {
    let failed = || "workspace snapshot discovery failed".to_owned();
    let expected = fs::symlink_metadata(canonical).map_err(|_| failed())?;
    let root = Dir::open(
        canonical,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_DIRECTORY,
        Mode::empty(),
    )
    .map_err(|_| failed())?;
    let opened = File::from(root.as_fd().try_clone_to_owned().map_err(|_| failed())?)
        .metadata()
        .map_err(|_| failed())?;
    if (opened.dev(), opened.ino()) != (expected.dev(), expected.ino()) {
        return Err("workspace directory identity changed during discovery".to_owned());
    }
    Ok(root)
}

fn bounded_entries(directory: &mut Dir, budget: &mut Budget) -> Result<Vec<CString>, String> {
    let failed = || "workspace snapshot discovery failed".to_owned();
    let mut names = Vec::new();
    for entry in directory.iter() {
        let entry = entry.map_err(|_| failed())?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        budget.visited += 1;
        budget.check(
            "workspace discovery entry budget exceeded",
            "workspace discovery time budget exceeded",
        )?;
        names.push(name.to_owned());
    }
    Ok(names)
}

fn snapshot_file_digest(mut file: File, before: &Metadata) -> Result<String, String> {
    let identity = |metadata: &Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.size(),
            metadata.mtime(),
            metadata.mtime_nsec(),
        )
    };
    let changed = "workspace file identity changed during discovery";
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut consumed: u64 = 0;
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        consumed += count as u64;
        if consumed > MAX_BYTES {
            return Err("workspace snapshot exceeds containment identity budget".to_owned());
        }
        digest.update(&buffer[..count]);
    }
    let after = file.metadata().map_err(|error| error.to_string())?;
    if identity(&after) != identity(before) {
        return Err(changed.to_owned());
    }
    Ok(hex::encode(digest.finalize()))
}

fn components(relative: &Path) -> Vec<String> {
    relative
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect()
}

fn posix(relative: &Path) -> String {
    components(relative).join("/")
}

/// Capture every eligible workspace file or reject the command for review.
///
/// Returns the framed snapshot digest and the inputs sorted by snapshot path.
pub(crate) fn complete_workspace_snapshot(
    workspace: &Path,
    exclude_protected: bool,
) -> Result<(String, Vec<Input>), String> {
    let canonical = canonical_workspace(workspace)?;
    let mut captured: Vec<(String, String, Input)> = Vec::new();
    let mut exclusions: Vec<(String, &'static str)> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut budget = Budget::new();
    let mut root = open_root(&canonical)?;
    let root_names = bounded_entries(&mut root, &mut budget)?;
    let mut stack = vec![Frame {
        path: canonical.clone(),
        handle: root,
        names: root_names.into_iter(),
    }];
    while let Some(frame) = stack.last_mut() {
        let Some(name) = frame.names.next() else {
            stack.pop();
            continue;
        };
        {
            let handle = &frame.handle;
            let directory = frame.path.clone();
            let os_name = OsStr::from_bytes(name.to_bytes());
            let path = directory.join(os_name);
            let relative = path
                .strip_prefix(&canonical)
                .map_err(|_| "workspace snapshot discovery failed".to_owned())?;
            let relative_text = posix(relative);
            let lowered: Vec<String> = components(relative)
                .iter()
                .map(|part| part.to_lowercase())
                .collect();
            let kind = entry_kind(handle, &name)?;
            let is_directory = kind == EntryKind::Directory;
            if lowered
                .iter()
                .any(|part| SKIPPED_STATE_NAMES.contains(&part.as_str()))
            {
                exclusions.push((relative_text, "protected-state"));
                continue;
            }
            if is_protected(relative, is_directory) {
                if exclude_protected {
                    exclusions.push((relative_text, "protected-content"));
                    continue;
                }
                return Err("protected workspace content requires Guard review".to_owned());
            }
            if is_directory
                && os_name == OsStr::new(".bin")
                && lowered.iter().any(|part| part == "node_modules")
            {
                exclusions.push((relative_text, "package-bin-links"));
                continue;
            }
            match kind {
                EntryKind::Symlink => {
                    return Err("workspace snapshot cannot contain symlinks".to_owned());
                }
                EntryKind::Other => {
                    return Err("workspace snapshot inputs must be regular files".to_owned());
                }
                EntryKind::Directory => {
                    let child = open_child(handle, &name, true)?;
                    if !child.metadata().is_ok_and(|metadata| metadata.is_dir()) {
                        return Err(
                            "workspace directory identity changed during discovery".to_owned()
                        );
                    }
                    if stack.len() >= MAX_DEPTH {
                        return Err("workspace discovery depth budget exceeded".to_owned());
                    }
                    let mut sub = Dir::from_fd(OwnedFd::from(child))
                        .map_err(|_| "workspace snapshot discovery failed".to_owned())?;
                    let names = bounded_entries(&mut sub, &mut budget)?;
                    stack.push(Frame {
                        path,
                        handle: sub,
                        names: names.into_iter(),
                    });
                    continue;
                }
                EntryKind::File => {}
            }
            let file = open_child(handle, &name, false)?;
            let metadata = file.metadata().map_err(|error| error.to_string())?;
            if !metadata.is_file() {
                return Err("workspace snapshot inputs must be regular files".to_owned());
            }
            if metadata.nlink() != 1 {
                return Err("workspace snapshot cannot contain hard-linked files".to_owned());
            }
            total_bytes += metadata.size();
            if captured.len() >= MAX_FILES || total_bytes > MAX_BYTES {
                return Err("workspace snapshot exceeds containment identity budget".to_owned());
            }
            let digest = snapshot_file_digest(file, &metadata)?;
            budget.check(
                "workspace discovery entry budget exceeded",
                "workspace discovery time budget exceeded",
            )?;
            let input = Input::new(&path.to_string_lossy(), &relative_text, &digest)?;
            captured.push((relative_text, digest, input));
        }
    }
    captured.sort_by(|left, right| left.0.cmp(&right.0));
    exclusions.sort();
    let files: Vec<Value> = captured
        .iter()
        .map(|(path, digest, _)| json!([path, digest]))
        .collect();
    let skipped: Vec<Value> = exclusions
        .iter()
        .map(|(path, reason)| json!([path, reason]))
        .collect();
    let digest = framed_digest(&json!({"exclusions": skipped, "files": files}))?;
    Ok((
        digest,
        captured.into_iter().map(|(_, _, input)| input).collect(),
    ))
}

/// Reject Node resolution roots outside the captured workspace.
pub(crate) fn reject_external_node_modules(workspace: &Path) -> Result<(), String> {
    for ancestor in workspace.ancestors().skip(1) {
        match fs::symlink_metadata(ancestor.join("node_modules")) {
            Ok(_) => return Err("external Node dependencies require Guard review".to_owned()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                return Err("external Node dependency identity is unavailable".to_owned());
            }
        }
    }
    Ok(())
}

fn is_protected(relative: &Path, is_directory: bool) -> bool {
    let text = posix(relative);
    if classify_secret_path(&text, None, None).is_some() {
        return true;
    }
    let parts = components(relative);
    let mut package_directory_expected = false;
    let mut in_dependency_tree = false;
    for (index, part) in parts.iter().enumerate() {
        let lowered = part.to_lowercase();
        if lowered == "node_modules" {
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
                    .any(|suffix| lowered.ends_with(suffix)));
        if is_protected_part(part, !skip_generic_words) {
            return true;
        }
        if package_directory_expected {
            package_directory_expected = package_directory && part.starts_with('@');
        }
    }
    false
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

fn has_protected_words(part: &str) -> bool {
    let chars: Vec<char> = part.chars().collect();
    let mut split = String::new();
    for (index, current) in chars.iter().enumerate() {
        if index > 0 {
            let previous = chars[index - 1];
            let lower_or_digit = previous.is_ascii_lowercase() || previous.is_ascii_digit();
            let acronym_end = previous.is_ascii_uppercase()
                && current.is_ascii_uppercase()
                && chars.get(index + 1).is_some_and(char::is_ascii_lowercase);
            if (lower_or_digit && current.is_ascii_uppercase()) || acronym_end {
                split.push('-');
            }
        }
        split.push(*current);
    }
    let lowered = split.to_lowercase();
    let words: Vec<&str> = lowered
        .split(|character: char| !(character.is_ascii_lowercase() || character.is_ascii_digit()))
        .filter(|word| !word.is_empty())
        .collect();
    words.iter().any(|word| PROTECTED_WORDS.contains(word))
        || words
            .windows(2)
            .any(|pair| PROTECTED_WORD_PAIRS.contains(&(pair[0], pair[1])))
}
