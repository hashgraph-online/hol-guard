//! Bounded host IO for the GitHub workflow descriptor: PATH resolution, the
//! allowlisted-environment `git`/`gh` subprocess, and workspace binding-file
//! digests. Ports the collection half of `github_workflow_context.py`; every
//! failure collapses to `None`, which the op reports as "no descriptor".

use std::collections::BTreeMap;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const OUTPUT_LIMIT: u64 = 64 * 1024;
const WORKSPACE_FILE_LIMIT: u64 = 8 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);
/// Whole-request wall clock for one descriptor collection; stays under the
/// nine-second resident client deadline.
pub(crate) const REQUEST_BUDGET: Duration = Duration::from_secs(8);
const ALLOWED_ENVIRONMENT: [&str; 6] = [
    "GH_CONFIG_DIR",
    "GH_HOST",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "HOME",
    "PATH",
];

pub(crate) fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// `_resolve_executable`: `shutil.which` over the request PATH, then require an
/// absolute, non-symlinked, regular executable. A relative or empty PATH entry
/// before the match fails closed.
pub(crate) fn resolve_executable(name: &str, path_value: Option<&str>) -> Option<PathBuf> {
    let path_value = path_value?;
    let mut found = None;
    for directory in std::env::split_paths(path_value) {
        if !directory.is_absolute() {
            return None;
        }
        let candidate = directory.join(name);
        if is_executable_file(&candidate) {
            found = Some(candidate);
            break;
        }
    }
    let path = found?;
    let canonical = canonical_path(&path)?;
    (path == canonical).then_some(path)
}

/// Strict `Path.resolve(strict=True)`; drops the Windows verbatim prefix.
pub(crate) fn canonical_path(path: &Path) -> Option<PathBuf> {
    let canonical = fs::canonicalize(path).ok()?;
    #[cfg(windows)]
    {
        if let Some(stripped) = canonical.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
            return Some(PathBuf::from(stripped));
        }
    }
    Some(canonical)
}

/// `_run_bounded`: no shell, stdin/stderr null, allowlisted environment, 5 s
/// wall clock (also capped by the caller's shared `request_deadline`), and
/// 64 KiB of output; a non-zero exit, overflow or output that outlives the
/// deadline is a failure.
pub(crate) fn run_bounded(
    arguments: &[String],
    cwd: &Path,
    environment: &BTreeMap<String, String>,
    request_deadline: Instant,
) -> Option<Vec<u8>> {
    let (program, rest) = arguments.split_first()?;
    let mut command = Command::new(program);
    command
        .args(rest)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for key in ALLOWED_ENVIRONMENT {
        if let Some(value) = environment.get(key) {
            command.env(key, value);
        }
    }
    let deadline = request_deadline.min(Instant::now() + TIMEOUT);
    let mut child = command.spawn().ok()?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return None;
    };
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(OUTPUT_LIMIT + 1).read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            _ => {
                // A descendant may still hold the pipe, so the reader is detached.
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    // A descendant may keep stdout open after the direct child exits; wait only
    // for the remaining budget and detach the reader on timeout.
    let bytes = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()?;
    (status.success() && bytes.len() as u64 <= OUTPUT_LIMIT).then_some(bytes)
}

/// `_file_sha256`: streamed digest of the resolved executable.
pub(crate) fn file_sha256(path: &Path) -> Option<String> {
    let mut stream = File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = stream.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Some(hex::encode(digest.finalize()))
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_ns: i128,
    changed_ns: i128,
}

fn identity(metadata: &Metadata) -> FileIdentity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified_ns: i128::from(metadata.mtime()) * 1_000_000_000
                + i128::from(metadata.mtime_nsec()),
            changed_ns: i128::from(metadata.ctime()) * 1_000_000_000
                + i128::from(metadata.ctime_nsec()),
        }
    }
    #[cfg(not(unix))]
    {
        let modified_ns = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |elapsed| elapsed.as_nanos() as i128);
        FileIdentity {
            device: 0,
            inode: 0,
            size: metadata.len(),
            modified_ns,
            changed_ns: 0,
        }
    }
}

/// `_workspace_files_sha256` collection leg: `(name, sha256)` for each present
/// binding file, with `lstat`/`fstat` identity stability checks. `None` when
/// any present file is irregular, oversized, or changes while read.
pub(crate) fn workspace_file_entries(
    workspace: &Path,
    names: &[&str],
) -> Option<Vec<(String, String)>> {
    let mut entries = Vec::new();
    for name in names {
        let path = workspace.join(name);
        let initial = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        if !initial.is_file() || initial.len() > WORKSPACE_FILE_LIMIT {
            return None;
        }
        let mut stream = File::open(&path).ok()?;
        let opened = stream.metadata().ok()?;
        if !opened.is_file()
            || opened.len() > WORKSPACE_FILE_LIMIT
            || identity_pair(&opened) != identity_pair(&initial)
        {
            return None;
        }
        let mut content = Vec::new();
        (&mut stream)
            .take(WORKSPACE_FILE_LIMIT + 1)
            .read_to_end(&mut content)
            .ok()?;
        let final_metadata = stream.metadata().ok()?;
        let named = fs::symlink_metadata(&path).ok()?;
        if content.len() as u64 > WORKSPACE_FILE_LIMIT
            || identity(&final_metadata) != identity(&opened)
            || identity(&named) != identity(&final_metadata)
        {
            return None;
        }
        entries.push(((*name).to_owned(), hex::encode(Sha256::digest(&content))));
    }
    Some(entries)
}

fn identity_pair(metadata: &Metadata) -> (u64, u64) {
    let identity = identity(metadata);
    (identity.device, identity.inode)
}
