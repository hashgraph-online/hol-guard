//! The portable Git project identity `resolve_portable_project_identity`
//! (`project_identity.py`) derives for a workspace, read in-process.
//!
//! Every answer is one of three outcomes. `Identity` is the exact identity
//! the Python resolver returns. `Absent` is returned only after the whole
//! input was read, where the Python resolver answers `None`. `Unknown` is
//! every input whose Python outcome this reader does not reproduce exactly:
//! an I/O error or a file that changed while it was read, a workspace path
//! `expanduser` or `resolve` would rewrite, a stat error a Python release
//! raises, or a remote or config shape only some Python releases accept.

use crate::context_digest::{is_python_space, python_strip};
use sha2::{Digest, Sha256};
use std::fs::{self, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

#[path = "project_identity_cache.rs"]
mod cache;
#[path = "project_identity_config.rs"]
mod config;
#[path = "project_identity_remote.rs"]
mod remote;

pub(crate) const PORTABLE_PROJECT_IDENTITY_PREFIX: &str = "git-project:v1:";
/// `_GIT_CONFIG_MAX_BYTES`.
const CONFIG_MAX_BYTES: u64 = 1024 * 1024;
/// `_GIT_REFLOG_MAX_BYTES`.
const REFLOG_MAX_BYTES: u64 = 4 * 1024 * 1024;
/// `_CLONE_REFLOG_PREFIX`.
const CLONE_REFLOG_PREFIX: &str = "clone: from ";

/// An input whose Python outcome this reader does not reproduce exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unmirrored;

pub(crate) type Mirror<T> = Result<T, Unmirrored>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PortableIdentity {
    /// The Python resolver answers `None`.
    Absent,
    /// The identity the Python resolver answers.
    Identity(String),
    /// The Python answer is not reproduced.
    Unknown,
}

/// The identity `resolve_portable_project_identity(workspace)` returns.
pub(crate) fn resolve(workspace: &str) -> PortableIdentity {
    match derive(workspace) {
        Ok(Some(identity)) => PortableIdentity::Identity(identity),
        Ok(None) => PortableIdentity::Absent,
        Err(Unmirrored) => PortableIdentity::Unknown,
    }
}

/// The errors `pathlib._ignore_error` reads as a false predicate; Python
/// 3.12 raises every other one (3.14 swallows them all).
fn ignorable(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOENT | libc::ENOTDIR | libc::EBADF | libc::ELOOP)
        )
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

/// `lstat` (or `stat`, following links), `None` where every `pathlib`
/// predicate reads false.
fn status(path: &Path, follow: bool) -> Mirror<Option<Metadata>> {
    let read = if follow {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    match read {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if ignorable(&error) => Ok(None),
        Err(_) => Err(Unmirrored),
    }
}

fn is_symlink(metadata: &Option<Metadata>) -> bool {
    metadata
        .as_ref()
        .is_some_and(|found| found.file_type().is_symlink())
}

/// `_workspace_path`: the stripped workspace, mirrored only where
/// `expanduser().resolve(strict=False)` leaves it as it is.
fn workspace_path(workspace: &str) -> Mirror<Option<PathBuf>> {
    let stripped = python_strip(workspace);
    if stripped.is_empty() {
        // project_identity.py:_workspace_path: a blank workspace is None.
        return Ok(None);
    }
    if !cfg!(unix) || !stripped.starts_with('/') {
        return Err(Unmirrored);
    }
    match fs::canonicalize(stripped) {
        Ok(resolved) if resolved.as_os_str() == stripped => Ok(Some(resolved)),
        _ => Err(Unmirrored),
    }
}

struct Repository<'w> {
    root: &'w Path,
    git_dir: PathBuf,
    config: Metadata,
    head_log: Metadata,
}

/// `_metadata_file_is_workspace_local(git_dir, git_dir / relative...)`: the
/// file's metadata, `None` where the Python check is false. A path that is
/// not a link reads the same through `stat` and `lstat`.
fn local_file(git_dir: &Path, relative: &[&str]) -> Mirror<Option<Metadata>> {
    let mut current = git_dir.to_path_buf();
    let Some((name, parents)) = relative.split_last() else {
        return Ok(None);
    };
    for part in parents {
        current.push(part);
        let found = status(&current, false)?;
        if is_symlink(&found) || !found.is_some_and(|found| found.is_dir()) {
            return Ok(None);
        }
    }
    current.push(name);
    let found = status(&current, false)?;
    if is_symlink(&found) {
        return Ok(None);
    }
    Ok(found.filter(Metadata::is_file))
}

/// `_discover_git_repository`: the walk from the workspace (or its parent)
/// through every ancestor up to the filesystem root.
fn discover(workspace: &Path) -> Mirror<Option<Repository<'_>>> {
    let is_dir = status(workspace, true)?.is_some_and(|found| found.is_dir());
    let current = match workspace.parent() {
        Some(parent) if !is_dir => parent,
        _ => workspace,
    };
    for root in current.ancestors() {
        let git_dir = root.join(".git");
        let own = status(&git_dir, false)?;
        if is_symlink(&own) {
            // `marker.is_file()` follows the link first and raises its
            // errors before `is_symlink()` answers.
            status(&git_dir, true)?;
            // project_identity.py:_discover_git_repository: a symlinked
            // `.git` is None.
            return Ok(None);
        }
        match own {
            Some(found) if found.is_file() => {
                // project_identity.py:_discover_git_repository: a gitdir
                // pointer file is None.
                return Ok(None);
            }
            Some(found) if found.is_dir() => {}
            _ => continue,
        }
        // project_identity.py:_discover_git_repository: a config or
        // logs/HEAD that is not a workspace-local file is None.
        let Some(config) = local_file(&git_dir, &["config"])? else {
            return Ok(None);
        };
        let Some(head_log) = local_file(&git_dir, &["logs", "HEAD"])? else {
            return Ok(None);
        };
        return Ok(Some(Repository {
            root,
            git_dir,
            config,
            head_log,
        }));
    }
    // project_identity.py:_discover_git_repository: no `.git` up to the
    // filesystem root is None.
    Ok(None)
}

/// The UTF-8 text of `path`, `None` when it exceeds `cap` or is not UTF-8.
fn read_capped(path: &Path, cap: u64) -> Mirror<Option<String>> {
    let mut file = fs::File::open(path).map_err(|_| Unmirrored)?;
    let size = file.metadata().map_err(|_| Unmirrored)?.len();
    if size > cap {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|_| Unmirrored)?;
    if u64::try_from(bytes.len()).ok() != Some(size) {
        // The file changed while it was read.
        return Err(Unmirrored);
    }
    Ok(String::from_utf8(bytes).ok())
}

/// A line boundary `str.splitlines` splits on (`\r` is already translated).
fn line_break(ch: char) -> bool {
    matches!(
        ch,
        '\n' | '\u{0b}'
            | '\u{0c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// `_clone_remote_anchor` over the reflog text.
fn clone_anchor(content: &str) -> Mirror<Option<String>> {
    let content = content.replace("\r\n", "\n").replace('\r', "\n");
    for line in content.split(line_break) {
        let Some((metadata, message)) = line.split_once('\t') else {
            continue;
        };
        let Some(remote) = message.strip_prefix(CLONE_REFLOG_PREFIX) else {
            continue;
        };
        let mut fields = metadata
            .split(is_python_space)
            .filter(|field| !field.is_empty());
        let (Some(previous), Some(_)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !previous.bytes().all(|byte| byte == b'0') {
            continue;
        }
        if let Some(anchor) = remote::canonical_remote(remote)? {
            return Ok(Some(anchor));
        }
    }
    Ok(None)
}

fn identity(workspace: &Path, repository: &Repository<'_>) -> Mirror<Option<String>> {
    let config_path = repository.git_dir.join("config");
    let Some(content) = read_capped(&config_path, CONFIG_MAX_BYTES)? else {
        // project_identity.py:_read_origin_remote: an oversized or non-UTF-8
        // config is None.
        return Ok(None);
    };
    let Some(origin) = config::origin_url(&content)? else {
        return Ok(None);
    };
    let Some(anchor) = remote::canonical_remote(&origin)? else {
        return Ok(None);
    };
    let log_path = repository.git_dir.join("logs").join("HEAD");
    let recorded = match read_capped(&log_path, REFLOG_MAX_BYTES)? {
        Some(content) => clone_anchor(&content)?,
        // project_identity.py:_clone_remote_anchor: an oversized or non-UTF-8
        // reflog records no clone.
        None => None,
    };
    if recorded.as_deref() != Some(anchor.as_str()) {
        // project_identity.py:resolve_portable_project_identity: an origin
        // the clone reflog does not record is None.
        return Ok(None);
    }
    // `_relative_workspace`: the stripped POSIX relative path, or `.`.
    let relative = workspace
        .strip_prefix(repository.root)
        .ok()
        .and_then(Path::to_str)
        .map(python_strip)
        .filter(|relative| !relative.is_empty())
        .unwrap_or(".");
    let digest = Sha256::digest(format!("{anchor}\n{relative}").as_bytes());
    Ok(Some(format!(
        "{PORTABLE_PROJECT_IDENTITY_PREFIX}{}",
        hex::encode(digest)
    )))
}

fn derive(workspace: &str) -> Mirror<Option<String>> {
    let Some(path) = workspace_path(workspace)? else {
        return Ok(None);
    };
    let Some(repository) = discover(&path)? else {
        return Ok(None);
    };
    let key = cache::Key::new(
        python_strip(workspace),
        &repository.git_dir,
        &repository.config,
        &repository.head_log,
    );
    if let Some(identity) = key.as_ref().and_then(cache::get) {
        return Ok(Some(identity));
    }
    let derived = identity(&path, &repository)?;
    if let (Some(key), Some(identity)) = (key, derived.as_ref()) {
        cache::put(key, identity.clone());
    }
    Ok(derived)
}

#[cfg(test)]
#[path = "project_identity_tests.rs"]
mod tests;
