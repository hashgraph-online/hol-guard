//! The portable Git project identity Guard derives for a workspace.
//!
//! This is the only resolver: the Python `resolve_portable_project_identity`
//! asks the resident's `project_identity` operation, which answers from
//! here. The rules are the ones the retired Python resolver applied, and the
//! checked-in vectors (`tests/fixtures/portable-project-identity.v1.json`)
//! pin them.
//!
//! Every answer is one of three outcomes. `Identity` is the identity the
//! workspace's Git metadata derives. `Absent` is returned only after the
//! whole input was read and names no conventional clone. `Unknown` is every
//! input this reader does not settle: an I/O error or a file that changed
//! while it was read, a workspace path `expanduser` or `resolve` would
//! rewrite, a stat error that is not plain absence, or a remote or config
//! shape the old resolver read differently across Python releases. Every
//! caller defers on `Unknown`: the in-process ones read no saved decision,
//! and the resident operation answers `native_project_identity_unresolved`
//! rather than no identity, because a lookup that lost its portable half
//! composes a local decision alone and can land on a weaker action than the
//! portable half would have forced.

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

/// The identity `resolve_portable_project_identity(workspace)` returns for a
/// workspace the calling process names relative to its own directory, which
/// `Path(...).resolve(strict=False)` reads against that process's `cwd`. The
/// relay never runs in that directory, so the join is mirrored from the `cwd`
/// the caller reports and then read exactly as an absolute workspace is read.
/// A `~` name and a reported directory that is not absolute are `Unknown`.
pub(crate) fn resolve_relative(workspace: &str, cwd: &str) -> PortableIdentity {
    let stripped = python_strip(workspace);
    if is_portable_project_identity(stripped) {
        return PortableIdentity::Identity(stripped.to_owned());
    }
    if stripped.is_empty() || Path::new(stripped).is_absolute() {
        return resolve(stripped);
    }
    match relative_path(stripped, cwd).and_then(|path| derive_resolved(&path)) {
        Ok(Some(identity)) => PortableIdentity::Identity(identity),
        Ok(None) => PortableIdentity::Absent,
        Err(Unmirrored) => PortableIdentity::Unknown,
    }
}

/// `Path(workspace).expanduser().resolve(strict=False)` against `cwd`.
///
/// `resolve` reads the name joined under the asking process's directory the
/// same way it reads an absolute workspace, so a relative name that exists,
/// or that carries separators or dot segments, is read here rather than left
/// unsettled. Only a `~` name, whose expansion reads an environment this
/// reader does not read, and a reported directory that is not absolute stay
/// unknown.
fn relative_path(workspace: &str, cwd: &str) -> Mirror<PathBuf> {
    if workspace.starts_with('~') {
        // `expanduser` rewrites a `~` name against an environment this reader
        // does not read.
        return Err(Unmirrored);
    }
    let directory = Path::new(cwd);
    if !directory.is_absolute() {
        // `resolve` joins a relative directory against the process's own
        // directory, which is not the one the caller reported.
        return Err(Unmirrored);
    }
    let directory = fs::canonicalize(directory).map_err(|_| Unmirrored)?;
    let resolved = resolve_existing_prefix(&directory.join(workspace))?;
    without_verbatim_prefix(resolved)
}

/// `is_portable_project_identity(value)` (`project_identity.py`): the
/// prefix followed by exactly the 64 lowercase hex digits of a digest.
pub(crate) fn is_portable_project_identity(value: &str) -> bool {
    value
        .strip_prefix(PORTABLE_PROJECT_IDENTITY_PREFIX)
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// `_portable_project_workspace(workspace)`
/// (`store_portable_project_memory.py`): the workspace itself when it
/// already names a portable identity, and the identity its Git metadata
/// derives otherwise.
pub(crate) fn portable_workspace(workspace: &str) -> PortableIdentity {
    let stripped = python_strip(workspace);
    if is_portable_project_identity(stripped) {
        return PortableIdentity::Identity(stripped.to_owned());
    }
    resolve(stripped)
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
        // The same errno set as Windows reports it (a missing file or
        // directory, a file where a directory was expected), plus the
        // `_IGNORED_WINERRORS`: a drive that is not ready, an invalid name
        // and a name the system cannot resolve.
        matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
        ) || matches!(error.raw_os_error(), Some(21 | 123 | 1921))
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

/// `_workspace_path`: the stripped workspace as
/// `expanduser().resolve(strict=False)` leaves it.
///
/// An absolute name with no `~` to expand resolves to its real path, which
/// is what `realpath` answers for a name that exists, so a workspace reached
/// through a symlink is read as the directory it names rather than deferred.
/// A name that does not exist resolves the part that does and appends the
/// rest without reading it, which is what `resolve_existing_prefix` reads. A
/// loop or an unreadable parent answers the part reached so far, which is
/// not read here, so it stays unknown.
fn workspace_path(workspace: &str) -> Mirror<Option<PathBuf>> {
    let stripped = python_strip(workspace);
    if stripped.is_empty() {
        // A blank workspace names no project.
        return Ok(None);
    }
    let path = Path::new(stripped);
    if !path.is_absolute() {
        // A relative or `~` name resolves against the asking process.
        return Err(Unmirrored);
    }
    let resolved = resolve_existing_prefix(path)?;
    without_verbatim_prefix(resolved).map(Some)
}

/// `resolve(strict=False)`: the longest prefix of `path` that exists, read
/// through its links, with the names below it appended unread.
///
/// A workspace whose directory is gone is an ordinary answer rather than an
/// unsettled one, so only a name this reader cannot read at all — a link
/// loop, an unreadable parent — stays unknown. A `..` below the prefix is
/// rewritten against what the part before it resolved to, which is not read
/// here, so it stays unknown too.
fn resolve_existing_prefix(path: &Path) -> Mirror<PathBuf> {
    match fs::canonicalize(path) {
        Ok(resolved) => return Ok(resolved),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(Unmirrored),
    }
    let mut unread = Vec::new();
    let mut current = path;
    loop {
        // `file_name` is `None` for a name ending in `..`, which `resolve`
        // rewrites against what the part before it resolved to.
        let (Some(parent), Some(name)) = (current.parent(), current.file_name()) else {
            return Err(Unmirrored);
        };
        unread.push(name);
        match fs::canonicalize(parent) {
            Ok(mut resolved) => {
                if fs::symlink_metadata(current).is_ok() {
                    // A name that exists but did not read is a link whose
                    // target is gone; `resolve` follows it to that target,
                    // which this reader does not reproduce.
                    return Err(Unmirrored);
                }
                resolved.extend(unread.iter().rev());
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => current = parent,
            Err(_) => return Err(Unmirrored),
        }
    }
}

/// `canonicalize` answers a verbatim (`\\?\`) path on Windows, where
/// `realpath` answers the drive or UNC form it stands for.
#[cfg(windows)]
fn without_verbatim_prefix(path: PathBuf) -> Mirror<PathBuf> {
    use std::path::{Component, Prefix};
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Ok(path);
    };
    let head = match prefix.kind() {
        Prefix::VerbatimDisk(letter) => format!("{}:", char::from(letter)),
        Prefix::VerbatimUNC(server, share) => format!(
            r"\\{}\{}",
            server.to_str().ok_or(Unmirrored)?,
            share.to_str().ok_or(Unmirrored)?
        ),
        Prefix::Verbatim(_) | Prefix::DeviceNS(_) => return Err(Unmirrored),
        Prefix::Disk(_) | Prefix::UNC(..) => return Ok(path),
    };
    Ok(PathBuf::from(head).join(components.as_path()))
}

#[cfg(not(windows))]
fn without_verbatim_prefix(path: PathBuf) -> Mirror<PathBuf> {
    Ok(path)
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
            // _discover_git_repository: a symlinked
            // `.git` is None.
            return Ok(None);
        }
        match own {
            Some(found) if found.is_file() => {
                // _discover_git_repository: a gitdir
                // pointer file is None.
                return Ok(None);
            }
            Some(found) if found.is_dir() => {}
            _ => continue,
        }
        // _discover_git_repository: a config or
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
    // _discover_git_repository: no `.git` up to the
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
        // _read_origin_remote: an oversized or non-UTF-8
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
        // _clone_remote_anchor: an oversized or non-UTF-8
        // reflog records no clone.
        None => None,
    };
    if recorded.as_deref() != Some(anchor.as_str()) {
        // An origin the clone reflog does not record is None.
        return Ok(None);
    }
    // `_relative_workspace`: the stripped POSIX relative path, or `.`. The
    // names are joined with `/` on every platform, so a clone reads the same
    // identity on Windows as on Unix.
    let names = match workspace.strip_prefix(repository.root) {
        Ok(relative) => relative
            .components()
            .map(|name| name.as_os_str().to_str())
            .collect::<Option<Vec<_>>>()
            .ok_or(Unmirrored)?,
        Err(_) => Vec::new(),
    };
    let joined = names.join("/");
    let relative = Some(python_strip(&joined))
        .filter(|relative| !relative.is_empty())
        .unwrap_or(".");
    let digest = Sha256::digest(format!("{anchor}\n{relative}").as_bytes());
    Ok(Some(format!(
        "{PORTABLE_PROJECT_IDENTITY_PREFIX}{}",
        hex::encode(digest)
    )))
}

/// `resolve_portable_project_identity` from the resolved path alone, read
/// without the identity cache: a relative workspace names a different
/// directory in every process it is read from, so its text is no cache key.
fn derive_resolved(path: &Path) -> Mirror<Option<String>> {
    let Some(repository) = discover(path)? else {
        return Ok(None);
    };
    identity(path, &repository)
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
        &path,
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
