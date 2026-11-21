//! The Codex and OpenCode lock files the resident holds under leases: where
//! each lives, and the checks a file must pass before it is locked. Each
//! opener refuses a link, a file swapped while opening, and on Unix a file
//! another account owns, and answers the open handle with its path.

use std::fs;
use std::path::{Component, Path, PathBuf};

use super::inspect::{resolve_lenient, sha256_hex};

const LIFECYCLE_BASE: &str = ".hol-guard-codex-lifecycle-locks";
const INSTALL_UNSAFE: &str = "codex_hook_transaction_lock_unsafe";
const OPENCODE_CHANGED: &str =
    "OpenCode config lock path changed or is not a regular file without hard-link aliases";

/// A refusal the client raises as its own error type.
pub(super) struct Refusal(pub(super) String);

impl Refusal {
    pub(super) fn lifecycle(stage: &str, error: &std::io::Error) -> Self {
        let reason = error
            .raw_os_error()
            .and_then(errno_name)
            .unwrap_or("UNKNOWN");
        Self(format!(
            "codex_lifecycle_lock_invalid: lifecycle lock {stage} is unavailable (reason={reason})"
        ))
    }
}

/// `errno.errorcode` for the reasons a lock file can be refused with.
fn errno_name(code: i32) -> Option<&'static str> {
    #[cfg(unix)]
    {
        use nix::errno::Errno;
        Some(match Errno::from_raw(code) {
            Errno::EACCES => "EACCES",
            Errno::EPERM => "EPERM",
            Errno::ENOENT => "ENOENT",
            Errno::ELOOP => "ELOOP",
            Errno::ENOTDIR => "ENOTDIR",
            Errno::EROFS => "EROFS",
            Errno::ENOSPC => "ENOSPC",
            Errno::EEXIST => "EEXIST",
            Errno::EISDIR => "EISDIR",
            Errno::EMFILE => "EMFILE",
            Errno::ENAMETOOLONG => "ENAMETOOLONG",
            _ => return None,
        })
    }
    #[cfg(not(unix))]
    {
        let _ = code;
        None
    }
}

pub(super) fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (metadata.dev(), metadata.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        (0, 0)
    }
}

pub(super) fn link_count(metadata: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.nlink()
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        1
    }
}

fn reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

fn owned_privately(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn open_lock(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    options.open(path)
}

/// `_ensure_private_directory(..., repair_mode=True)`.
fn private_directory(path: &Path) -> Result<(), Refusal> {
    let refuse = |code: &str| Refusal(code.to_owned());
    fs::create_dir_all(path).map_err(|_| refuse("codex_hook_manifest_directory_unsafe"))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| refuse("codex_hook_manifest_directory_unsafe"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(refuse("codex_hook_manifest_directory_unsafe"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != nix::unistd::getuid().as_raw() {
            return Err(refuse("codex_hook_manifest_directory_owner_mismatch"));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| refuse("codex_hook_manifest_directory_permissions_unsafe"))?;
        }
    }
    Ok(())
}

/// The installation lock, opened and checked as `_verify_lock_file` does.
pub(super) fn install_lock(guard_home: &Path) -> Result<(fs::File, PathBuf), Refusal> {
    let path = resolve_lenient(guard_home)
        .join("managed")
        .join("codex")
        .join("installation.lock");
    let parent = path.parent().ok_or(Refusal(INSTALL_UNSAFE.to_owned()))?;
    private_directory(parent)?;
    let unsafe_lock = |_| Refusal(INSTALL_UNSAFE.to_owned());
    let file = open_lock(&path).map_err(unsafe_lock)?;
    let opened = file.metadata().map_err(unsafe_lock)?;
    let current = fs::symlink_metadata(&path).map_err(unsafe_lock)?;
    if !opened.is_file()
        || !current.is_file()
        || link_count(&opened) != 1
        || identity(&opened) != identity(&current)
        || reparse(&current)
        || !owned_privately(&opened)
    {
        return Err(Refusal(INSTALL_UNSAFE.to_owned()));
    }
    Ok((file, path))
}

#[cfg_attr(test, allow(dead_code))]
fn account_home() -> std::io::Result<PathBuf> {
    #[cfg(unix)]
    {
        nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten()
            .map(|user| user.dir)
            .ok_or_else(|| std::io::Error::other("codex_lifecycle_account_home_unavailable"))
    }
    #[cfg(windows)]
    {
        guard_runtime_windows_process::user_profile_directory()
            .and_then(|profile| {
                guard_runtime_windows_process::real_directory(&profile.to_string_lossy())
            })
            .map(PathBuf::from)
            .ok_or_else(|| std::io::Error::other("codex_lifecycle_account_home_unavailable"))
    }
}

/// Where the lifecycle locks live. Tests keep them out of the real account.
fn lifecycle_base() -> std::io::Result<PathBuf> {
    #[cfg(test)]
    {
        let parent =
            std::env::temp_dir().join(format!("hol-guard-lifecycle-locks-{}", std::process::id()));
        fs::create_dir_all(&parent)?;
        Ok(parent.join(LIFECYCLE_BASE))
    }
    #[cfg(not(test))]
    {
        Ok(account_home()?.join(LIFECYCLE_BASE))
    }
}

/// `os.path.normcase(str(directory.resolve()))`.
pub(super) fn configuration_identity(directory: &Path) -> String {
    // `Path.resolve()` folds `.` and `..` that follow a missing component;
    // nothing missing can be a link, so folding them lexically matches it.
    let mut folded = PathBuf::new();
    for component in resolve_lenient(directory).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                folded.pop();
            }
            other => folded.push(other),
        }
    }
    let resolved = folded.to_string_lossy().into_owned();
    if cfg!(windows) {
        resolved.replace('/', "\\").to_lowercase()
    } else {
        resolved
    }
}

fn lifecycle_identity(path: &Path) -> Result<Option<(u64, u64)>, Refusal> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Refusal::lifecycle("file", &error)),
        Ok(metadata) if !metadata.is_file() || link_count(&metadata) != 1 => Err(Refusal(
            "codex_lifecycle_lock_invalid: lifecycle lock must be a regular file with one link"
                .to_owned(),
        )),
        Ok(metadata) => Ok(Some(identity(&metadata))),
    }
}

/// `codex_lifecycle_lock._target_lock`: open and check one lifecycle lock.
pub(super) fn lifecycle_lock(directory: &Path) -> Result<(fs::File, PathBuf), Refusal> {
    let base = lifecycle_base().map_err(|error| Refusal::lifecycle("directory", &error))?;
    lifecycle_lock_in(&base, directory)
}

/// The lock file of one configuration directory's identity under `base`.
fn lock_path_in(base: &Path, identity: &str) -> PathBuf {
    base.join(format!("{}.lock", sha256_hex(identity.as_bytes())))
}

/// Where the lifecycle lock of the directory with this identity lives.
pub(super) fn lifecycle_lock_path(identity: &str) -> std::io::Result<PathBuf> {
    Ok(lock_path_in(&lifecycle_base()?, identity))
}

fn lifecycle_lock_in(base: &Path, directory: &Path) -> Result<(fs::File, PathBuf), Refusal> {
    let path = lock_path_in(base, &configuration_identity(directory));
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    if let Err(error) = builder.create(base) {
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(Refusal::lifecycle("directory", &error));
        }
    }
    let metadata =
        fs::symlink_metadata(base).map_err(|error| Refusal::lifecycle("directory", &error))?;
    let private = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            metadata.uid() == nix::unistd::getuid().as_raw()
                && metadata.permissions().mode() & 0o077 == 0
        }
        #[cfg(not(unix))]
        {
            true
        }
    };
    if !metadata.is_dir() || !private {
        return Err(Refusal(
            "codex_lifecycle_lock_invalid: lifecycle lock directory is not private".to_owned(),
        ));
    }
    let prior = lifecycle_identity(&path)?;
    let file = open_lock(&path).map_err(|error| Refusal::lifecycle("file", &error))?;
    let opened = file
        .metadata()
        .map_err(|error| Refusal::lifecycle("file", &error))?;
    let opened = identity(&opened);
    if lifecycle_identity(&path)? != Some(opened) || prior.is_some_and(|prior| prior != opened) {
        return Err(Refusal(
            "codex_lifecycle_lock_invalid: lifecycle lock changed while opening".to_owned(),
        ));
    }
    Ok((file, path))
}

/// `opencode_runtime.opencode_config_lock`: one lock per home's OpenCode
/// config directory. Refusals carry the Python messages, which the client
/// raises as `ValueError`.
pub(super) fn opencode_lock(home_dir: &Path) -> Result<(fs::File, PathBuf), Refusal> {
    let path = home_dir
        .join(".config")
        .join("opencode")
        .join(".hol-guard-config.lock");
    let changed = |_| Refusal(OPENCODE_CHANGED.to_owned());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(changed)?;
    }
    if fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(Refusal(
            "OpenCode config lock must not be a symlink".to_owned(),
        ));
    }
    let file = open_lock(&path).map_err(changed)?;
    let opened = file.metadata().map_err(changed)?;
    let current = fs::symlink_metadata(&path).map_err(changed)?;
    if !opened.is_file()
        || !current.is_file()
        || reparse(&current)
        || identity(&opened) != identity(&current)
        || link_count(&opened) != 1
    {
        return Err(Refusal(OPENCODE_CHANGED.to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.uid() != nix::unistd::geteuid().as_raw() {
            return Err(Refusal(
                "OpenCode config lock must be owned by the current user on POSIX".to_owned(),
            ));
        }
    }
    Ok((file, path))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_lock_refuses_a_linked_file_and_keeps_its_target() {
        let root = tempfile::TempDir::new().unwrap();
        let base = root.path().join("locks");
        let directory = root.path().join("home/.codex");
        let (_, path) = lifecycle_lock_in(&base, &directory).ok().unwrap();
        fs::remove_file(&path).unwrap();
        let target = base.join("user-file");
        fs::write(&target, b"kept").unwrap();
        fs::hard_link(&target, &path).unwrap();
        let Err(Refusal(error)) = lifecycle_lock_in(&base, &directory) else {
            panic!("linked lock accepted");
        };
        assert!(error.starts_with("codex_lifecycle_lock_invalid"), "{error}");
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(lifecycle_lock_in(&base, &directory).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"kept");
    }

    #[test]
    fn opencode_lock_refuses_links_and_keeps_their_target() {
        let home = tempfile::TempDir::new().unwrap();
        let (_, path) = opencode_lock(home.path()).ok().unwrap();
        fs::remove_file(&path).unwrap();
        let target = home.path().join("untouched");
        fs::write(&target, b"unchanged").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let Err(Refusal(error)) = opencode_lock(home.path()) else {
            panic!("symlinked lock accepted");
        };
        assert!(error.contains("symlink"), "{error}");
        fs::remove_file(&path).unwrap();
        fs::hard_link(&target, &path).unwrap();
        let Err(Refusal(error)) = opencode_lock(home.path()) else {
            panic!("hard-linked lock accepted");
        };
        assert!(error.contains("lock path changed"), "{error}");
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
    }
}
