//! Non-destructive Git pre-commit integration for HOL Guard Secrets.
//!
//! Port of `codex_plugin_scanner.guard.secrets.precommit` (RTM-032,
//! `src/codex_plugin_scanner/guard/secrets/precommit.py`). The installer
//! preserves any existing user hook by chaining it; all filesystem mutation
//! happens relative to the opened hooks-directory descriptor (`dir_fd`
//! semantics) so a symlink swap between lookup and write cannot redirect
//! changes outside the real Git hooks directory.
//!
//! `dir_fd` primitives are POSIX-only, matching the Python module's reliance
//! on `os.{open,stat,replace,unlink}(dir_fd=...)`; the non-Unix entry points
//! fail closed with the same refusal Python surfaces when those calls are
//! unavailable.

use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::fd::{AsFd, OwnedFd};
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
use nix::errno::Errno;
#[cfg(unix)]
use nix::fcntl::{openat, renameat, AtFlags, OFlag};
#[cfg(unix)]
use nix::sys::stat::{fstat, fstatat, FileStat, Mode, SFlag};
#[cfg(unix)]
use nix::unistd::{fsync, unlinkat, UnlinkatFlags};

#[cfg(unix)]
use crate::git_read::{run_git, GitError, GIT_TIMEOUT_SECONDS};

/// `_MANAGED_MARKER` from the Python module.
#[cfg(unix)]
const MANAGED_MARKER: &str = "# HOL_GUARD_SECRETS_PRE_COMMIT_V1";
/// `_BACKUP_NAME` from the Python module.
#[cfg(unix)]
const BACKUP_NAME: &str = "pre-commit.hol-guard-user";

/// `_MANAGED_HOOK` from the Python module: the managed shim that chains a
/// preserved user hook before delegating to `hol-guard secrets scan --staged`.
#[cfg(unix)]
fn managed_hook() -> String {
    format!(
        "#!/bin/sh\n\
         {MANAGED_MARKER}\n\
         # Managed by `hol-guard secrets install-hook`. Do not place secrets in this file.\n\
         hook_dir=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n\
         legacy=\"$hook_dir/{BACKUP_NAME}\"\n\
         if [ -x \"$legacy\" ]; then\n\
         \x20 \"$legacy\" \"$@\"\n\
         \x20 status=$?\n\
         \x20 if [ \"$status\" -ne 0 ]; then\n\
         \x20   exit \"$status\"\n\
         \x20 fi\n\
         fi\n\
         exec hol-guard secrets scan --staged --fail-on-findings\n"
    )
}

/// Mirror of the frozen `SecretsHookResult` dataclass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretsHookResult {
    /// `status`: `installed`, `already_installed`, `uninstalled`, `restored`,
    /// or `not_installed`.
    pub status: &'static str,
    /// `hook`: the display path, always `git-hooks/pre-commit`.
    pub hook: &'static str,
    /// `chained_existing`: whether a user hook was preserved under
    /// `pre-commit.hol-guard-user`.
    pub chained_existing: bool,
}

impl SecretsHookResult {
    /// Public payload matching Python `to_public_dict`.
    pub fn to_public_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": "guard-secrets-hook.v1",
            "status": self.status,
            "hook": self.hook,
            "chained_existing": self.chained_existing,
        })
    }
}

/// Python raises `ValueError` for every guarded refusal and wraps `OSError`s
/// from the mutation blocks in `ValueError` with fixed messages; raw
/// `OSError`s escape only from the low-level stat probes that feed those
/// blocks. [`PrecommitError`] keeps that split: `Value` carries the exact
/// Python message string, `Io` the raw `OSError`.
#[derive(Debug)]
pub enum PrecommitError {
    /// Python `ValueError` — the public, message-bearing failure mode.
    Value(String),
    /// Python `OSError` — raised by the `dir_fd` probes, wrapped by the
    /// install/uninstall mutation blocks exactly like `except OSError`.
    Io(io::Error),
}

impl PrecommitError {
    /// `raise ValueError(message)`.
    fn value(message: &str) -> Self {
        Self::Value(message.to_string())
    }
}

impl fmt::Display for PrecommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Value(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for PrecommitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// `Errno` → `OSError`.
#[cfg(unix)]
fn errno_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

/// `stat.S_ISDIR(entry.st_mode)`.
#[cfg(unix)]
fn is_directory(entry: &FileStat) -> bool {
    file_type(entry) == SFlag::S_IFDIR
}

/// `stat.S_ISREG(entry.st_mode)`.
#[cfg(unix)]
fn is_regular(entry: &FileStat) -> bool {
    file_type(entry) == SFlag::S_IFREG
}

/// The `S_IFMT` field. File types share bits (`S_IFLNK` contains `S_IFREG`,
/// `S_IFSOCK` contains `S_IFDIR`), so a type test must compare the whole
/// field rather than check for one type's bits.
#[cfg(unix)]
fn file_type(entry: &FileStat) -> SFlag {
    SFlag::from_bits_truncate(entry.st_mode as nix::libc::mode_t) & SFlag::S_IFMT
}

/// Python `_git_common_dir`: refuse `core.hooksPath`, then resolve
/// `rev-parse --git-common-dir` against the resolved worktree root.
///
/// `run_git` folds `rc != 0` into [`GitError::NonZero`]; for
/// `config --get core.hooksPath` an unset key yields `NonZero` with empty
/// stderr, which Python (`returncode == 0 and stdout.strip()`) treats as "no
/// custom hooks path" rather than a refusal.
#[cfg(unix)]
fn git_common_dir(root: &Path) -> Result<PathBuf, PrecommitError> {
    // `root.expanduser().resolve()` — Python resolve() is non-strict, so fall
    // back to the expanded path and let `is_dir()` carry the exists check.
    let expanded = crate::repository_scanner::expand_tilde(root);
    let resolved = expanded.canonicalize().unwrap_or(expanded);
    if !resolved.is_dir() {
        return Err(PrecommitError::value(
            "hook target must be an existing Git worktree directory",
        ));
    }

    let custom_hooks_set = match run_git(
        &resolved,
        &["config", "--get", "core.hooksPath"],
        GIT_TIMEOUT_SECONDS,
    ) {
        Ok(output) => {
            // `custom_hooks.returncode == 0 and custom_hooks.stdout.strip()`
            let raw = std::str::from_utf8(&output.stdout)
                .map_err(|error| PrecommitError::Value(error.to_string()))?;
            !raw.trim().is_empty()
        }
        // rc != 0 with stderr output is a real config failure (Python catches
        // it as `SubprocessError` → "not a usable Git worktree"); the plain
        // unset-key exit keeps stderr empty.
        Err(GitError::NonZero { ref stderr, .. }) if stderr.is_empty() => false,
        Err(_) => {
            return Err(PrecommitError::value(
                "hook target is not a usable Git worktree",
            ))
        }
    };
    if custom_hooks_set {
        return Err(PrecommitError::value(
            "custom core.hooksPath is configured; HOL Guard will not modify a shared or \
             custom hook directory automatically",
        ));
    }

    let result = run_git(
        &resolved,
        &["rev-parse", "--git-common-dir"],
        GIT_TIMEOUT_SECONDS,
    )
    // `OSError`/`SubprocessError` and `returncode != 0` share this message.
    .map_err(|_| PrecommitError::value("hook target is not a usable Git worktree"))?;
    // `raw = result.stdout.decode("utf-8", errors="strict").strip()`; a strict
    // decode failure is a `UnicodeDecodeError`, a `ValueError` subclass.
    let raw = String::from_utf8(result.stdout)
        .map_err(|error| PrecommitError::Value(error.to_string()))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PrecommitError::value(
            "Git hook directory could not be resolved",
        ));
    }
    let path = PathBuf::from(trimmed);
    let candidate = if path.is_absolute() {
        path
    } else {
        resolved.join(path)
    };
    // `(path if path.is_absolute() else resolved / path).resolve()`
    Ok(candidate.canonicalize().unwrap_or(candidate))
}

/// `_entry_stat`: `os.stat(name, dir_fd=directory, follow_symlinks=False)`
/// returning `None` only on `ENOENT`.
#[cfg(unix)]
fn entry_stat(directory: &OwnedFd, name: &str) -> Result<Option<FileStat>, PrecommitError> {
    match fstatat(directory.as_fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(entry) => Ok(Some(entry)),
        Err(Errno::ENOENT) => Ok(None),
        Err(error) => Err(PrecommitError::Io(errno_io(error))),
    }
}

/// `_is_managed_hook`: a regular file whose first 512 bytes name the marker.
#[cfg(unix)]
fn is_managed_hook(directory: &OwnedFd, name: &str) -> Result<bool, PrecommitError> {
    let Some(entry) = entry_stat(directory, name)? else {
        return Ok(false);
    };
    if !is_regular(&entry) {
        return Ok(false);
    }
    // `os.open(name, O_RDONLY | O_NOFOLLOW, dir_fd=directory)`; the Python
    // `except OSError: return False` covers both open and read failures.
    let Ok(descriptor) = openat(
        directory.as_fd(),
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) else {
        return Ok(false);
    };
    let mut prefix = Vec::new();
    if std::fs::File::from(descriptor)
        .take(512)
        .read_to_end(&mut prefix)
        .is_err()
    {
        return Ok(false);
    }
    Ok(String::from_utf8_lossy(&prefix).contains(MANAGED_MARKER))
}

/// `_require_regular_entry`.
#[cfg(unix)]
fn require_regular_entry(directory: &OwnedFd, name: &str) -> Result<(), PrecommitError> {
    if let Some(entry) = entry_stat(directory, name)? {
        if !is_regular(&entry) {
            return Err(PrecommitError::value(
                "refusing to modify a non-regular Git hook entry",
            ));
        }
    }
    Ok(())
}

/// `_open_hooks_directory`: optionally create `.git/hooks` (mode `0o700`,
/// `exist_ok=True`), then open it `O_RDONLY | O_DIRECTORY | O_NOFOLLOW` and
/// re-verify via `fstat`.
#[cfg(unix)]
fn open_hooks_directory(root: &Path, create: bool) -> Result<Option<OwnedFd>, PrecommitError> {
    let hooks_dir = git_common_dir(root)?.join("hooks");
    if create {
        // `hooks_dir.mkdir(mode=0o700, exist_ok=True)`
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&hooks_dir) {
            Ok(()) => {}
            // `exist_ok=True`: an already-present path is left for the open
            // below to validate as a real directory.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                return Err(PrecommitError::value(
                    "Git hook directory could not be created safely",
                ))
            }
        }
    }
    // `os.open(hooks_dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)`
    let descriptor = match nix::fcntl::open(
        hooks_dir.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::ENOENT) => {
            // `except FileNotFoundError`: `create=False` reports absence,
            // `create=True` means the mkdir could not yield a directory.
            if !create {
                return Ok(None);
            }
            return Err(PrecommitError::value(
                "Git hook directory must be a real trusted directory",
            ));
        }
        Err(_) => {
            return Err(PrecommitError::value(
                "Git hook directory must be a real trusted directory",
            ))
        }
    };
    // `if not stat.S_ISDIR(os.fstat(descriptor).st_mode)`
    match fstat(&descriptor) {
        Ok(entry) if is_directory(&entry) => Ok(Some(descriptor)),
        Ok(_) => Err(PrecommitError::value(
            "Git hook directory must be a real trusted directory",
        )),
        Err(error) => Err(PrecommitError::Io(errno_io(error))),
    }
}

/// Install the managed hook while preserving any existing user hook.
#[cfg(unix)]
pub fn install_precommit_hook(root: &Path) -> Result<SecretsHookResult, PrecommitError> {
    let hook = "pre-commit";
    let backup = BACKUP_NAME;
    let display = "git-hooks/pre-commit";
    let temp = format!(".{hook}.hol-guard-{}.tmp", std::process::id());

    // `_open_hooks_directory(root, create=True)` always returns a descriptor
    // or raises, so `None` mirrors Python's unreachable `ValueError` guard.
    let directory = open_hooks_directory(root, true)?
        .ok_or_else(|| PrecommitError::value("Git hook directory could not be created safely"))?;

    // The Python `try` block below maps `OSError` to cleanup +
    // `ValueError("could not install ...")`; `ValueError`s propagate
    // untouched. `PrecommitError::Io` is the `OSError` analogue.
    let mut moved_existing = false;
    let outcome = (|| -> Result<SecretsHookResult, PrecommitError> {
        require_regular_entry(&directory, hook)?;
        require_regular_entry(&directory, backup)?;
        if is_managed_hook(&directory, hook)? {
            return Ok(SecretsHookResult {
                status: "already_installed",
                hook: display,
                chained_existing: entry_stat(&directory, backup)?.is_some(),
            });
        }
        let hook_exists = entry_stat(&directory, hook)?.is_some();
        if hook_exists && entry_stat(&directory, backup)?.is_some() {
            return Err(PrecommitError::value(
                "refusing to replace pre-commit hook because the HOL Guard backup path already \
                 exists",
            ));
        }
        if hook_exists {
            // `os.replace(hook, backup, src_dir_fd=..., dst_dir_fd=...)`
            renameat(directory.as_fd(), hook, directory.as_fd(), backup)
                .map_err(|error| PrecommitError::Io(errno_io(error)))?;
            moved_existing = true;
        }
        // `os.open(temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o755, dir_fd=...)`
        let descriptor = openat(
            directory.as_fd(),
            temp.as_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW,
            Mode::from_bits_truncate(0o755),
        )
        .map_err(|error| PrecommitError::Io(errno_io(error)))?;
        let mut file = std::fs::File::from(descriptor);
        file.write_all(managed_hook().as_bytes())
            .map_err(PrecommitError::Io)?;
        file.flush().map_err(PrecommitError::Io)?;
        fsync(&file).map_err(|error| PrecommitError::Io(errno_io(error)))?;
        drop(file);
        // `os.replace(temp, hook, src_dir_fd=..., dst_dir_fd=...)`
        renameat(directory.as_fd(), temp.as_str(), directory.as_fd(), hook)
            .map_err(|error| PrecommitError::Io(errno_io(error)))?;
        Ok(SecretsHookResult {
            status: "installed",
            hook: display,
            chained_existing: moved_existing,
        })
    })();

    match outcome {
        Ok(result) => Ok(result),
        Err(error) => {
            if matches!(error, PrecommitError::Io(_)) {
                // Python `except OSError` cleanup, itself wrapped in
                // `except OSError: pass`; the steps share one closure so the
                // sequence stops at the first cleanup failure like Python.
                let _ = (|| -> Result<(), PrecommitError> {
                    if entry_stat(&directory, temp.as_str())?.is_some() {
                        unlinkat(directory.as_fd(), temp.as_str(), UnlinkatFlags::NoRemoveDir)
                            .map_err(|error| PrecommitError::Io(errno_io(error)))?;
                    }
                    if moved_existing
                        && entry_stat(&directory, backup)?.is_some()
                        && entry_stat(&directory, hook)?.is_none()
                    {
                        renameat(directory.as_fd(), backup, directory.as_fd(), hook)
                            .map_err(|error| PrecommitError::Io(errno_io(error)))?;
                    }
                    Ok(())
                })();
            }
            Err(match error {
                PrecommitError::Io(_) => {
                    PrecommitError::value("could not install HOL Guard Secrets pre-commit hook")
                }
                other => other,
            })
        }
    }
}

/// Remove only the managed hook and restore a chained user hook exactly.
#[cfg(unix)]
pub fn uninstall_precommit_hook(root: &Path) -> Result<SecretsHookResult, PrecommitError> {
    let hook = "pre-commit";
    let backup = BACKUP_NAME;
    let display = "git-hooks/pre-commit";

    // `_open_hooks_directory(root, create=False)` → `None` reports a missing
    // hooks directory as `not_installed`.
    let Some(directory) = open_hooks_directory(root, false)? else {
        return Ok(SecretsHookResult {
            status: "not_installed",
            hook: display,
            chained_existing: false,
        });
    };

    // `_require_regular_entry` for both names: a symlinked or special hook
    // entry is refused before anything is read through it.
    require_regular_entry(&directory, hook)?;
    require_regular_entry(&directory, backup)?;
    if entry_stat(&directory, hook)?.is_none() {
        if entry_stat(&directory, backup)?.is_some() {
            renameat(directory.as_fd(), backup, directory.as_fd(), hook).map_err(|_| {
                PrecommitError::value("could not restore the preserved pre-commit hook")
            })?;
            return Ok(SecretsHookResult {
                status: "restored",
                hook: display,
                chained_existing: true,
            });
        }
        return Ok(SecretsHookResult {
            status: "not_installed",
            hook: display,
            chained_existing: false,
        });
    }

    // Python wraps the mutation block in `except OSError` →
    // `ValueError("could not uninstall ...")`; the non-managed + no-backup
    // early return and the `ValueError` refusal bypass that wrapper.
    let outcome = (|| -> Result<SecretsHookResult, PrecommitError> {
        if !is_managed_hook(&directory, hook)? {
            if entry_stat(&directory, backup)?.is_some() {
                return Err(PrecommitError::value(
                    "refusing to overwrite a non-HOL-Guard pre-commit hook while a preserved \
                     backup exists",
                ));
            }
            return Ok(SecretsHookResult {
                status: "not_installed",
                hook: display,
                chained_existing: false,
            });
        }
        // `os.unlink(hook, dir_fd=directory)`
        unlinkat(directory.as_fd(), hook, UnlinkatFlags::NoRemoveDir)
            .map_err(|error| PrecommitError::Io(errno_io(error)))?;
        let restored = entry_stat(&directory, backup)?.is_some();
        if restored {
            // `os.replace(backup, hook, src_dir_fd=..., dst_dir_fd=...)`
            renameat(directory.as_fd(), backup, directory.as_fd(), hook)
                .map_err(|error| PrecommitError::Io(errno_io(error)))?;
        }
        Ok(SecretsHookResult {
            status: if restored { "restored" } else { "uninstalled" },
            hook: display,
            chained_existing: restored,
        })
    })();

    outcome.map_err(|error| match error {
        PrecommitError::Io(_) => {
            PrecommitError::value("could not uninstall HOL Guard Secrets pre-commit hook")
        }
        other => other,
    })
}

/// Non-POSIX fallback: the Python module cannot open `dir_fd` descriptors
/// there, so installation refuses the same way an untrusted hooks directory
/// does.
#[cfg(not(unix))]
pub fn install_precommit_hook(_root: &Path) -> Result<SecretsHookResult, PrecommitError> {
    Err(PrecommitError::value(
        "Git hook directory must be a real trusted directory",
    ))
}

/// Non-POSIX fallback; see [`install_precommit_hook`].
#[cfg(not(unix))]
pub fn uninstall_precommit_hook(_root: &Path) -> Result<SecretsHookResult, PrecommitError> {
    Err(PrecommitError::value(
        "Git hook directory must be a real trusted directory",
    ))
}

#[cfg(all(test, unix))]
#[path = "precommit_tests.rs"]
mod tests;
