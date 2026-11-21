//! The pathlib/os behaviours the package-context inputs relied on.
//!
//! The resident has neither the client's working directory nor its home
//! directory, so every relative path is taken against the facts the client sent
//! ([`Fs`]) and never against the resident's own process state. Failure kinds
//! follow the retired Python: conditions it would have raised as `OSError` stay
//! recoverable ([`ResolveError::Os`]) while the ones it let escape
//! (`RuntimeError` for a symlink loop, or an unexpected `stat` failure) become
//! [`BuildError::Fatal`], which fails the whole build closed.

use std::collections::BTreeMap;
use std::fs::{self, Metadata, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use crate::codex_output_py::PyPath;

use super::{BuildError, Built};

pub(super) const MAX_CONFIG_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub(super) const MAX_DEPENDENCY_FILE_BYTES: u64 = 32 * 1024 * 1024;
pub(super) const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_GIT_POINTER_BYTES: u64 = 16 * 1024;
const MAX_CONTEXT_BYTES: u64 = 96 * 1024 * 1024;
pub(super) const MAX_TREE_FILES: usize = 512;
const READ_CHUNK_BYTES: u64 = 1024 * 1024;

/// Why a path could not be resolved.
#[derive(Debug)]
pub(super) enum ResolveError {
    /// `OSError`: the path does not exist or a component is unusable.
    Os,
    /// `RuntimeError`: a symlink loop.
    Loop(String),
}

impl ResolveError {
    pub(super) fn into_fatal(self, path: &str) -> BuildError {
        match self {
            Self::Os => BuildError::Fatal(format!("cannot resolve {path}")),
            Self::Loop(text) => BuildError::Fatal(text),
        }
    }
}

/// Process facts the Python code read from its interpreter.
pub(super) struct Fs {
    cwd: String,
    home: String,
    home_env: Option<String>,
}

pub(super) fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// `posixpath.normpath` for an absolute path.
pub(super) fn normpath(path: &str) -> String {
    let initial = if path.starts_with("//") && !path.starts_with("///") {
        2
    } else {
        1
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part != ".." || parts.last() == Some(&"..") {
            parts.push(part);
        } else {
            parts.pop();
        }
    }
    format!("{}{}", "/".repeat(initial), parts.join("/"))
}

fn ignored_stat_error(error: &std::io::Error) -> bool {
    match error.raw_os_error() {
        Some(code) => {
            code == libc::ENOENT
                || code == libc::ENOTDIR
                || code == libc::EBADF
                || code == libc::ELOOP
        }
        None => error.kind() == ErrorKind::InvalidInput,
    }
}

impl Fs {
    pub(super) fn new(cwd: &str, home: &str, home_env: Option<&str>) -> Self {
        Self {
            cwd: cwd.to_owned(),
            home: home.to_owned(),
            home_env: home_env.map(str::to_owned),
        }
    }

    pub(super) fn fs_path(&self, path: &str) -> PathBuf {
        if is_absolute(path) {
            PathBuf::from(path)
        } else {
            PathBuf::from(&self.cwd).join(path)
        }
    }

    /// `Path.stat()` / `Path.lstat()` where `ENOENT`-like failures mean "absent".
    fn stat(&self, path: &str, follow: bool) -> Built<Option<Metadata>> {
        let target = self.fs_path(path);
        let result = if follow {
            fs::metadata(&target)
        } else {
            fs::symlink_metadata(&target)
        };
        match result {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if ignored_stat_error(&error) => Ok(None),
            Err(error) => Err(BuildError::Fatal(format!("cannot stat {path}: {error}"))),
        }
    }

    pub(super) fn exists(&self, path: &str) -> Built<bool> {
        Ok(self.stat(path, true)?.is_some())
    }

    pub(super) fn is_file(&self, path: &str) -> Built<bool> {
        Ok(self.stat(path, true)?.is_some_and(|meta| meta.is_file()))
    }

    pub(super) fn is_dir(&self, path: &str) -> Built<bool> {
        Ok(self.stat(path, true)?.is_some_and(|meta| meta.is_dir()))
    }

    pub(super) fn is_symlink(&self, path: &str) -> Built<bool> {
        Ok(self
            .stat(path, false)?
            .is_some_and(|meta| meta.file_type().is_symlink()))
    }

    /// `Path.expanduser()`: `~` and `~/...` follow `HOME`, then the passwd home.
    /// `~name` needs a passwd lookup the resident does not perform, so it fails
    /// the build (Python raised or expanded depending on the account).
    pub(super) fn expanduser(&self, path: &str) -> Built<String> {
        let parsed = PyPath::new(path);
        if parsed.is_absolute() {
            return Ok(parsed.to_string());
        }
        let Some(first) = parsed.components().first() else {
            return Ok(parsed.to_string());
        };
        if !first.starts_with('~') {
            return Ok(parsed.to_string());
        }
        if first != "~" {
            return Err(BuildError::Fatal(
                "native_package_context_home_lookup_unsupported".to_owned(),
            ));
        }
        let mut result = PyPath::new(&self.home_directory());
        for component in &parsed.components()[1..] {
            result = result.join(component);
        }
        Ok(result.to_string())
    }

    /// `os.path.expanduser("~")` for the client process.
    pub(super) fn home_directory(&self) -> String {
        let raw = self.home_env.as_deref().unwrap_or(&self.home);
        let trimmed = raw.trim_end_matches('/');
        if trimmed.is_empty() {
            "/".to_owned()
        } else {
            trimmed.to_owned()
        }
    }

    /// `Path.resolve(strict)`.
    pub(super) fn resolve(&self, path: &str, strict: bool) -> Result<String, ResolveError> {
        let absolute = if is_absolute(path) {
            path.to_owned()
        } else {
            format!("{}/{path}", self.cwd)
        };
        let mut seen = BTreeMap::new();
        let (resolved, complete) = Self::join_realpath("/", &absolute, strict, &mut seen)?;
        if !complete {
            return Err(ResolveError::Loop(format!("Symlink loop from {path}")));
        }
        Ok(normpath(&resolved))
    }

    fn join_realpath(
        start: &str,
        rest: &str,
        strict: bool,
        seen: &mut BTreeMap<String, Option<String>>,
    ) -> Result<(String, bool), ResolveError> {
        let mut path = start.to_owned();
        let mut rest = rest.to_owned();
        if is_absolute(&rest) {
            rest = rest.trim_start_matches('/').to_owned();
            path = "/".to_owned();
        }
        while !rest.is_empty() {
            let (name, remainder) = match rest.split_once('/') {
                Some((name, remainder)) => (name.to_owned(), remainder.to_owned()),
                None => (rest.clone(), String::new()),
            };
            rest = remainder;
            if name.is_empty() || name == "." {
                continue;
            }
            if name == ".." {
                path = parent_of(&path);
                continue;
            }
            let newpath = join_posix(&path, &name);
            let is_link = match fs::symlink_metadata(&newpath) {
                Ok(meta) => meta.file_type().is_symlink(),
                Err(_) if strict => return Err(ResolveError::Os),
                Err(_) => false,
            };
            if !is_link {
                path = newpath;
                continue;
            }
            if let Some(cached) = seen.get(&newpath) {
                if let Some(cached) = cached {
                    path = cached.clone();
                    continue;
                }
                return Ok((join_posix(&newpath, &rest), false));
            }
            seen.insert(newpath.clone(), None);
            let target = fs::read_link(&newpath).map_err(|_| ResolveError::Os)?;
            let target = target.to_string_lossy().into_owned();
            let (resolved, complete) = Self::join_realpath(&path, &target, strict, seen)?;
            if !complete {
                return Ok((join_posix(&resolved, &rest), false));
            }
            seen.insert(newpath, Some(resolved.clone()));
            path = resolved;
        }
        Ok((path, true))
    }

    /// `sorted(root.rglob("*"))`: every entry below `root` in `pathlib` order.
    /// Symlinked directories are listed but not entered; a directory the process
    /// may not read is skipped, as `pathlib` does.
    pub(super) fn rglob(&self, root: &str) -> Result<Vec<String>, ()> {
        let mut found: Vec<String> = Vec::new();
        let mut pending = vec![root.to_owned()];
        while let Some(directory) = pending.pop() {
            let listing = match fs::read_dir(self.fs_path(&directory)) {
                Ok(listing) => listing,
                Err(error) if error.kind() == ErrorKind::PermissionDenied => continue,
                Err(_) => return Err(()),
            };
            for entry in listing {
                let entry = entry.map_err(|_| ())?;
                let name = entry.file_name().to_string_lossy().into_owned();
                let path = format!("{}/{name}", directory.trim_end_matches('/'));
                let kind = entry.file_type().map_err(|_| ())?;
                if kind.is_dir() {
                    pending.push(path.clone());
                }
                found.push(path);
            }
        }
        found.sort_by(|left, right| {
            let left = PyPath::new(left);
            let right = PyPath::new(right);
            left.components().cmp(right.components())
        });
        Ok(found)
    }
}

/// `posixpath.split(path)[0]` for an absolute, normalised `path`.
fn parent_of(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        None | Some(0) => "/".to_owned(),
        Some(index) => trimmed[..index].trim_end_matches('/').to_owned(),
    }
}

fn join_posix(base: &str, name: &str) -> String {
    if base.is_empty() || base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Stable-file reads under the context resource budget (`ContextFiles`).
#[derive(Default)]
pub(super) struct ContextFiles {
    total_bytes: u64,
    count: usize,
}

fn unreadable() -> BuildError {
    BuildError::Unavailable("unreadable_configuration")
}

fn identity(meta: &Metadata) -> (u64, u64, u64, i128, i128) {
    (
        meta.dev(),
        meta.ino(),
        meta.size(),
        i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
        i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()),
    )
}

impl ContextFiles {
    pub(super) fn read(
        &mut self,
        fs_facts: &Fs,
        path: &str,
        maximum_bytes: u64,
        allow_symlink: bool,
    ) -> Built<Vec<u8>> {
        if !allow_symlink {
            let linked = match fs::symlink_metadata(fs_facts.fs_path(path)) {
                Ok(meta) => meta.file_type().is_symlink(),
                Err(error) if ignored_stat_error(&error) => false,
                Err(_) => return Err(unreadable()),
            };
            if linked {
                return Err(BuildError::Unavailable("symlinked_configuration"));
            }
        }
        let resolved = if allow_symlink {
            fs_facts.resolve(path, true).map_err(|_| unreadable())?
        } else {
            path.to_owned()
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(fs_facts.fs_path(&resolved))
            .map_err(|_| unreadable())?;
        let before = file.metadata().map_err(|_| unreadable())?;
        if !before.is_file() {
            return Err(BuildError::Unavailable("unsupported_configuration"));
        }
        if before.size() > maximum_bytes || self.total_bytes + before.size() > MAX_CONTEXT_BYTES {
            return Err(BuildError::Unavailable("oversized_configuration"));
        }
        let mut payload =
            Vec::with_capacity(usize::try_from(before.size().min(READ_CHUNK_BYTES)).unwrap_or(0));
        (&file)
            .take(before.size())
            .read_to_end(&mut payload)
            .map_err(|_| unreadable())?;
        let after = file.metadata().map_err(|_| unreadable())?;
        if payload.len() as u64 != before.size() || identity(&before) != identity(&after) {
            return Err(BuildError::Unavailable(
                "configuration_changed_during_review",
            ));
        }
        self.total_bytes += payload.len() as u64;
        self.count += 1;
        if self.count > MAX_TREE_FILES {
            return Err(BuildError::Unavailable("oversized_configuration"));
        }
        Ok(payload)
    }
}
