//! The pathlib/os/shutil behaviours the Python shim code relied on.
//!
//! Paths are handled as strings because the results are rendered into
//! generated files and JSON, where Python's `str(Path)` spelling matters.
//! Every relative path is taken against [`ShimFacts::cwd`], never against the
//! resident's own working directory.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use super::winpath::{nt_is_within, nt_normcase, WinPath};
use super::{ShimFacts, ShimResult};
use crate::codex_output_py::PyPath;

/// `pathlib` normalisation: drop empty and `.` segments, keep a double leading
/// slash, and spell an empty path `.`.
pub(crate) fn py_norm(path: &str) -> String {
    PyPath::new(path).to_string()
}

/// `posixpath.normpath`.
pub(crate) fn py_normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let initial = if path.starts_with("//") && !path.starts_with("///") {
        2
    } else {
        usize::from(path.starts_with('/'))
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        let keeps_parent =
            part != ".." || (initial == 0 && parts.is_empty()) || parts.last() == Some(&"..");
        if keeps_parent {
            parts.push(part);
        } else if !parts.is_empty() {
            parts.pop();
        }
    }
    let joined = format!("{}{}", "/".repeat(initial), parts.join("/"));
    if joined.is_empty() {
        ".".to_owned()
    } else {
        joined
    }
}

/// `Path(base) / child`.
pub(crate) fn py_join(base: &str, child: &str) -> String {
    PyPath::new(base).join(child).to_string()
}

/// `Path(path).name`.
pub(crate) fn py_name(path: &str) -> String {
    PyPath::new(path).name().to_owned()
}

/// `str(Path(path).parent)`.
pub(crate) fn py_parent(path: &str) -> String {
    PyPath::new(path).parent().to_string()
}

pub(crate) fn is_absolute(path: &str) -> bool {
    PyPath::new(path).is_absolute()
}

/// Why `read_text` failed; Python caught only the first kind in most callers.
#[derive(Debug)]
pub(crate) enum ReadError {
    Io(String),
    Decode,
}

impl ReadError {
    pub(crate) fn message(&self, path: &str) -> String {
        match self {
            Self::Io(text) => format!("cannot read {path}: {text}"),
            Self::Decode => format!("cannot decode {path} as UTF-8"),
        }
    }
}

/// `Path.read_text` newline handling: `\r\n` and `\r` become `\n`.
pub(crate) fn universal_newlines(text: &str) -> String {
    if !text.contains('\r') {
        return text.to_owned();
    }
    text.replace("\r\n", "\n").replace('\r', "\n")
}

impl ShimFacts {
    /// `str(Path(path))` in the request's path flavour.
    pub(crate) fn norm(&self, path: &str) -> String {
        if self.windows {
            WinPath::new(path).to_string()
        } else {
            py_norm(path)
        }
    }

    /// `str(Path(base) / child)`.
    pub(crate) fn join(&self, base: &str, child: &str) -> String {
        if self.windows {
            WinPath::new(base).join(child).to_string()
        } else {
            py_join(base, child)
        }
    }

    /// `Path(path).name`.
    pub(crate) fn name(&self, path: &str) -> String {
        if self.windows {
            WinPath::new(path).name()
        } else {
            py_name(path)
        }
    }

    /// `str(Path(path).parent)`.
    pub(crate) fn parent(&self, path: &str) -> String {
        if self.windows {
            WinPath::new(path).parent().to_string()
        } else {
            py_parent(path)
        }
    }

    /// `Path(path).is_absolute()`.
    pub(crate) fn is_abs(&self, path: &str) -> bool {
        if self.windows {
            WinPath::new(path).is_absolute()
        } else {
            is_absolute(path)
        }
    }

    /// `Path(left) == Path(right)`: case- and separator-insensitive on Windows.
    pub(crate) fn path_eq(&self, left: &str, right: &str) -> bool {
        if self.windows {
            nt_normcase(&WinPath::new(left).to_string())
                == nt_normcase(&WinPath::new(right).to_string())
        } else {
            left == right
        }
    }

    /// `Path(path).relative_to(Path(root))` succeeding (`path` is `root` or below it).
    pub(crate) fn is_within(&self, path: &str, root: &str) -> bool {
        if self.windows {
            return nt_is_within(path, root);
        }
        path == root || path.starts_with(&format!("{}/", root.trim_end_matches('/')))
    }

    /// A filesystem path for `path`, absolutised against the facts' cwd.
    pub(crate) fn fs_path(&self, path: &str) -> PathBuf {
        if self.is_abs(path) {
            PathBuf::from(path)
        } else if path.is_empty() {
            PathBuf::from(&self.cwd)
        } else {
            PathBuf::from(&self.cwd).join(path)
        }
    }

    pub(crate) fn exists(&self, path: &str) -> bool {
        fs::metadata(self.fs_path(path)).is_ok()
    }

    pub(crate) fn is_file(&self, path: &str) -> bool {
        fs::metadata(self.fs_path(path)).is_ok_and(|meta| meta.is_file())
    }

    pub(crate) fn is_dir(&self, path: &str) -> bool {
        fs::metadata(self.fs_path(path)).is_ok_and(|meta| meta.is_dir())
    }

    pub(crate) fn is_symlink(&self, path: &str) -> bool {
        fs::symlink_metadata(self.fs_path(path)).is_ok_and(|meta| meta.file_type().is_symlink())
    }

    /// `Path.expanduser()`; only `~` and `~/...` are expanded. Python also
    /// resolves `~name` through the user database and raises when the user is
    /// unknown; the resident does not consult it and leaves such paths as is.
    pub(crate) fn expanduser(&self, path: &str) -> ShimResult<String> {
        if self.windows {
            return self.expanduser_nt(path);
        }
        Ok(self.posix_expanduser(path))
    }

    fn posix_expanduser(&self, path: &str) -> String {
        let norm = py_norm(path);
        let first = norm.split('/').next().unwrap_or("");
        if norm.starts_with('/') || first != "~" {
            return norm;
        }
        let home = match self.environ.get("HOME") {
            Some(value) => value.trim_end_matches('/').to_owned(),
            None => self.home.trim_end_matches('/').to_owned(),
        };
        let home = if home.is_empty() {
            "/".to_owned()
        } else {
            home
        };
        let rest = norm.strip_prefix('~').unwrap_or("").trim_start_matches('/');
        if rest.is_empty() {
            py_norm(&home)
        } else {
            py_join(&home, rest)
        }
    }

    /// `os.path.abspath(os.path.expanduser(path))`.
    pub(crate) fn expanded_abspath(&self, path: &str) -> String {
        if self.windows {
            return self.nt_abspath(&self.expanduser_os_nt(path));
        }
        let expanded = self.posix_expanduser(path);
        if is_absolute(&expanded) {
            py_normpath(&expanded)
        } else {
            py_normpath(&format!("{}/{expanded}", self.cwd))
        }
    }

    /// `Path.absolute()` (no symlink resolution, no `..` collapsing).
    pub(crate) fn absolute(&self, path: &str) -> String {
        self.join(&self.cwd, path)
    }

    /// `Path.resolve()` (non-strict): `posixpath` or `ntpath` real-path semantics.
    pub(crate) fn resolve(&self, path: &str) -> ShimResult<String> {
        if self.windows {
            return Ok(self.resolve_nt(path));
        }
        let absolute = if is_absolute(path) {
            path.to_owned()
        } else {
            format!("{}/{path}", self.cwd)
        };
        let mut seen: BTreeMap<String, Option<String>> = BTreeMap::new();
        let (resolved, _ok) = Self::join_realpath("/", &absolute, &mut seen)?;
        Ok(py_normpath(&resolved))
    }

    fn join_realpath(
        start: &str,
        rest: &str,
        seen: &mut BTreeMap<String, Option<String>>,
    ) -> ShimResult<(String, bool)> {
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
                path = py_parent_posix(&path);
                continue;
            }
            let newpath = join_posix(&path, &name);
            let is_link = fs::symlink_metadata(&newpath)
                .map(|meta| meta.file_type().is_symlink())
                .unwrap_or(false);
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
            let target = fs::read_link(&newpath)
                .map_err(|error| format!("cannot read link {newpath}: {error}"))?;
            let target = target.to_string_lossy().into_owned();
            let (resolved, ok) = Self::join_realpath(&path, &target, seen)?;
            if !ok {
                return Ok((join_posix(&resolved, &rest), false));
            }
            seen.insert(newpath, Some(resolved.clone()));
            path = resolved;
        }
        Ok((path, true))
    }

    /// `os.access(path, X_OK)`.
    #[cfg(unix)]
    pub(super) fn access_executable(&self, path: &str) -> bool {
        nix::unistd::access(&self.fs_path(path), nix::unistd::AccessFlags::X_OK).is_ok()
    }

    #[cfg(not(unix))]
    pub(super) fn access_executable(&self, _path: &str) -> bool {
        true
    }

    /// `os.access(path, X_OK)` for callers outside this file.
    pub(crate) fn is_executable(&self, path: &str) -> bool {
        self.access_executable(path)
    }

    /// `shutil.which(command, path=search_path)` with the facts' environment.
    pub(crate) fn which(&self, command: &str, search_path: &str) -> Option<String> {
        if self.windows {
            return self.which_nt(command, search_path);
        }
        let check = |candidate: &str| {
            self.exists(candidate) && self.access_executable(candidate) && !self.is_dir(candidate)
        };
        if command.contains('/') {
            return check(command).then(|| command.to_owned());
        }
        if search_path.is_empty() {
            return None;
        }
        let mut seen: Vec<String> = Vec::new();
        for directory in search_path.split(':') {
            if seen.iter().any(|entry| entry == directory) {
                continue;
            }
            seen.push(directory.to_owned());
            let candidate = if directory.is_empty() {
                command.to_owned()
            } else if directory.ends_with('/') {
                format!("{directory}{command}")
            } else {
                format!("{directory}/{command}")
            };
            if check(&candidate) {
                return Some(candidate);
            }
        }
        None
    }

    pub(crate) fn read_bytes(&self, path: &str) -> Result<Vec<u8>, ReadError> {
        fs::read(self.fs_path(path)).map_err(|error| ReadError::Io(error.to_string()))
    }

    /// `Path.read_text(encoding="utf-8")`.
    pub(crate) fn read_text(&self, path: &str) -> Result<String, ReadError> {
        let bytes = self.read_bytes(path)?;
        let text = String::from_utf8(bytes).map_err(|_| ReadError::Decode)?;
        Ok(universal_newlines(&text))
    }

    /// `Path.write_text(text, encoding="utf-8")`.
    pub(crate) fn write_text(&self, path: &str, text: &str) -> ShimResult<()> {
        // Newline translation is the host platform's, as in `Path.write_text`.
        let payload = if cfg!(windows) {
            text.replace('\n', "\r\n")
        } else {
            text.to_owned()
        };
        fs::write(self.fs_path(path), payload)
            .map_err(|error| format!("cannot write {path}: {error}"))
    }

    /// `Path.mkdir(parents=True, exist_ok=True)`.
    pub(crate) fn mkdir_parents(&self, path: &str) -> ShimResult<()> {
        fs::create_dir_all(self.fs_path(path))
            .map_err(|error| format!("cannot create {path}: {error}"))
    }

    pub(crate) fn unlink(&self, path: &str) -> ShimResult<()> {
        fs::remove_file(self.fs_path(path))
            .map_err(|error| format!("cannot remove {path}: {error}"))
    }

    /// `path.chmod(path.stat().st_mode | 0o755)`.
    #[cfg(unix)]
    pub(crate) fn add_executable_bits(&self, path: &str) -> ShimResult<()> {
        use std::os::unix::fs::PermissionsExt;
        let target = self.fs_path(path);
        let meta = fs::metadata(&target).map_err(|error| format!("cannot stat {path}: {error}"))?;
        let mode = meta.permissions().mode() | 0o755;
        fs::set_permissions(&target, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot chmod {path}: {error}"))
    }

    #[cfg(not(unix))]
    pub(crate) fn add_executable_bits(&self, _path: &str) -> ShimResult<()> {
        Ok(())
    }
}

fn join_posix(base: &str, name: &str) -> String {
    if name.starts_with('/') {
        name.to_owned()
    } else if base.is_empty() || base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// `posixpath.split(path)[0]` for an absolute, normalised `path`.
fn py_parent_posix(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        None => "/".to_owned(),
        Some(0) => "/".to_owned(),
        Some(index) => trimmed[..index].trim_end_matches('/').to_owned(),
    }
}
