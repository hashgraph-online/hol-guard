//! Restricted execution admission, environment filtering and runtime read grants.

use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

// ---------------------------------------------------------------------------
// `restricted_pytest_model.py` literals consumed by this module (:31-89).
// ---------------------------------------------------------------------------

pub const PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE: &str = "pytest_restricted_sandbox_unavailable";
pub const PYTEST_INVALID_COMMAND_REASON_CODE: &str = "pytest_restricted_invalid_command";
pub const PYTEST_INVALID_WORKSPACE_REASON_CODE: &str = "pytest_restricted_invalid_workspace";
pub const PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE: &str = "pytest_restricted_external_pythonpath";

/// `RestrictedPytestBackend` (:37).
pub type RestrictedPytestBackend = &'static str;

static PYTEST_EXECUTABLE_NAMES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from(["pytest", "py.test", "pytest.exe", "py.test.exe"]));

static PYTHON_EXECUTABLE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(?:python|pythonw)(?:\d+(?:\.\d+)*)?(?:\.exe)?$").unwrap());

const PROJECT_WORKSPACE_MARKERS: &[&str] = &[
    ".git",
    "pyproject.toml",
    "pytest.ini",
    "setup.cfg",
    "setup.py",
    "tox.ini",
    "package.json",
];

static SENSITIVE_HOME_ROOT_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        ".aws", ".azure", ".config", ".docker", ".gnupg", ".kube", ".ssh", "Library",
    ])
});

static TRUSTED_EXECUTABLE_ROOTS: LazyLock<Vec<PathBuf>> = LazyLock::new(|| {
    vec![
        PathBuf::from("/bin"),
        PathBuf::from("/opt/homebrew"),
        PathBuf::from("/opt/hostedtoolcache/Python"),
        PathBuf::from("/System"),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/usr/local"),
    ]
});

// ---------------------------------------------------------------------------
// `RestrictedPytestError` (restricted_pytest_model.py :95).
// ---------------------------------------------------------------------------

/// `RestrictedPytestError` — reason-coded fail-closed error.
use crate::restricted_command::{normalized_command, RestrictedPytestError};

// ---------------------------------------------------------------------------
// Path/executable primitives used below.
// ---------------------------------------------------------------------------

/// `Path.expanduser`: POSIX `~`/`~/` expansion against `$HOME`.
fn expand_user(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if text == "~" {
        if let Some(home) = env::var_os("HOME") {
            return PathBuf::from(home);
        }
        return path.to_path_buf();
    }
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = env::var_os("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    path.to_path_buf()
}

/// `Path.absolute()`: anchor to cwd without resolving parent components.
fn path_absolute(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    let absolute: PathBuf = joined.components().collect();
    if joined.to_string_lossy().starts_with("//") && !joined.to_string_lossy().starts_with("///") {
        PathBuf::from(format!("/{}", absolute.display()))
    } else {
        absolute
    }
}

/// POSIX `os.path.normpath`: collapse `.`, redundant separators, and `..`
/// lexically (no filesystem access).
fn normpath(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    let rooted = text.starts_with('/');
    let mut stack: Vec<String> = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                if stack.last().map(|p| p.as_str() != "..").unwrap_or(false) {
                    stack.pop();
                } else if !rooted {
                    stack.push("..".to_owned());
                }
            }
            other => stack.push(other.to_owned()),
        }
    }
    let body = stack.join("/");
    if rooted {
        PathBuf::from(format!("/{body}"))
    } else if body.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(body)
    }
}

/// `Path.resolve(strict=False)` — POSIX canonicalize that tolerates missing
/// trailing components (lexically normalizes the unresolved tail).
fn resolve_nonstrict(path: &Path) -> Result<PathBuf, std::io::Error> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    let parts = |path: &Path| {
        path.components()
            .filter_map(|part| match part {
                std::path::Component::Normal(value) => Some(value.to_os_string()),
                std::path::Component::ParentDir => Some(std::ffi::OsString::from("..")),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let mut pending: std::collections::VecDeque<_> = parts(&absolute).into();
    let mut resolved = PathBuf::from("/");
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let candidate = resolved.join(part);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.is_symlink() => {
                links += 1;
                if links > 40 {
                    return Err(std::io::Error::from_raw_os_error(libc::ELOOP));
                }
                let target = fs::read_link(&candidate)?;
                if target.is_absolute() {
                    resolved = PathBuf::from("/");
                }
                for part in parts(&target).into_iter().rev() {
                    pending.push_front(part);
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return Err(error),
            _ => resolved = candidate,
        }
    }
    Ok(resolved)
}

/// `shutil.which(value)`: locate `value` on `PATH` honoring PATHEXT-free
/// POSIX semantics (existence + executable bit).
fn shutil_which(value: &str, path_env: Option<&str>) -> Option<PathBuf> {
    if value.contains('/') || value.contains('\\') {
        let candidate = Path::new(value);
        return executable_file(candidate).then(|| candidate.to_path_buf());
    }
    let path = path_env
        .map(|p| p.to_owned())
        .or_else(|| env::var("PATH").ok())
        .unwrap_or_else(|| "/bin:/usr/bin".to_owned());
    for entry in path.split(':') {
        let directory = if entry.is_empty() { "." } else { entry };
        let candidate = Path::new(directory).join(value);
        if executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn executable_file(candidate: &Path) -> bool {
    match candidate.metadata() {
        Ok(metadata) => metadata.is_file() && metadata.mode() & 0o111 != 0,
        Err(_) => false,
    }
}

mod authority;
mod contained;
#[cfg(test)]
mod contained_tests;
mod credentials;
mod environment;
mod executables;
mod mapping;
mod mapping_elf;
mod mapping_snapshot;
mod paths;
mod profiles;
mod toolchains;
mod user_site;
mod validation;
mod venv;
mod workspace;
mod workspace_linked;
mod workspace_linux;
mod workspace_overlay;
pub fn evaluate_with_deadline(
    operation: &str,
    input: &serde_json::Value,
    deadline: std::time::Instant,
) -> serde_json::Value {
    mapping::evaluate(operation, input, deadline).unwrap_or_else(|| evaluate(operation, input))
}
pub use authority::evaluate;
pub(crate) use environment::forwarded_setting;
pub use mapping::evidence as mapping_evidence;
pub use workspace::workspace_script_reads;
pub(crate) use workspace::{exact_shape as workspace_exact_shape, workspace_admissible};
pub(crate) use workspace_linux::available as linux_workspace_sandbox_available;
#[cfg(test)]
mod parity_tests;
use executables::*;
use paths::*;
use toolchains::workspace_exec_roots;
use validation::*;
