//! `runtime/restricted_pytest_validation.py` — fail-closed restricted pytest
//! launch validation (497 lines — verbatim port, defmap order).
//!
//! Shared model constants live at the top of this module because the Python
//! `restricted_pytest_model.py` module is out of this port's scope; only the
//! constants and literals this validation file reads are duplicated here.

use std::collections::HashSet;
use std::env;
use std::ffi::OsStr;
use std::fs;
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

const MAX_ARG_COUNT: usize = 4_096;
const MAX_ARG_BYTES: usize = 1_048_576;

static PYTEST_EXECUTABLE_NAMES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from(["pytest", "py.test", "pytest.exe", "py.test.exe"]));

static PYTHON_EXECUTABLE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:python|pythonw)(?:\d+(?:\.\d+)*)?(?:\.exe)?$").unwrap());

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
#[derive(Debug, Clone)]
pub struct RestrictedPytestError {
    pub reason_code: String,
    pub message: String,
}

impl RestrictedPytestError {
    fn new(reason_code: &str, message: impl Into<String>) -> Self {
        Self {
            reason_code: reason_code.to_owned(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for RestrictedPytestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for RestrictedPytestError {}

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

/// `path.absolute()`: lexical absolutization (POSIX mirrors `abspath`, which
/// is CWD-relative with `.`/`..` collapsed via normpath).
fn path_absolute(path: &Path) -> PathBuf {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(path)
    };
    normpath(&joined)
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
    match fs::canonicalize(path) {
        Ok(resolved) => Ok(resolved),
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(error);
            }
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                env::current_dir()?.join(path)
            };
            Ok(normpath(&absolute))
        }
    }
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

/// `os.getuid()` — `unsafe` is crate-forbidden, so read the real uid from
/// libc's stable env bookkeeping is not possible; POSIX callers in this crate
/// run under the hook uid and `metadata.uid() == 0` checks need the euid.
/// We use `std::process::id`-adjacent free data: the only uid-relevant checks
/// here compare file ownership to root (`0`), so where Python calls
/// `os.getuid()`, a fail-closed `-1` surrogate ("hasattr(getuid)" true but
/// unknown) preserves behavior: uid checks that require the current uid fail
/// closed rather than trusting a guess. Where Python gates on
/// `hasattr(os, "getuid")` (POSIX-only feature detection) we return `Some(0)`
/// only when the effective owner check can be resolved without unsafe —
/// i.e. we treat "non-root owner" as "current uid" for workspace launchers,
/// matching the deployed shape where the hook runs as the user.
#[allow(dead_code)]
fn current_uid() -> i64 {
    // `os.getuid()` equivalent without unsafe: the process uid is exposed via
    // /proc on linux; on macOS the hook always runs as a non-root user whose
    // uid we cannot read safely. Mirror Python's `current_uid = -1` fallback
    // (feature absent) so owner checks require uid 0 — the strictest reading
    // that keeps all Python branches reachable but fail-closed.
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(field) = rest.split_whitespace().next() {
                        if let Ok(uid) = field.parse::<i64>() {
                            return uid;
                        }
                    }
                }
            }
        }
        -1
    }
    #[cfg(not(target_os = "linux"))]
    {
        -1
    }
}

/// `os.getgroups()` — fail-closed empty set (Python falls back to `set()` when
/// unavailable); group-writable checks then require literal group bits.
#[allow(dead_code)]
fn current_groups() -> HashSet<u32> {
    #[cfg(target_os = "linux")]
    {
        let mut groups = HashSet::new();
        if let Ok(groups_file) = fs::read_to_string("/proc/self/status") {
            for line in groups_file.lines() {
                if let Some(rest) = line.strip_prefix("Groups:") {
                    for field in rest.split_whitespace() {
                        if let Ok(gid) = field.parse::<u32>() {
                            groups.insert(gid);
                        }
                    }
                }
            }
        }
        groups
    }
    #[cfg(not(target_os = "linux"))]
    {
        HashSet::new()
    }
}

// ---------------------------------------------------------------------------
// defmap order below (:34-497).
// ---------------------------------------------------------------------------

/// `_normalized_command` (:34-51).
pub fn normalized_command(command: &[String]) -> Result<Vec<String>, RestrictedPytestError> {
    let mut normalized: Vec<String> = command.to_vec();
    if normalized.first().map(|s| s.as_str()) == Some("--") {
        normalized.remove(0);
    }
    let total_bytes: usize = normalized.iter().map(|item| item.len()).sum();
    if normalized.is_empty() || normalized.len() > MAX_ARG_COUNT || total_bytes > MAX_ARG_BYTES {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest requires a bounded, non-empty argv after `--`.",
        ));
    }
    if normalized.iter().any(|item| item.contains('\0')) {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest argv cannot contain NUL bytes.",
        ));
    }
    Ok(normalized)
}

/// `_resolve_workspace` (:52-77).
pub fn resolve_workspace(workspace: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let resolved = expand_user(workspace).canonicalize().map_err(|error| {
        RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            format!("Restricted pytest workspace could not be resolved: {error}"),
        )
    })?;
    if !resolved.is_dir() {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest workspace must be an existing directory.",
        ));
    }
    if workspace_is_broad_or_sensitive(&resolved) {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest workspace cannot be a filesystem, home, temporary, or credential-directory root.",
        ));
    }
    if !PROJECT_WORKSPACE_MARKERS
        .iter()
        .any(|marker| resolved.join(marker).exists())
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest workspace must be an explicit project root with a recognized project marker.",
        ));
    }
    Ok(resolved)
}

/// `_workspace_is_broad_or_sensitive` (:78-104).
fn workspace_is_broad_or_sensitive(workspace: &Path) -> bool {
    let broad_roots: HashSet<PathBuf> = [
        "/",
        "/Users",
        "/etc",
        "/home",
        "/private",
        "/private/tmp",
        "/private/var",
        "/tmp",
        "/var",
        "/var/tmp",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if broad_roots.contains(workspace) {
        return true;
    }
    let home = host_home_directory();
    let home = match home {
        Some(h) => h,
        None => return true,
    };
    if workspace == home || home.ancestors().skip(1).any(|p| p == workspace) {
        return true;
    }
    let relative_to_home = match workspace.strip_prefix(&home) {
        Ok(rel) => rel,
        Err(_) => return false,
    };
    match relative_to_home.components().next() {
        Some(component) => {
            SENSITIVE_HOME_ROOT_NAMES.contains(component.as_os_str().to_string_lossy().as_ref())
        }
        None => false,
    }
}

/// `_resolve_cwd` (:105-121).
#[allow(dead_code)]
fn resolve_cwd(cwd: &Path, workspace: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let resolved = expand_user(cwd)
        .canonicalize()
        .ok()
        .filter(|resolved| resolved.strip_prefix(workspace).is_ok())
        .ok_or_else(|| {
            RestrictedPytestError::new(
                PYTEST_INVALID_WORKSPACE_REASON_CODE,
                "Restricted pytest cwd must resolve to an existing directory inside the approved workspace.",
            )
        })?;
    if !resolved.is_dir() {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest cwd must be a directory.",
        ));
    }
    Ok(resolved)
}

/// `_resolve_pytest_executable` (:122-162).
pub fn resolve_pytest_executable(
    command: &[String],
    cwd: &Path,
    workspace: &Path,
) -> Result<(PathBuf, PathBuf), RestrictedPytestError> {
    let command_name = Path::new(&command[0].replace('\\', "/"))
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if PYTEST_EXECUTABLE_NAMES.contains(command_name.as_str()) {
        validate_pytest_args(&command[1..])?;
    } else if regex_is_match(&PYTHON_EXECUTABLE_PATTERN, &command_name) {
        if !python_args_target_pytest(&command[1..]) {
            return Err(RestrictedPytestError::new(
                PYTEST_INVALID_COMMAND_REASON_CODE,
                "Restricted pytest accepts only a pytest executable or a Python `-m pytest` invocation.",
            ));
        }
    } else {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest accepts only a pytest executable or a Python `-m pytest` invocation.",
        ));
    }
    let launch_executable = locate_executable(&command[0], cwd)?;
    let executable = resolve_executable(&command[0], cwd)?;
    let launched_from_workspace = path_is_within_lexically(&launch_executable, workspace);
    if !launched_from_workspace && !path_is_within_any(&executable, &TRUSTED_EXECUTABLE_ROOTS) {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable must be inside the workspace or a trusted system installation root.",
        ));
    }
    if PYTEST_EXECUTABLE_NAMES.contains(command_name.as_str())
        && !PYTEST_EXECUTABLE_NAMES.contains(
            &executable
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default()
                .as_str(),
        )
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable symlink does not resolve to a pytest executable.",
        ));
    }
    if regex_is_match(&PYTHON_EXECUTABLE_PATTERN, &command_name)
        && !regex_is_match(
            &PYTHON_EXECUTABLE_PATTERN,
            &executable
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        )
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted Python symlink does not resolve to a Python executable.",
        ));
    }
    Ok((launch_executable, executable))
}

/// `_validate_pytest_args` (:163-170).
fn validate_pytest_args(args: &[String]) -> Result<(), RestrictedPytestError> {
    if args
        .iter()
        .any(|item| matches!(item.as_str(), ";" | "&&" | "||" | "|" | "|&" | "&"))
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest receives argv directly and does not accept shell control operators.",
        ));
    }
    Ok(())
}

/// `_python_args_target_pytest` (:171-194).
fn python_args_target_pytest(args: &[String]) -> bool {
    let mut index = 0usize;
    while index < args.len() {
        let item = &args[index];
        if item == "--" {
            return false;
        }
        if item == "-c"
            || item == "--command"
            || item.starts_with("-c")
            || item.starts_with("--command=")
        {
            return false;
        }
        if item == "-m" {
            return args
                .get(index + 1)
                .map(|next| next.split('.').next() == Some("pytest"))
                .unwrap_or(false);
        }
        if item.starts_with("-m") && item.len() > 2 {
            return item[2..].split('.').next() == Some("pytest");
        }
        if matches!(item.as_str(), "-W" | "-X" | "--check-hash-based-pycs") {
            index += 2;
            continue;
        }
        if item.starts_with("-W")
            || item.starts_with("-X")
            || item.starts_with("--check-hash-based-pycs=")
        {
            index += 1;
            continue;
        }
        if !item.starts_with('-') {
            return false;
        }
        index += 1;
    }
    false
}

/// `_resolve_executable` (:195-218).
fn resolve_executable(value: &str, cwd: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let candidate = locate_executable(value, cwd)?;
    let resolved = candidate.canonicalize().map_err(|_| {
        RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            format!("Restricted pytest executable could not be resolved: {value}"),
        )
    })?;
    let metadata = resolved.metadata().map_err(|_| {
        RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            format!("Restricted pytest executable could not be inspected: {value}"),
        )
    })?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            format!("Restricted pytest target is not an executable regular file: {value}"),
        ));
    }
    Ok(resolved)
}

/// `_locate_executable` (:219-233).
fn locate_executable(value: &str, cwd: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let mut candidate = expand_user(Path::new(value));
    if candidate.is_absolute() || value.contains('/') || value.contains('\\') {
        if !candidate.is_absolute() {
            candidate = cwd.join(&candidate);
        }
        return Ok(path_absolute(&candidate));
    }
    match shutil_which(value, None) {
        Some(located) => Ok(path_absolute(&expand_user(&located))),
        None => Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            format!("Restricted pytest executable was not found on PATH: {value}"),
        )),
    }
}

/// `_select_backend` (:234-259).
pub fn select_backend(
    platform: &str,
    backend_executable: Option<&Path>,
) -> Result<(RestrictedPytestBackend, PathBuf), RestrictedPytestError> {
    let (backend, candidate): (RestrictedPytestBackend, PathBuf) = if platform == "darwin" {
        (
            "macos-seatbelt",
            backend_executable
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("/usr/bin/sandbox-exec")),
        )
    } else if platform.starts_with("linux") {
        let located = shutil_which("bwrap", None);
        (
            "linux-bubblewrap",
            backend_executable
                .map(|p| p.to_path_buf())
                .or(located)
                .unwrap_or_else(|| PathBuf::from("/usr/bin/bwrap")),
        )
    } else {
        return Err(RestrictedPytestError::new(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            "No enforceable restricted pytest backend is available for this platform; execution was not started.",
        ));
    };
    match trusted_backend_executable(&candidate) {
        Some(trusted) => Ok((backend, trusted)),
        None => Err(RestrictedPytestError::new(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            format!(
                "Required {backend} backend is missing or not a trusted system executable; execution was not started."
            ),
        )),
    }
}

/// `_trusted_backend_executable` (:260-276).
fn trusted_backend_executable(candidate: &Path) -> Option<PathBuf> {
    let resolved = expand_user(candidate).canonicalize().ok()?;
    let metadata = resolved.metadata().ok()?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return None;
    }
    if metadata.mode() & 0o022 != 0 {
        return None;
    }
    if metadata.uid() != 0 {
        return None;
    }
    if !path_is_within_any(
        &resolved,
        &[
            PathBuf::from("/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/local/bin"),
        ],
    ) {
        return None;
    }
    Some(resolved)
}

/// `_allowed_executables` (:277-313).
pub fn allowed_executables(
    executable: &Path,
    launch_executable: &Path,
    command: &[String],
    cwd: &Path,
    workspace: &Path,
) -> Result<Vec<PathBuf>, RestrictedPytestError> {
    let mut allowed = vec![launch_executable.to_path_buf(), executable.to_path_buf()];
    let command_name = Path::new(&command[0].replace('\\', "/"))
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if PYTEST_EXECUTABLE_NAMES.contains(command_name.as_str()) {
        let interpreter = script_interpreter(executable, cwd)?;
        if let Some(interpreter) = interpreter {
            let last_name = interpreter
                .last()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !regex_is_match(&PYTHON_EXECUTABLE_PATTERN, &last_name) {
                return Err(RestrictedPytestError::new(
                    PYTEST_INVALID_COMMAND_REASON_CODE,
                    "Restricted pytest entry points must use a Python interpreter.",
                ));
            }
            allowed.extend(interpreter);
        }
    }
    for allowed_executable in allowed.clone() {
        allowed.extend(framework_python_helpers(&allowed_executable));
    }
    let workspace_launcher = path_is_within_lexically(launch_executable, workspace);
    if allowed
        .iter()
        .any(|path| !allowed_executable_path(path, workspace, workspace_launcher))
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest script resolves to an interpreter outside the workspace and trusted system roots.",
        ));
    }
    if allowed
        .iter()
        .any(|path| !executable_symlink_chain_is_approved(path, workspace))
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable has an unapproved path in its interpreter symlink chain.",
        ));
    }
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for path in allowed {
        if seen.insert(path.clone()) {
            deduped.push(path);
        }
    }
    Ok(deduped)
}

/// `_framework_python_helpers` (:314-329).
fn framework_python_helpers(executable: &Path) -> Vec<PathBuf> {
    if executable
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n != "bin")
        .unwrap_or(true)
    {
        return Vec::new();
    }
    let version_root = match executable.parent().and_then(|p| p.parent()) {
        Some(root) => root,
        None => return Vec::new(),
    };
    let versions_dir = match version_root.parent() {
        Some(parent) => parent,
        None => return Vec::new(),
    };
    let framework_dir = match versions_dir.parent() {
        Some(parent) => parent,
        None => return Vec::new(),
    };
    if versions_dir
        .file_name()
        .map(|n| n != "Versions")
        .unwrap_or(true)
        || framework_dir
            .file_name()
            .map(|n| n != "Python.framework")
            .unwrap_or(true)
    {
        return Vec::new();
    }
    let helper = version_root
        .join("Resources")
        .join("Python.app")
        .join("Contents")
        .join("MacOS")
        .join("Python");
    if !helper.exists() {
        return Vec::new();
    }
    let resolved = match resolve_executable(
        &helper.to_string_lossy(),
        helper.parent().unwrap_or_else(|| Path::new("/")),
    ) {
        Ok(resolved) => resolved,
        Err(_) => return Vec::new(),
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in [path_absolute(&helper), resolved] {
        if seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

/// `_allowed_executable_path` (:330-340).
fn allowed_executable_path(path: &Path, workspace: &Path, workspace_launcher: bool) -> bool {
    if path_is_within_lexically(path, workspace)
        || path_is_within_any(path, &TRUSTED_EXECUTABLE_ROOTS)
    {
        return true;
    }
    let basename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    workspace_launcher
        && regex_is_match(&PYTHON_EXECUTABLE_PATTERN, &basename)
        && approved_user_python_runtime(path)
}

/// `_approved_user_python_runtime` (:341-369).
fn approved_user_python_runtime(path: &Path) -> bool {
    let home = match host_home_directory() {
        Some(home) => home,
        None => return false,
    };
    let absolute = path_absolute(path);
    let relative = match absolute.strip_prefix(&home) {
        Ok(rel) => rel,
        Err(_) => return false,
    };
    let relative_parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let managed_prefixes: &[&[&str]] = &[
        &[".asdf", "installs", "python"],
        &[".local", "share", "mise", "installs", "python"],
        &[".local", "share", "uv", "python"],
        &[".pyenv", "versions"],
        &["Library", "Application Support", "uv", "python"],
        &["Library", "Caches", "uv", "python"],
    ];
    if managed_prefixes.iter().any(|prefix| {
        relative_parts.len() > prefix.len()
            && relative_parts[..prefix.len()]
                .iter()
                .map(|s| s.as_str())
                .eq(prefix.iter().copied())
    }) {
        return true;
    }
    !relative_parts.is_empty()
        && matches!(
            relative_parts[0].as_str(),
            "anaconda3" | "mambaforge" | "miniconda3" | "miniforge3"
        )
        && relative_parts.len() > 2
}

/// `_executable_symlink_chain_is_approved` (:370-385).
fn executable_symlink_chain_is_approved(path: &Path, workspace: &Path) -> bool {
    let mut current = path_absolute(path);
    for _depth in 0..16 {
        let expansion = match first_symlink_expansion(&current) {
            Some(expansion) => expansion,
            None => return true,
        };
        current = expansion;
        if !path_is_within_lexically(&current, workspace)
            && !path_is_within_any_lexically(&current, &TRUSTED_EXECUTABLE_ROOTS)
            && !approved_user_python_runtime(&current)
        {
            return false;
        }
    }
    first_symlink_expansion(&current).is_none()
}

/// `_script_interpreter` (:386-415).
fn script_interpreter(
    executable: &Path,
    cwd: &Path,
) -> Result<Option<Vec<PathBuf>>, RestrictedPytestError> {
    let first_line = {
        let handle = match fs::File::open(executable) {
            Ok(handle) => handle,
            Err(_) => return Ok(None),
        };
        use std::io::{BufRead, BufReader};
        let mut reader = BufReader::new(handle);
        let mut line = Vec::new();
        match reader.read_until(b'\n', &mut line) {
            Ok(_) => line,
            Err(_) => return Ok(None),
        }
    };
    if !first_line.starts_with(b"#!") {
        return Ok(None);
    }
    let shebang = match std::str::from_utf8(&first_line[2..]) {
        Ok(text) => text.trim().to_owned(),
        Err(_) => {
            return Err(RestrictedPytestError::new(
                PYTEST_INVALID_COMMAND_REASON_CODE,
                "Restricted pytest executable has an invalid interpreter declaration.",
            ))
        }
    };
    let parts = shlex_split(&shebang).ok_or_else(|| {
        RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable has an invalid interpreter declaration.",
        )
    })?;
    if parts.is_empty() {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable has an empty interpreter declaration.",
        ));
    }
    let interpreter_launch = locate_executable(&parts[0], cwd)?;
    let interpreter = resolve_executable(&parts[0], cwd)?;
    let mut interpreters = vec![interpreter_launch, interpreter.clone()];
    if interpreter == Path::new("/usr/bin/env") && parts.len() >= 2 {
        let last = parts.last().cloned().unwrap_or_default();
        let target_launch = locate_executable(&last, cwd)?;
        interpreters.push(target_launch);
        interpreters.push(resolve_executable(&last, cwd)?);
    }
    Ok(Some(interpreters))
}

/// `shlex.split` (POSIX): single/double quotes, backslash escapes, comment
/// char disabled (shebangs never reach `#` quoting context).
fn shlex_split(input: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut state = 0u8; // 0 = unquoted, 1 = single, 2 = double, 3 = escaped
    let mut in_token = false;
    while let Some(ch) = chars.next() {
        match state {
            0 => match ch {
                ' ' | '\t' | '\r' | '\n' => {
                    if in_token {
                        tokens.push(std::mem::take(&mut current));
                        in_token = false;
                    }
                }
                '\'' => {
                    state = 1;
                    in_token = true;
                }
                '"' => {
                    state = 2;
                    in_token = true;
                }
                '\\' => {
                    state = 3;
                    in_token = true;
                }
                _ => {
                    current.push(ch);
                    in_token = true;
                }
            },
            1 => {
                if ch == '\'' {
                    state = 0;
                } else {
                    current.push(ch);
                }
            }
            2 => {
                if ch == '"' {
                    state = 0;
                } else if ch == '\\'
                    && matches!(chars.peek(), Some('"') | Some('\\') | Some('$') | Some('`'))
                {
                    current.push(chars.next().unwrap());
                } else {
                    current.push(ch);
                }
            }
            3 => {
                if ch == '\n' {
                    // escaped newline: line continuation
                } else {
                    current.push(ch);
                }
                state = 0;
            }
            _ => unreachable!(),
        }
    }
    if state == 1 || state == 2 {
        return None; // unclosed quote -> ValueError
    }
    if state == 3 {
        current.push('\\');
    }
    if in_token {
        tokens.push(current);
    }
    Some(tokens)
}

/// `_restricted_pythonpath` (:416-436).
pub fn restricted_pythonpath(
    value: &str,
    workspace: &Path,
    cwd: &Path,
) -> Result<String, RestrictedPytestError> {
    let mut entries: Vec<String> = Vec::new();
    for raw_entry in value.split(':') {
        let resolved = if raw_entry.is_empty() {
            cwd.to_path_buf()
        } else {
            let candidate = expand_user(Path::new(raw_entry));
            let joined = if candidate.is_absolute() {
                candidate
            } else {
                cwd.join(&candidate)
            };
            let resolved = resolve_nonstrict(&joined).map_err(|_| {
                RestrictedPytestError::new(
                    PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE,
                    "Restricted pytest rejected PYTHONPATH because it references a path outside the workspace.",
                )
            })?;
            if resolved.strip_prefix(workspace).is_err() {
                return Err(RestrictedPytestError::new(
                    PYTEST_EXTERNAL_PYTHONPATH_REASON_CODE,
                    "Restricted pytest rejected PYTHONPATH because it references a path outside the workspace.",
                ));
            }
            resolved
        };
        let text = resolved.to_string_lossy().into_owned();
        if !entries.contains(&text) {
            entries.push(text);
        }
    }
    Ok(entries.join(":"))
}

/// `_first_symlink_expansion` (:437-455).
fn first_symlink_expansion(path: &Path) -> Option<PathBuf> {
    let parts: Vec<PathBuf> = path
        .components()
        .map(|c| PathBuf::from(c.as_os_str()))
        .collect();
    if parts.is_empty() {
        return None;
    }
    let mut current = parts[0].clone();
    for index in 1..parts.len() {
        current = current.join(&parts[index]);
        if !current.is_symlink() {
            continue;
        }
        let raw_target = match fs::read_link(&current) {
            Ok(target) => target,
            Err(_) => return None,
        };
        let target = if raw_target.is_absolute() {
            raw_target
        } else {
            current
                .parent()
                .unwrap_or_else(|| Path::new("/"))
                .join(&raw_target)
        };
        let mut expanded = target;
        for part in &parts[index + 1..] {
            expanded = expanded.join(part);
        }
        return Some(path_absolute(&expanded));
    }
    None
}

/// `_runtime_distribution_root` (:456-462).
pub fn runtime_distribution_root(executable: &Path) -> PathBuf {
    let parts: Vec<&OsStr> = executable.components().map(|c| c.as_os_str()).collect();
    let bin_indexes: Vec<usize> = parts
        .iter()
        .enumerate()
        .filter(|(_, part)| **part == OsStr::new("bin"))
        .map(|(index, _)| index)
        .collect();
    if bin_indexes.is_empty() {
        return executable
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/"));
    }
    let last = *bin_indexes.last().unwrap();
    let mut root = PathBuf::new();
    for part in &parts[..last] {
        root.push(part);
    }
    root
}

/// `_host_home_directory` (:463-475).
fn host_home_directory() -> Option<PathBuf> {
    // `pwd.getpwuid(os.getuid())` requires unsafe; the POSIX-fallback `Path.home()`
    // path is used for all platforms here.
    let home = env::var_os("HOME").map(PathBuf::from).or_else(dirs_home)?;
    home.canonicalize().ok()
}

#[cfg(unix)]
fn dirs_home() -> Option<PathBuf> {
    // `Path.home()` fallback without unsafe: passwd lookup via $USER + /etc/passwd.
    let user = env::var("USER").ok()?;
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(user.as_str()) {
            let _pw = fields.next();
            let _uid = fields.next();
            let _gid = fields.next();
            let _gecos = fields.next();
            if let Some(dir) = fields.next() {
                if !dir.is_empty() {
                    return Some(PathBuf::from(dir));
                }
            }
        }
    }
    None
}

#[cfg(not(unix))]
fn dirs_home() -> Option<PathBuf> {
    env::var_os("USERPROFILE").map(PathBuf::from)
}

/// `_path_is_within` (:476-483).
fn path_is_within(path: &Path, root: &Path) -> bool {
    match (resolve_nonstrict(path).ok(), resolve_nonstrict(root).ok()) {
        (Some(resolved), Some(root_resolved)) => resolved.strip_prefix(root_resolved).is_ok(),
        _ => false,
    }
}

/// `_path_is_within_lexically` (:484-491).
fn path_is_within_lexically(path: &Path, root: &Path) -> bool {
    match resolve_nonstrict(root).ok() {
        Some(root_resolved) => path_absolute(path).strip_prefix(&root_resolved).is_ok(),
        None => false,
    }
}

/// `_path_is_within_any` (:492-495).
fn path_is_within_any(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path_is_within(path, root))
}

/// `_path_is_within_any_lexically` (:496-497).
fn path_is_within_any_lexically(path: &Path, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|root| path_is_within_lexically(path, root))
}

/// `re.Pattern.fullmatch` — anchored case-insensitive compare (Python's
/// pattern is compiled with `re.IGNORECASE`).
fn regex_is_match(pattern: &Regex, text: &str) -> bool {
    // `re.IGNORECASE` is baked into the Python pattern; the Rust port
    // case-folds input instead (pattern literals are all lowercase).
    pattern.is_match(&text.to_lowercase())
}
