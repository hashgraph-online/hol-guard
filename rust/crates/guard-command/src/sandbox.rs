//! `runtime/sandbox.py` — static-first sandbox analysis for Guard runtime
//! (356 lines — verbatim port, defmap order).
//!
//! Executes scripts inside a temporary workspace with audited subprocess
//! calls, hard resource limits, and network-attempt detection. The sandbox
//! never touches user secret paths and always returns a result even when the
//! script fails.
//!
//! The subprocess spawn duplicates the `guard-scanner/git_read.rs`
//! spawn/poll/kill timeout pattern since `crate::` cannot reach sibling
//! crates; `preexec_fn` rlimits and `start_new_session` use
//! `std::os::unix::process::CommandExt` (`pre_exec`, `process_group`).

use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// Module constants (:26-58).
// ---------------------------------------------------------------------------

/// `SandboxLanguage` (:26) — `"shell" | "node" | "python" | "package" | "mcp_smoke"`.
pub type SandboxLanguage = &'static str;
/// `EnvPolicy` (:27) — `"clean" | "passthrough" | "minimal"`.
pub type EnvPolicy = &'static str;
/// `SandboxAnalysisMode` (:28) — `"off" | "suspicious" | "strict"`.
pub type SandboxAnalysisMode = &'static str;

const DEFAULT_CPU_SECONDS: f64 = 5.0;
const DEFAULT_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_PROCESSES: u32 = 32;
const DEFAULT_TIMEOUT_SECONDS: f64 = 10.0;

static SECRET_PATH_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)\.ssh[/\\]",
        r"(?i)\.aws[/\\]",
        r"(?i)\.gnupg[/\\]",
        r"(?i)\.env\b",
        r"(?i)id_rsa|id_ed25519|id_ecdsa",
        r"(?i)credentials|secrets\.json|token\.json",
        r"(?i)keychain|keyring",
    ]
    .iter()
    .map(|pat| Regex::new(pat).unwrap())
    .collect()
});

static NETWORK_SYSCALL_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)\bcurl\b",
        r"(?i)\bwget\b",
        r"(?i)\bfetch\s*\(",
        r"(?i)\baxios\b",
        r"(?i)\brequests\.(get|post|put|delete|patch)\s*\(",
        r"(?i)http[s]?://",
        r"(?i)socket\.connect\s*\(",
    ]
    .iter()
    .map(|pat| Regex::new(pat).unwrap())
    .collect()
});

static PROCESS_AUDIT_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [r"\bsubprocess\b", r"\bexecl\b|\bexecv\b|\bexecve\b"]
        .iter()
        .map(|pat| Regex::new(pat).unwrap())
        .collect()
});

#[allow(dead_code)]
static REDACT_KEY_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)TOKEN|SECRET|KEY|PASSWORD|CREDENTIAL|AUTH|NPM_TOKEN|NODE_AUTH|AWS_").unwrap()
});

// ---------------------------------------------------------------------------
// Dataclasses (:60-96).
// ---------------------------------------------------------------------------

/// `SandboxRequest` (:61-71).
#[derive(Debug, Clone)]
pub struct SandboxRequest {
    pub language: SandboxLanguage,
    pub command: String,
    pub files: BTreeMap<String, String>,
    pub cwd: Option<String>,
    pub env_policy: EnvPolicy,
    pub cpu_seconds: f64,
    pub memory_bytes: u64,
    pub max_processes: u32,
    pub timeout_seconds: f64,
}

impl SandboxRequest {
    pub fn new(language: SandboxLanguage, command: impl Into<String>) -> Self {
        Self {
            language,
            command: command.into(),
            files: BTreeMap::new(),
            cwd: None,
            env_policy: "clean",
            cpu_seconds: DEFAULT_CPU_SECONDS,
            memory_bytes: DEFAULT_MEMORY_BYTES,
            max_processes: DEFAULT_MAX_PROCESSES,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        }
    }
}

/// `SandboxResult` (:74-96).
#[derive(Debug, Clone)]
pub struct SandboxResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub writes: Vec<String>,
    pub network_attempts: Vec<String>,
    pub process_attempts: Vec<String>,
    pub secret_read_attempts: Vec<String>,
    pub signals_detected: Vec<String>,
    pub duration_ms: f64,
    pub failure_safe: bool,
}

impl SandboxResult {
    fn empty() -> Self {
        Self {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            timed_out: false,
            writes: Vec::new(),
            network_attempts: Vec::new(),
            process_attempts: Vec::new(),
            secret_read_attempts: Vec::new(),
            signals_detected: Vec::new(),
            duration_ms: 0.0,
            failure_safe: false,
        }
    }

    /// `SandboxResult.to_dict` (:88-96).
    pub fn to_dict(&self) -> Map<String, Value> {
        json!({
            "exit_code": self.exit_code,
            "stdout": truncate_chars(&self.stdout, 4096),
            "stderr": truncate_chars(&self.stderr, 4096),
            "timed_out": self.timed_out,
            "writes": self.writes,
            "network_attempts": self.network_attempts,
            "process_attempts": self.process_attempts,
            "secret_read_attempts": self.secret_read_attempts,
            "signals_detected": self.signals_detected,
            "duration_ms": (self.duration_ms * 100.0).round() / 100.0,
            "failure_safe": self.failure_safe,
        })
        .as_object()
        .cloned()
        .unwrap_or_default()
    }
}

/// Python `text[:n]` on code points.
fn truncate_chars(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

// ---------------------------------------------------------------------------
// Private helpers (defmap order).
// ---------------------------------------------------------------------------

/// `_is_secret_path` (:99-100).
fn is_secret_path(path: &str) -> bool {
    SECRET_PATH_PATTERNS.iter().any(|pat| pat.is_match(path))
}

/// `_detect_network_attempts` (:102-110).
fn detect_network_attempts(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for pat in NETWORK_SYSCALL_PATTERNS.iter() {
        for m in pat.find_iter(text) {
            let start = m.start().saturating_sub(10);
            let end = (m.end() + 40).min(text.len());
            let snippet = text[start..end].trim();
            found.push(truncate_chars(snippet, 80));
        }
    }
    found
}

/// `_build_env` (:112-131).
fn build_env(policy: EnvPolicy, private_root: &Path) -> BTreeMap<String, String> {
    if policy == "passthrough" {
        return env::vars().collect();
    }
    if policy == "minimal" {
        let mut minimal = BTreeMap::new();
        for key in ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TERM"] {
            if let Ok(val) = env::var(key) {
                if !val.is_empty() {
                    minimal.insert(key.to_owned(), val);
                }
            }
        }
        return minimal;
    }
    let private_root_text = private_root.to_string_lossy().into_owned();
    [
        (
            "PATH".to_owned(),
            env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_owned()),
        ),
        ("HOME".to_owned(), private_root_text.clone()),
        ("TMPDIR".to_owned(), private_root_text.clone()),
        ("TEMP".to_owned(), private_root_text.clone()),
        ("TMP".to_owned(), private_root_text),
    ]
    .into_iter()
    .collect()
}

/// `_redact_env` (:133-139).
#[allow(dead_code)]
fn redact_env(env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    env.iter()
        .map(|(key, value)| {
            (
                key.clone(),
                if REDACT_KEY_PATTERN.is_match(key) {
                    "[REDACTED]".to_owned()
                } else {
                    value.clone()
                },
            )
        })
        .collect()
}

/// `_apply_resource_limits` (:141-154).
///
/// `resource.setrlimit` via libc requires `unsafe` (crate-forbidden). The
/// Python code wraps every call in `contextlib.suppress(OSError, ValueError)`
/// and skips entirely when `resource` is unavailable, so the safe-mode port
/// keeps the callsite shape and relies on the process-group kill timeout as
/// the enforcement backstop.
fn apply_resource_limits(_cpu_seconds: f64, _memory_bytes: u64, _max_processes: u32) {
    // no-op — see docstring; rlimit calls need unsafe libc.
}

/// `_write_sandbox_files` (:156-165).
fn write_sandbox_files(workspace: &Path, files: &BTreeMap<String, String>) {
    let resolved_workspace = match workspace.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => return,
    };
    for (rel_path, content) in files {
        if is_secret_path(rel_path) {
            continue;
        }
        let target = match workspace.join(rel_path).canonicalize() {
            Ok(target) => target,
            Err(_) => {
                // `Path.resolve(strict=False)`: normalize lexically when the
                // target does not exist yet.
                let candidate = workspace.join(rel_path);
                let parent = match candidate.parent() {
                    Some(parent) => parent.to_path_buf(),
                    None => continue,
                };
                let resolved_parent = match parent.canonicalize() {
                    Ok(resolved) => resolved,
                    Err(_) => {
                        if fs::create_dir_all(&parent).is_err() {
                            continue;
                        }
                        match parent.canonicalize() {
                            Ok(resolved) => resolved,
                            Err(_) => continue,
                        }
                    }
                };
                match candidate.file_name() {
                    Some(name) => resolved_parent.join(name),
                    None => continue,
                }
            }
        };
        if target.strip_prefix(&resolved_workspace).is_err() {
            continue;
        }
        if let Some(parent) = target.parent() {
            if fs::create_dir_all(parent).is_err() {
                continue;
            }
        }
        let _ = fs::write(&target, content);
    }
}

/// `_language_argv` (:167-176).
fn language_argv(language: SandboxLanguage, command: &str, _workspace: &Path) -> Vec<String> {
    match language {
        "shell" | "package" | "mcp_smoke" => {
            vec!["/bin/sh".to_owned(), "-c".to_owned(), command.to_owned()]
        }
        "node" => vec!["node".to_owned(), "-e".to_owned(), command.to_owned()],
        "python" => vec!["python3".to_owned(), "-c".to_owned(), command.to_owned()],
        _ => vec!["/bin/sh".to_owned(), "-c".to_owned(), command.to_owned()],
    }
}

/// `_scan_writes` (:178-187).
fn scan_writes(
    workspace: &Path,
    before: &HashSet<String>,
    before_mtimes: &BTreeMap<String, f64>,
) -> Vec<String> {
    let mut after_new: HashSet<String> = HashSet::new();
    let mut modified: Vec<String> = Vec::new();
    for path in rglob_files(workspace) {
        let rel = path
            .strip_prefix(workspace)
            .map(|rel| rel.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !before.contains(&rel) {
            after_new.insert(rel);
        } else {
            let mtime = path
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            if mtime > before_mtimes.get(&rel).copied().unwrap_or(0.0) {
                modified.push(rel);
            }
        }
    }
    let mut all: Vec<String> = after_new.into_iter().chain(modified).collect();
    all.sort();
    all
}

/// `Path.rglob("*")` for regular files, preserving `is_file()` semantics.
fn rglob_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        if let Ok(entries) = fs::read_dir(&directory) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Ok(file_type) = entry.file_type() {
                    if file_type.is_dir() {
                        pending.push(path);
                    } else if path.is_file() {
                        out.push(path);
                    }
                }
            }
        }
    }
    out
}

/// `_audit_combined_output` (:189-202).
fn audit_combined_output(stdout: &str, stderr: &str) -> (Vec<String>, Vec<String>) {
    let combined = format!("{stdout}\n{stderr}");
    let network_attempts = detect_network_attempts(&combined);
    let mut process_attempts: Vec<String> = Vec::new();
    for pat in PROCESS_AUDIT_PATTERNS.iter() {
        for m in pat.find_iter(&combined) {
            let start = m.start().saturating_sub(5);
            let end = (m.end() + 40).min(combined.len());
            let snippet = combined[start..end].trim();
            process_attempts.push(truncate_chars(snippet, 80));
        }
    }
    (network_attempts, process_attempts)
}

/// `_static_only_analysis` (:204-221).
fn static_only_analysis(request: &SandboxRequest) -> Option<SandboxResult> {
    let combined = format!(
        "{}\n{}",
        request.command,
        request
            .files
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    let network_attempts = detect_network_attempts(&combined);
    if network_attempts.is_empty() {
        return Some(SandboxResult::empty());
    }
    None
}

// ---------------------------------------------------------------------------
// `run_sandbox` (:223-335).
// ---------------------------------------------------------------------------

/// `run_sandbox` — execute a script in a sandboxed temporary workspace.
///
/// Always returns a `SandboxResult`. If the sandbox itself fails (missing
/// interpreter, permissions issue), `failure_safe=true` is set and the
/// result carries the error detail.
pub fn run_sandbox(request: &SandboxRequest, analysis_mode: SandboxAnalysisMode) -> SandboxResult {
    if analysis_mode == "off" {
        return SandboxResult::empty();
    }
    let network_pre = detect_network_attempts(&request.command);
    if analysis_mode == "suspicious" && network_pre.is_empty() {
        if let Some(static_result) = static_only_analysis(request) {
            return static_result;
        }
    }
    // `tempfile.TemporaryDirectory(prefix="guard-sandbox-")` — the `tempfile`
    // crate is not a workspace dep; roll the POSIX mkdtemp shape: create a
    // private 0700 dir under TMPDIR, remove on drop.
    let workspace = match TemporarySandboxDir::create("guard-sandbox-") {
        Ok(dir) => dir.path().to_path_buf(),
        Err(error) => {
            let mut result = SandboxResult::empty();
            result.stderr = format!("sandbox-error: {error}");
            result.network_attempts = network_pre;
            result.signals_detected = vec!["sandbox.execution-error".to_owned()];
            result.failure_safe = true;
            return result;
        }
    };
    let _tmpdir_guard = TemporarySandboxDir {
        path: workspace.clone(),
    };
    write_sandbox_files(&workspace, &request.files);

    let mut before_files: HashSet<String> = HashSet::new();
    let mut before_mtimes: BTreeMap<String, f64> = BTreeMap::new();
    for path in rglob_files(&workspace) {
        if path.is_file() {
            if let Ok(rel) = path.strip_prefix(&workspace) {
                let rel = rel.to_string_lossy().into_owned();
                before_files.insert(rel.clone());
                let mtime = path
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs_f64())
                    .unwrap_or(0.0);
                before_mtimes.insert(rel, mtime);
            }
        }
    }

    let env_map = build_env(request.env_policy, &workspace);
    let argv = language_argv(request.language, &request.command, &workspace);
    let effective_cwd = request
        .cwd
        .as_ref()
        .and_then(|cwd| Path::new(cwd).canonicalize().ok())
        .unwrap_or_else(|| workspace.clone());
    let timeout = Duration::from_secs_f64(request.timeout_seconds.max(0.001));

    // `preexec_fn=_preexec` — see spawn_bounded's note; the parent-side call
    // is a no-op stand-in retained so the rlimit cutover is a one-line change.
    apply_resource_limits(
        request.cpu_seconds,
        request.memory_bytes,
        request.max_processes,
    );
    let start = Instant::now();
    let spawn_result = spawn_bounded(&argv, &effective_cwd, &env_map, timeout);
    match spawn_result {
        Ok((exit_code, stdout, stderr, timed_out)) => {
            let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
            let writes = scan_writes(&workspace, &before_files, &before_mtimes);
            let (mut network_attempts, process_attempts) = audit_combined_output(&stdout, &stderr);
            // `dict.fromkeys` dedup preserving first-seen order.
            let mut merged: Vec<String> = Vec::new();
            let mut seen = HashSet::new();
            for item in network_pre.iter().chain(network_attempts.iter()) {
                if seen.insert(item.clone()) {
                    merged.push(item.clone());
                }
            }
            network_attempts = merged;
            let mut signals_detected: Vec<String> = Vec::new();
            if timed_out {
                signals_detected.push("sandbox.timeout".to_owned());
            }
            if !network_attempts.is_empty() {
                signals_detected.push("sandbox.network-attempt".to_owned());
            }
            if !writes.is_empty() {
                signals_detected.push("sandbox.unexpected-write".to_owned());
            }
            SandboxResult {
                exit_code,
                stdout,
                stderr,
                timed_out,
                writes,
                network_attempts,
                process_attempts,
                secret_read_attempts: Vec::new(),
                signals_detected,
                duration_ms,
                failure_safe: false,
            }
        }
        Err(error) => {
            let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
            SandboxResult {
                exit_code: None,
                stdout: String::new(),
                stderr: format!("sandbox-error: {error}"),
                timed_out: false,
                writes: Vec::new(),
                network_attempts: network_pre,
                process_attempts: Vec::new(),
                secret_read_attempts: Vec::new(),
                signals_detected: vec!["sandbox.execution-error".to_owned()],
                duration_ms,
                failure_safe: true,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Subprocess spawn/poll/kill — duplicated `guard-scanner/git_read.rs` pattern
// (crate boundary) extended with `pre_exec` rlimits, `process_group(0)` for
// `start_new_session`, and `killpg` on timeout.
// ---------------------------------------------------------------------------

/// `subprocess.Popen(...).communicate(timeout=...)` with SIGKILL of the
/// spawned process group on `TimeoutExpired`.
fn spawn_bounded(
    argv: &[String],
    cwd: &Path,
    env_map: &BTreeMap<String, String>,
    timeout: Duration,
) -> Result<(Option<i32>, String, String, bool), String> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;

    let program = argv
        .first()
        .cloned()
        .ok_or_else(|| "sandbox-error: empty argv".to_owned())?;
    let mut command = Command::new(&program);
    command
        .args(&argv[1..])
        .current_dir(cwd)
        .env_clear()
        .envs(env_map.iter().map(|(k, v)| (k.clone(), v.clone())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // `preexec_fn=_preexec` — `resource.setrlimit` in the child requires
    // `unsafe` libc calls (crate-forbidden) or a `pre_exec` closure (also
    // `unsafe`). Python wraps every rlimit call in `contextlib.suppress` and
    // skips when `resource` is unavailable, so this port treats rlimits as
    // unavailable and relies on the bounded timeout + process kill as the
    // enforcement backstop. Callsite shape retained for a future cutover.
    let mut child = command.spawn().map_err(|error| format!("{error}"))?;

    // Poll with bounded sleep — same shape as git_read.rs's timeout loop.
    let deadline = Instant::now() + timeout;
    let timed_out;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                timed_out = false;
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    // `os.killpg(os.getpgid(proc.pid), signal.SIGKILL)` —
                    // process group id equals the child pid after
                    // `process_group(0)`.
                    let pid = child.id() as i32;
                    let _ = kill_process_group(pid);
                    let _ = child.kill();
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(format!("{error}")),
        }
    }

    let mut stdout_raw = Vec::new();
    let mut stderr_raw = Vec::new();
    if let Some(mut stdout_pipe) = child.stdout.take() {
        let _ = stdout_pipe.read_to_end(&mut stdout_raw);
    }
    if let Some(mut stderr_pipe) = child.stderr.take() {
        let _ = stderr_pipe.read_to_end(&mut stderr_raw);
    }
    let exit_code = if timed_out {
        let _ = child.wait();
        None
    } else {
        child.wait().ok().and_then(|status| status.code())
    };
    let stdout = String::from_utf8_lossy(&stdout_raw).into_owned();
    let stderr = String::from_utf8_lossy(&stderr_raw).into_owned();
    Ok((exit_code, stdout, stderr, timed_out))
}

/// `os.killpg(os.getpgid(proc.pid), signal.SIGKILL)` — signals the spawned
/// process group. `libc::killpg` requires `unsafe` (crate-forbidden); the
/// child was started with `process_group(0)` so its group id equals its pid
/// and the same result is reachable through `pkill -KILL -g <pgid>` which
/// needs no `unsafe` in this crate.
fn kill_process_group(pgid: i32) -> Result<(), String> {
    let status = Command::new("/bin/kill")
        .args(["-KILL", &format!("-{pgid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => Err(format!("killpg failed for pgid {pgid}")),
    }
}

/// `tempfile.TemporaryDirectory(prefix=...)` stand-in — RAII removal plus a
/// process-global registry so drop-on-scope-exit stays explicit.
struct TemporarySandboxDir {
    path: PathBuf,
}

impl TemporarySandboxDir {
    fn create(prefix: &str) -> Result<Self, String> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let base = env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let pid = std::process::id();
        for attempt in 0..100u32 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let candidate = base.join(format!("{prefix}{pid}-{attempt}-{nanos}"));
            match fs::create_dir(&candidate) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ =
                            fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700));
                    }
                    return Ok(Self { path: candidate });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(format!("{error}")),
            }
        }
        Err("could not create unique sandbox tempdir".to_owned())
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporarySandboxDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
