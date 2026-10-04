//! Bounded working-tree and Git-history scanner for leaked secrets.
//!
//! Port of `codex_plugin_scanner.guard.secrets.secret_repository_scanner`
//! (RTM-032). The scanner is intentionally local and read-only. It does not
//! invoke a shell, does not contact the network, and never includes raw
//! secret candidates in its public result. Git-history scanning examines
//! files changed by bounded commits instead of materializing repository
//! history to disk.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::git_read::{run_git, GIT_TIMEOUT_SECONDS};
use crate::secret_detection::{
    detector_version, scan_secret_text, EmptyFingerprintKeyError, PublicFinding, SecretFinding,
};

/// `DEFAULT_MAX_FILES` from the Python module.
pub const DEFAULT_MAX_FILES: usize = 5_000;
/// `DEFAULT_MAX_FILE_BYTES` from the Python module.
pub const DEFAULT_MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
/// `DEFAULT_MAX_TOTAL_BYTES` from the Python module.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;
/// `DEFAULT_MAX_FINDINGS` from the Python module. Note this is the
/// bounded-scan default (500), distinct from the per-text
/// `secret_detection::DEFAULT_MAX_FINDINGS` (200).
pub const DEFAULT_MAX_FINDINGS: usize = 500;
/// `DEFAULT_MAX_COMMITS` from the Python module.
pub const DEFAULT_MAX_COMMITS: usize = 500;

/// Python `_TRUNCATION_REASON_ORDER`.
const TRUNCATION_REASON_ORDER: [&str; 4] = [
    "max_files",
    "max_total_bytes",
    "max_findings",
    "max_commits",
];

/// Python `_BINARY_SUFFIXES`, stored without the leading dot to match
/// `Path::extension` output; membership is compared case-insensitively.
const BINARY_SUFFIXES: &[&str] = &[
    "7z", "a", "avi", "bin", "bmp", "class", "dll", "dmg", "doc", "docx", "eot", "exe", "gif",
    "gz", "ico", "jar", "jpeg", "jpg", "mov", "mp3", "mp4", "o", "otf", "pdf", "png", "pyc", "so",
    "tar", "tiff", "ttf", "wav", "webm", "woff", "woff2", "xz", "zip",
];

/// Python `_SKIP_DIR_NAMES`.
const SKIP_DIR_NAMES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".turbo",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "coverage",
];

/// Errors raised by [`scan_repository_secrets`]. Mirrors the Python
/// `ValueError("secret scan target does not exist")` raise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanRepositoryError {
    /// The scan target does not exist on the filesystem.
    TargetMissing,
}

impl fmt::Display for ScanRepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TargetMissing => formatter.write_str("secret scan target does not exist"),
        }
    }
}

impl Error for ScanRepositoryError {}

/// Bound knobs for [`scan_repository_secrets`]; mirrors the Python keyword
/// arguments and their module-level defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryScanOptions {
    /// `include_history`
    pub include_history: bool,
    /// `max_commits` (bounded to `[1, 50_000]`).
    pub max_commits: usize,
    /// `max_files` (bounded to `[1, 100_000]`).
    pub max_files: usize,
    /// `max_file_bytes` (bounded to `[1, 32 MiB]`).
    pub max_file_bytes: usize,
    /// `max_total_bytes` (bounded to `[1, 4 GiB]`).
    pub max_total_bytes: usize,
    /// `max_findings` (bounded to `[1, 10_000]`).
    pub max_findings: usize,
}

impl Default for RepositoryScanOptions {
    fn default() -> Self {
        Self {
            include_history: false,
            max_commits: DEFAULT_MAX_COMMITS,
            max_files: DEFAULT_MAX_FILES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_findings: DEFAULT_MAX_FINDINGS,
        }
    }
}

/// Mirror of the frozen `RepositorySecretScanResult` dataclass.
#[derive(Debug, Clone, PartialEq)]
pub struct RepositorySecretScanResult {
    /// Deduped, ordered, `max_findings`-capped findings.
    pub findings: Vec<SecretFinding>,
    /// Files whose bytes were passed to the detector (binary/unreadable files
    /// still count once read, matching the Python accounting).
    pub files_scanned: usize,
    /// Commits whose changed paths were scanned.
    pub commits_scanned: usize,
    /// Decoded text bytes scanned (binary blobs contribute 0).
    pub bytes_scanned: usize,
    /// Whether history scanning was requested.
    pub history_enabled: bool,
    /// Whether any bound or failure truncated the scan.
    pub truncated: bool,
    /// Fail-closed error tags (e.g. `history_requested_for_non_git_target`).
    pub errors: Vec<String>,
    /// Active truncation reasons in `_TRUNCATION_REASON_ORDER` order.
    pub truncation_reasons: Vec<String>,
}

/// Serializable form of `RepositorySecretScanResult.to_public_dict`. Field
/// order matches the Python dict insertion order so `serde_json` emits the
/// same key order.
#[derive(Debug, Clone, Serialize)]
pub struct PublicRepositorySecretScanResult<'a> {
    pub schema: &'static str,
    pub detector_version: String,
    pub files_scanned: usize,
    pub commits_scanned: usize,
    pub bytes_scanned: usize,
    pub history_enabled: bool,
    pub truncated: bool,
    pub truncation_reasons: &'a [String],
    pub finding_count: usize,
    pub findings: Vec<PublicFinding<'a>>,
    pub errors: &'a [String],
}

impl RepositorySecretScanResult {
    /// Public, non-sensitive payload matching Python `to_public_dict`.
    /// Fingerprints are omitted exactly like `finding.to_public_dict()` called
    /// with no key.
    pub fn to_public_dict(
        &self,
    ) -> Result<PublicRepositorySecretScanResult<'_>, EmptyFingerprintKeyError> {
        let mut findings = Vec::with_capacity(self.findings.len());
        for finding in &self.findings {
            findings.push(finding.to_public_dict(None)?);
        }
        Ok(PublicRepositorySecretScanResult {
            schema: "guard-repository-secret-scan.v1",
            detector_version: detector_version(),
            files_scanned: self.files_scanned,
            commits_scanned: self.commits_scanned,
            bytes_scanned: self.bytes_scanned,
            history_enabled: self.history_enabled,
            truncated: self.truncated,
            truncation_reasons: &self.truncation_reasons,
            finding_count: findings.len(),
            findings,
            errors: &self.errors,
        })
    }
}

/// Python `_bounded_positive`. The `int(value)` coercion can only fail for
/// non-int inputs in Python; the Rust signature is already `usize`, so only
/// the `parsed <= 0` guard survives.
pub(crate) fn bounded_positive(value: usize, default: usize, maximum: usize) -> usize {
    if value == 0 {
        return default;
    }
    value.min(maximum)
}

/// Python `_active_limit_reasons`.
fn active_limit_reasons(
    files_scanned: usize,
    bytes_scanned: usize,
    finding_count: usize,
    max_files: usize,
    max_total_bytes: usize,
    max_findings: usize,
) -> Vec<&'static str> {
    let mut reasons = Vec::with_capacity(3);
    if files_scanned >= max_files {
        reasons.push("max_files");
    }
    if bytes_scanned >= max_total_bytes {
        reasons.push("max_total_bytes");
    }
    if finding_count >= max_findings {
        reasons.push("max_findings");
    }
    reasons
}

/// Python `_ordered_truncation_reasons`.
fn ordered_truncation_reasons(reasons: &HashSet<&'static str>) -> Vec<String> {
    TRUNCATION_REASON_ORDER
        .iter()
        .filter(|&reason| reasons.contains(reason))
        .map(|reason| reason.to_string())
        .collect()
}

/// Python `_looks_binary`: known binary suffix (case-insensitive) or a NUL
/// byte inside the first 8192 bytes.
fn looks_binary(path: &str, data: &[u8]) -> bool {
    if let Some(extension) = Path::new(path).extension().and_then(OsStr::to_str) {
        if BINARY_SUFFIXES
            .iter()
            .any(|suffix| extension.eq_ignore_ascii_case(suffix))
        {
            return true;
        }
    }
    data[..data.len().min(8192)].contains(&0)
}

/// Python `_decode_text`.
fn decode_text<'a>(path: &str, data: &'a [u8]) -> Option<&'a str> {
    if looks_binary(path, data) {
        return None;
    }
    std::str::from_utf8(data).ok()
}

/// Python `_safe_relative`. `canonical_root` is the already-resolved scan root
/// (Python recomputes `root.resolve()` per call; the result is identical).
fn safe_relative(path: &Path, canonical_root: &Path) -> String {
    if let Ok(resolved) = path.canonicalize() {
        if let Ok(relative) = resolved.strip_prefix(canonical_root) {
            return relative.to_string_lossy().into_owned();
        }
    }
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Python `_filesystem_paths`: `os.walk(root, followlinks=False)` with
/// `_SKIP_DIR_NAMES` pruning, symlinks skipped, result sorted.
fn filesystem_paths(root: &Path, canonical_root: &Path) -> Vec<String> {
    let mut paths = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(file_type) if file_type.is_symlink() => continue,
                Ok(file_type) if file_type.is_dir() => {
                    let name = entry.file_name();
                    if !SKIP_DIR_NAMES
                        .iter()
                        .any(|skipped| name == OsStr::new(skipped))
                    {
                        stack.push(path);
                    }
                }
                _ => paths.push(safe_relative(&path, canonical_root)),
            }
        }
    }
    paths.sort();
    paths
}

// ---------------------------------------------------------------------------
// Git subprocess entry points. Each helper mirrors the Python `except
// (OSError, subprocess.SubprocessError)` / `returncode != 0` early exits:
// `run_git` folds all three failure modes into `Err(GitError)` and `Ok`
// guarantees `returncode == 0`, so `Err(_) => None`/`false` is the verbatim
// port of the Python degradation.

/// Python `bytes.strip()`: ASCII whitespace off both ends.
fn strip_bytes(data: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = data.len();
    while start < end && data[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && data[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &data[start..end]
}

/// `_is_git_repository`: `git rev-parse --is-inside-work-tree` must exit 0
/// and print exactly `true`.
fn is_git_repository(root: &Path) -> bool {
    let Ok(result) = run_git(
        root,
        &["rev-parse", "--is-inside-work-tree"],
        GIT_TIMEOUT_SECONDS,
    ) else {
        return false;
    };
    strip_bytes(&result.stdout) == b"true"
}

/// `item.decode("utf-8", errors="surrogateescape")` over NUL-separated git
/// output. Rust strings cannot hold surrogates, so `from_utf8_lossy` is the
/// closest faithful decode: valid UTF-8 is byte-identical and invalid bytes
/// become `U+FFFD` instead of lone surrogates.
fn decode_nul_paths(stdout: &[u8]) -> Vec<String> {
    stdout
        .split(|byte| *byte == 0)
        .filter(|item| !item.is_empty())
        .map(|item| String::from_utf8_lossy(item).into_owned())
        .collect()
}

/// `_git_working_paths`: `git ls-files -co --exclude-standard -z` split on
/// NUL (tracked, untracked, and non-ignored files).
fn git_working_paths(root: &Path) -> Option<Vec<String>> {
    let result = run_git(
        root,
        &["ls-files", "-co", "--exclude-standard", "-z"],
        GIT_TIMEOUT_SECONDS,
    )
    .ok()?;
    Some(decode_nul_paths(&result.stdout))
}

/// `_git_commits`: `git rev-list --all --max-count=<n>`, one commit per line.
fn git_commits(root: &Path, max_commits: usize) -> Option<Vec<String>> {
    let max_count = format!("--max-count={max_commits}");
    let result = run_git(
        root,
        &["rev-list", "--all", max_count.as_str()],
        GIT_TIMEOUT_SECONDS,
    )
    .ok()?;
    Some(
        String::from_utf8_lossy(&result.stdout)
            .split('\n')
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

/// `_git_changed_paths`: `git diff-tree --root --no-commit-id --name-only
/// -r -z <commit>` split on NUL.
fn git_changed_paths(root: &Path, commit: &str) -> Option<Vec<String>> {
    let result = run_git(
        root,
        &[
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-only",
            "-r",
            "-z",
            commit,
        ],
        GIT_TIMEOUT_SECONDS,
    )
    .ok()?;
    Some(decode_nul_paths(&result.stdout))
}

/// `_git_blob`: size-check `git cat-file -s <commit>:<path>` against
/// `max_file_bytes`, then `git cat-file blob <commit>:<path>` with the bound
/// re-applied to the streamed payload.
fn git_blob(root: &Path, commit: &str, path: &str, max_file_bytes: usize) -> Option<Vec<u8>> {
    let spec = format!("{commit}:{path}");
    let size_result = run_git(
        root,
        &["cat-file", "-s", spec.as_str()],
        GIT_TIMEOUT_SECONDS,
    )
    .ok()?;
    // Python `int(strip_bytes(&size_result.stdout))`; `from_utf8` covers any byte
    // garbage the way `ValueError` catches non-numeric output.
    let size_text = std::str::from_utf8(strip_bytes(&size_result.stdout)).ok()?;
    let size: i64 = size_text.parse().ok()?;
    if size < 0 || size > max_file_bytes as i64 {
        return None;
    }
    let blob_result = run_git(
        root,
        &["cat-file", "blob", spec.as_str()],
        GIT_TIMEOUT_SECONDS,
    )
    .ok()?;
    if blob_result.stdout.len() > max_file_bytes {
        return None;
    }
    Some(blob_result.stdout)
}
// ---------------------------------------------------------------------------

/// Python `_scan_blob`.
pub(crate) fn scan_blob(
    data: &[u8],
    path: &str,
    source: &str,
    commit: Option<&str>,
    finding_budget: usize,
) -> (Vec<SecretFinding>, usize) {
    let Some(text) = decode_text(path, data) else {
        return (Vec::new(), 0);
    };
    let summary = scan_secret_text(text, path, source, commit, finding_budget);
    (summary.findings, data.len())
}

/// Python `_read_working_file`. `canonical_root` is `root.resolve()` computed
/// once by the caller.
fn read_working_file(
    root: &Path,
    canonical_root: &Path,
    relative_path: &str,
    max_file_bytes: usize,
) -> Option<Vec<u8>> {
    let resolved = root.join(relative_path).canonicalize().ok()?;
    resolved.strip_prefix(canonical_root).ok()?;
    let metadata = resolved.metadata().ok()?;
    // Parity: `resolved` is canonical so it can never be a symlink; the check
    // is kept because the Python guard performs it.
    if !metadata.is_file() || resolved.is_symlink() {
        return None;
    }
    if metadata.len() > max_file_bytes as u64 {
        return None;
    }
    fs::read(&resolved).ok()
}

/// Minimal `Path.expanduser()` parity: expands a leading `~` or `~/` via
/// `$HOME`; the `~user` form is left intact (not needed by callers).
pub(crate) fn expand_tilde(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(home) = std::env::var_os("HOME") {
        if text == "~" {
            return PathBuf::from(home);
        }
        if let Some(rest) = text.strip_prefix("~/") {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

/// Scan a local file/directory and optionally bounded Git history.
/// Mirrors `scan_repository_secrets(target, *, include_history=False,
/// max_commits=..., max_files=..., max_file_bytes=..., max_total_bytes=...,
/// max_findings=...)`.
///
/// History scanning requires `git`: targets outside a worktree, or invocations
/// where git exits non-zero/times out, degrade exactly like the Python
/// `except`/`returncode != 0` early exits — `include_history` on a non-git
/// target reports `history_requested_for_non_git_target`.
pub fn scan_repository_secrets(
    target: &Path,
    options: &RepositoryScanOptions,
) -> Result<RepositorySecretScanResult, ScanRepositoryError> {
    // `target.expanduser().resolve()` plus the `root.exists()` ValueError.
    let root = expand_tilde(target)
        .canonicalize()
        .map_err(|_| ScanRepositoryError::TargetMissing)?;

    let max_commits = bounded_positive(options.max_commits, DEFAULT_MAX_COMMITS, 50_000);
    let max_files = bounded_positive(options.max_files, DEFAULT_MAX_FILES, 100_000);
    let max_file_bytes = bounded_positive(
        options.max_file_bytes,
        DEFAULT_MAX_FILE_BYTES,
        32 * 1024 * 1024,
    );
    let max_total_bytes = bounded_positive(
        options.max_total_bytes,
        DEFAULT_MAX_TOTAL_BYTES,
        4 * 1024 * 1024 * 1024,
    );
    let max_findings = bounded_positive(options.max_findings, DEFAULT_MAX_FINDINGS, 10_000);

    let (scan_root, git_repo, working_paths) = if root.is_file() {
        let scan_root = root
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        let name = root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        (scan_root, false, vec![name])
    } else {
        let scan_root = root.clone();
        let git_repo = is_git_repository(&scan_root);
        let working_paths = if git_repo {
            git_working_paths(&scan_root)
        } else {
            None
        }
        .unwrap_or_else(|| filesystem_paths(&scan_root, &scan_root));
        (scan_root, git_repo, working_paths)
    };
    // `root` was canonicalized above; `scan_root` is either `root` or its
    // parent, both canonical, so this is `root.resolve()` from Python.
    let canonical_root = scan_root.clone();

    let mut findings: Vec<SecretFinding> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut truncation_reasons: HashSet<&'static str> = HashSet::new();
    let mut files_scanned = 0usize;
    let mut commits_scanned = 0usize;
    let mut bytes_scanned = 0usize;
    let mut truncated = false;

    for relative_path in &working_paths {
        let active = active_limit_reasons(
            files_scanned,
            bytes_scanned,
            findings.len(),
            max_files,
            max_total_bytes,
            max_findings,
        );
        if !active.is_empty() {
            truncation_reasons.extend(active);
            truncated = true;
            break;
        }
        let Some(data) =
            read_working_file(&scan_root, &canonical_root, relative_path, max_file_bytes)
        else {
            continue;
        };
        if bytes_scanned + data.len() > max_total_bytes {
            truncation_reasons.insert("max_total_bytes");
            truncated = true;
            break;
        }
        let normalized = relative_path.replace('\\', "/");
        let (found, scanned_bytes) = scan_blob(
            &data,
            &normalized,
            "working_tree",
            None,
            max_findings - findings.len(),
        );
        files_scanned += 1;
        bytes_scanned += scanned_bytes;
        findings.extend(found);
    }

    if options.include_history && git_repo {
        let active = active_limit_reasons(
            files_scanned,
            bytes_scanned,
            findings.len(),
            max_files,
            max_total_bytes,
            max_findings,
        );
        if !active.is_empty() {
            truncation_reasons.extend(active);
            truncated = true;
        } else {
            let commits: Vec<String> = match git_commits(&scan_root, max_commits + 1) {
                None => {
                    errors.push("git_history_enumeration_failed".to_string());
                    truncated = true;
                    Vec::new()
                }
                Some(candidates) => {
                    if candidates.len() > max_commits {
                        truncation_reasons.insert("max_commits");
                        truncated = true;
                    }
                    candidates.into_iter().take(max_commits).collect()
                }
            };
            for commit in commits {
                let active = active_limit_reasons(
                    files_scanned,
                    bytes_scanned,
                    findings.len(),
                    max_files,
                    max_total_bytes,
                    max_findings,
                );
                if !active.is_empty() {
                    truncation_reasons.extend(active);
                    truncated = true;
                    break;
                }
                commits_scanned += 1;
                let Some(changed_paths) = git_changed_paths(&scan_root, &commit) else {
                    errors.push("git_history_changed_paths_failed".to_string());
                    truncated = true;
                    continue;
                };
                for relative_path in changed_paths {
                    let active = active_limit_reasons(
                        files_scanned,
                        bytes_scanned,
                        findings.len(),
                        max_files,
                        max_total_bytes,
                        max_findings,
                    );
                    if !active.is_empty() {
                        truncation_reasons.extend(active);
                        truncated = true;
                        break;
                    }
                    let Some(data) = git_blob(&scan_root, &commit, &relative_path, max_file_bytes)
                    else {
                        continue;
                    };
                    if bytes_scanned + data.len() > max_total_bytes {
                        truncation_reasons.insert("max_total_bytes");
                        truncated = true;
                        break;
                    }
                    let normalized = relative_path.replace('\\', "/");
                    let (found, scanned_bytes) = scan_blob(
                        &data,
                        &normalized,
                        "git_history",
                        Some(&commit),
                        max_findings - findings.len(),
                    );
                    files_scanned += 1;
                    bytes_scanned += scanned_bytes;
                    findings.extend(found);
                }
            }
        }
    } else if options.include_history {
        errors.push("history_requested_for_non_git_target".to_string());
        truncated = true;
    }

    // A provider rule can also be recognized by the contextual assignment
    // rule. Keep occurrences stable while preferring the stronger provider
    // format (higher confidence_score wins the dedup key).
    let mut deduped: HashMap<(String, usize, String, Option<String>), SecretFinding> =
        HashMap::new();
    for finding in findings {
        let key = (
            finding.path.clone(),
            finding.line,
            finding.candidate.clone(),
            finding.commit.clone(),
        );
        match deduped.entry(key) {
            Entry::Occupied(mut slot) => {
                if finding.confidence_score > slot.get().confidence_score {
                    slot.insert(finding);
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(finding);
            }
        }
    }
    let mut ordered: Vec<SecretFinding> = deduped.into_values().collect();
    ordered.sort_by(|a, b| {
        (
            a.commit.as_deref().unwrap_or(""),
            a.path.as_str(),
            a.line,
            a.rule_id,
        )
            .cmp(&(
                b.commit.as_deref().unwrap_or(""),
                b.path.as_str(),
                b.line,
                b.rule_id,
            ))
    });
    let deduped_len = ordered.len();
    ordered.truncate(max_findings);
    if deduped_len > ordered.len() {
        truncation_reasons.insert("max_findings");
        truncated = true;
    }

    Ok(RepositorySecretScanResult {
        findings: ordered,
        files_scanned,
        commits_scanned,
        bytes_scanned,
        history_enabled: options.include_history,
        truncated,
        errors,
        truncation_reasons: ordered_truncation_reasons(&truncation_reasons),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Known detector oracle: `github-token` strong-format rule (mirrors the
    // `secret_detection` fixture line).
    const SECRET_LINE: &str = "GH_TOKEN = ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345";

    fn temp_root(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "guard-scanner-repo-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn decode_text_matches_python_binary_and_utf8_rules() {
        assert_eq!(decode_text("a/b.txt", "héllo".as_bytes()), Some("héllo"));
        // Binary suffix wins over otherwise valid UTF-8 payload, and the
        // suffix comparison is case-insensitive.
        assert!(decode_text("image.PNG", b"plain text").is_none());
        // NUL inside the first 8192 bytes marks the blob binary.
        assert!(decode_text("data", b"ok\0tail").is_none());
        // A NUL past the 8192-byte sample window is not inspected, so the
        // blob decodes as text (NUL is valid UTF-8).
        let mut far_nul = vec![b'a'; 8192];
        far_nul.push(0);
        assert!(decode_text("data", &far_nul).is_some());
        // invalid UTF-8 fails closed.
        assert!(decode_text("data", b"bad\xffutf8").is_none());
    }

    #[test]
    fn limit_helpers_match_python() {
        assert_eq!(bounded_positive(0, 7, 10), 7);
        assert_eq!(bounded_positive(3, 7, 10), 3);
        assert_eq!(bounded_positive(42, 7, 10), 10);

        assert!(active_limit_reasons(4, 99, 9, 5, 100, 10).is_empty());
        assert_eq!(
            active_limit_reasons(5, 100, 10, 5, 100, 10),
            vec!["max_files", "max_total_bytes", "max_findings"]
        );

        let mut reasons = HashSet::new();
        reasons.insert("max_findings");
        reasons.insert("max_files");
        assert_eq!(
            ordered_truncation_reasons(&reasons),
            vec!["max_files".to_string(), "max_findings".to_string()]
        );
    }

    #[test]
    fn scan_blob_oracle_dict_of_blob_to_findings() {
        // Fixture contract: dict-of-blob -> findings. Blob text is passed
        // directly to the pure scan path; no real git repository is needed.
        let blob = format!("line one\n{SECRET_LINE}\n");
        let (findings, scanned) = scan_blob(
            blob.as_bytes(),
            "config/prod.env",
            "git_history",
            Some("deadbeef"),
            200,
        );
        assert_eq!(scanned, blob.len());
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.rule_id, "github-token");
        assert_eq!(finding.source, "git_history");
        assert_eq!(finding.commit.as_deref(), Some("deadbeef"));
        assert_eq!(finding.path, "config/prod.env");
        assert_eq!(finding.line, 2);

        // Binary blobs produce no findings and contribute zero scanned bytes.
        let (none, scanned) = scan_blob(b"\0binary", "blob.bin", "working_tree", None, 200);
        assert!(none.is_empty());
        assert_eq!(scanned, 0);
    }

    #[test]
    fn missing_target_fails_closed() {
        let result = scan_repository_secrets(
            Path::new("/nonexistent/rtm032-scan-target"),
            &RepositoryScanOptions::default(),
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "secret scan target does not exist"
        );
    }

    #[test]
    fn filesystem_scan_matches_python_oracle() {
        let dir = temp_root("fs");
        fs::write(dir.join("app.env"), SECRET_LINE).unwrap();
        fs::write(dir.join("readme.txt"), "nothing here").unwrap();
        // Binary suffix: read but never decoded, still counted by
        // files_scanned like the Python scanner.
        fs::write(dir.join("logo.png"), SECRET_LINE).unwrap();
        fs::create_dir_all(dir.join("node_modules")).unwrap();
        fs::write(dir.join("node_modules").join("dep.env"), SECRET_LINE).unwrap();
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub").join("deep.env"), SECRET_LINE).unwrap();

        let result = scan_repository_secrets(&dir, &RepositoryScanOptions::default()).unwrap();
        assert!(!result.truncated);
        assert!(!result.history_enabled);
        assert!(result.errors.is_empty());
        assert!(result.truncation_reasons.is_empty());
        assert_eq!(result.files_scanned, 4);
        assert_eq!(result.commits_scanned, 0);
        assert_eq!(result.findings.len(), 2);
        let paths: Vec<&str> = result.findings.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["app.env", "sub/deep.env"]);
        assert!(result.findings.iter().all(|f| f.source == "working_tree"));
        assert!(result.findings.iter().all(|f| f.commit.is_none()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_request_on_non_git_target_matches_python_error() {
        let dir = temp_root("nogit");
        fs::write(dir.join("a.env"), SECRET_LINE).unwrap();
        let options = RepositoryScanOptions {
            include_history: true,
            ..RepositoryScanOptions::default()
        };
        let result = scan_repository_secrets(&dir, &options).unwrap();
        assert!(result.history_enabled);
        assert!(result.truncated);
        assert_eq!(result.errors, ["history_requested_for_non_git_target"]);
        assert_eq!(result.commits_scanned, 0);
        assert_eq!(result.findings.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_files_cap_truncates_with_ordered_reason() {
        let dir = temp_root("cap");
        fs::write(dir.join("a.env"), "clean a").unwrap();
        fs::write(dir.join("b.env"), "clean b").unwrap();
        let options = RepositoryScanOptions {
            max_files: 1,
            ..RepositoryScanOptions::default()
        };
        let result = scan_repository_secrets(&dir, &options).unwrap();
        assert!(result.truncated);
        assert_eq!(result.files_scanned, 1);
        assert_eq!(result.truncation_reasons, ["max_files"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn public_dict_omits_candidates_and_matches_python_schema() {
        let dir = temp_root("public");
        fs::write(dir.join("app.env"), SECRET_LINE).unwrap();
        let result = scan_repository_secrets(&dir, &RepositoryScanOptions::default()).unwrap();
        let payload = result.to_public_dict().unwrap();
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["schema"], "guard-repository-secret-scan.v1");
        assert_eq!(json["finding_count"], 1);
        assert_eq!(json["files_scanned"], 1);
        assert_eq!(json["findings"][0]["path"], "app.env");
        assert_eq!(json["findings"][0]["source"], "working_tree");
        // The public payload never carries the raw candidate.
        assert!(!json
            .to_string()
            .contains("ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345"));
        let _ = fs::remove_dir_all(&dir);
    }
}
