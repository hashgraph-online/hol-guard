//! Bounded leaked-secret scanning for the Git staging index.
//!
//! Port of `codex_plugin_scanner.guard.secrets.secret_staged_scanner`
//! (RTM-032). Scanning is local and read-only: staged blob content is fetched
//! through Git plumbing (`diff --cached`, `cat-file`) and never written back
//! to disk or sent over the network.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use crate::git_read::run_git_os;
use crate::git_read::{run_git, GIT_TIMEOUT_SECONDS};
use crate::repository_scanner::{
    bounded_positive, expand_tilde, scan_blob, RepositorySecretScanResult, DEFAULT_MAX_FILES,
    DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_FINDINGS, DEFAULT_MAX_TOTAL_BYTES,
};
use crate::secret_detection::SecretFinding;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

/// Keyword options mirroring `scan_staged_secrets(root, *, max_files=...,
/// max_file_bytes=..., max_total_bytes=..., max_findings=...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedScanOptions {
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub max_findings: usize,
}

impl Default for StagedScanOptions {
    fn default() -> Self {
        Self {
            max_files: DEFAULT_MAX_FILES,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_findings: DEFAULT_MAX_FINDINGS,
        }
    }
}

// --- git subprocess helpers -------------------------------------------------
// Thin wrappers over `git_read::run_git` (Python `_run_git`). `run_git` folds
// `OSError`/`SubprocessError`/`returncode != 0` into `Err(GitError)`, so
// `.ok()` below is the verbatim port of each Python `except` + `returncode`
// early exit.

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

/// Python `_git_repository_root`: `git rev-parse --show-toplevel`, strict
/// UTF-8 decode of the trimmed output, then `Path(raw).resolve()`.
fn git_repository_root(root: &Path) -> Option<PathBuf> {
    let result = run_git(root, &["rev-parse", "--show-toplevel"], GIT_TIMEOUT_SECONDS).ok()?;
    // `result.stdout.decode("utf-8", errors="strict").strip()`; a strict
    // decode failure is a `ValueError`, which Python does not catch here, but
    // the surrounding callers degrade identically on `None`.
    let raw = std::str::from_utf8(&result.stdout).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    // `Path(raw).resolve()` — non-strict in Python, so a failed canonicalize
    // still yields the raw path rather than `None`.
    let path = PathBuf::from(trimmed);
    Some(path.canonicalize().unwrap_or(path))
}

/// Python `_git_staged_paths`:
/// `git diff --cached --name-only --diff-filter=ACMR -z --` split on NUL.
/// Python decodes with `surrogateescape`, so non-UTF-8 staged paths still
/// reach `git cat-file :<path>` byte-exact. Rust keeps raw bytes and converts
/// to `OsString` only at the subprocess boundary so non-UTF-8 paths are
/// scanned, never silently skipped.
fn git_staged_paths(root: &Path) -> Option<Vec<Vec<u8>>> {
    let result = run_git(
        root,
        &[
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
            "--",
        ],
        GIT_TIMEOUT_SECONDS,
    )
    .ok()?;
    Some(
        result
            .stdout
            .split(|byte| *byte == 0)
            .filter(|item| !item.is_empty())
            .map(|item| item.to_vec())
            .collect(),
    )
}

/// Build `["cat-file", "-s"|"blob", ":<path>"]` argv. Byte-exact on unix via
/// `OsString`; on non-unix `OsString::from_vec` is unavailable, so decode
/// lossily (matches the rare-path substitute — a non-UTF-8 staged path on
/// Windows still resolves via git's own argv decoding).
fn staged_blob_args(path: &[u8], op: &str) -> Vec<std::ffi::OsString> {
    let mut spec = b":".to_vec();
    spec.extend_from_slice(path);
    #[cfg(unix)]
    let spec_arg = std::ffi::OsString::from_vec(spec);
    #[cfg(not(unix))]
    let spec_arg = std::ffi::OsString::from(String::from_utf8_lossy(&spec).into_owned());
    vec![
        std::ffi::OsString::from("cat-file"),
        std::ffi::OsString::from(op),
        spec_arg,
    ]
}

#[cfg(unix)]
fn run_git_blob(
    root: &Path,
    args: &[std::ffi::OsString],
) -> Result<crate::git_read::CompletedOutput, crate::git_read::GitError> {
    run_git_os(root, args, GIT_TIMEOUT_SECONDS)
}

#[cfg(not(unix))]
fn run_git_blob(
    root: &Path,
    args: &[std::ffi::OsString],
) -> Result<crate::git_read::CompletedOutput, crate::git_read::GitError> {
    let str_args: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let borrowed: Vec<&str> = str_args.iter().map(String::as_str).collect();
    run_git(root, &borrowed, GIT_TIMEOUT_SECONDS)
}

/// Python `_git_staged_blob`: size check via `git cat-file -s :<path>` then
/// payload via `git cat-file blob :<path>` bounded by `max_file_bytes`.
/// Returns `(Option<bytes>, blob_too_large)` — `too_large` only when the
/// staged object itself exceeds `max_file_bytes`; every other failure
/// mirrors the Python `except`/`returncode` early exits as `(None, false)`
/// so the caller records `git_staged_blob_failed`.
fn git_staged_blob(root: &Path, path: &[u8], max_file_bytes: usize) -> (Option<Vec<u8>>, bool) {
    let spec_args = staged_blob_args(path, "-s");
    let Ok(size_result) = run_git_blob(root, &spec_args) else {
        return (None, false);
    };
    // `int(size_result.stdout.strip())`; invalid output mirrors `ValueError`.
    let Some(size) = std::str::from_utf8(strip_bytes(&size_result.stdout))
        .ok()
        .and_then(|text| text.parse::<i64>().ok())
    else {
        return (None, false);
    };
    if size < 0 || size > max_file_bytes as i64 {
        return (None, true);
    }
    let Ok(blob_result) = run_git_blob(root, &staged_blob_args(path, "blob")) else {
        return (None, false);
    };
    if blob_result.stdout.len() > max_file_bytes {
        return (None, true);
    }
    (Some(blob_result.stdout), false)
}
// ---------------------------------------------------------------------------

/// Empty-result constructor for the fail-closed early exits, mirroring the
/// literal `RepositorySecretScanResult(...)` built inside each Python branch.
fn failed_result(error: &str) -> RepositorySecretScanResult {
    RepositorySecretScanResult {
        findings: Vec::new(),
        files_scanned: 0,
        commits_scanned: 0,
        bytes_scanned: 0,
        history_enabled: false,
        truncated: true,
        errors: vec![error.to_string()],
        // Python `scan_staged_secrets` never passes `truncation_reasons`;
        // the dataclass default is `()`.
        truncation_reasons: Vec::new(),
    }
}

/// Dedup/ordering block shared by all staged findings: keyed on
/// `(path, line, candidate)` with the higher `confidence_score` winning, then
/// sorted by `(path, line, rule_id)` and capped at `max_findings`. Returns the
/// ordered findings plus whether the cap dropped entries.
fn dedup_findings(findings: Vec<SecretFinding>, max_findings: usize) -> (Vec<SecretFinding>, bool) {
    let mut deduped: HashMap<(String, usize, String), SecretFinding> = HashMap::new();
    for finding in findings {
        let key = (
            finding.path.clone(),
            finding.line,
            finding.candidate.clone(),
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
        (a.path.as_str(), a.line, a.rule_id).cmp(&(b.path.as_str(), b.line, b.rule_id))
    });
    let deduped_len = ordered.len();
    ordered.truncate(max_findings);
    let dropped = deduped_len > ordered.len();
    (ordered, dropped)
}

/// Scan only content currently staged in a Git index.
/// Mirrors `scan_staged_secrets(root, *, max_files=..., max_file_bytes=...,
/// max_total_bytes=..., max_findings=...)`.
pub fn scan_staged_secrets(root: &Path, options: &StagedScanOptions) -> RepositorySecretScanResult {
    // `Path(root).expanduser().resolve()`; Python's resolve is non-strict, so
    // a missing root resolves to itself and falls into the git_root failure
    // branch rather than raising.
    let expanded_root = expand_tilde(root);
    let resolved_root = expanded_root
        .canonicalize()
        .unwrap_or_else(|_| expanded_root.clone());
    let Some(git_root) = git_repository_root(&resolved_root) else {
        return failed_result("git_repository_root_failed");
    };
    let Some(staged_paths) = git_staged_paths(&git_root) else {
        return failed_result("git_staged_enumeration_failed");
    };

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

    let mut findings: Vec<SecretFinding> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut files_scanned = 0usize;
    let mut bytes_scanned = 0usize;
    let mut truncated = false;

    for relative_path in &staged_paths {
        if files_scanned >= max_files || bytes_scanned >= max_total_bytes {
            truncated = true;
            break;
        }
        // Display/label strings use lossy UTF-8 (surrogateescape-parity);
        // the blob lookup itself still consumes the raw `relative_path` bytes.
        let normalized = String::from_utf8_lossy(relative_path).replace('\\', "/");
        let (data, too_large) = git_staged_blob(&git_root, relative_path, max_file_bytes);
        if too_large {
            truncated = true;
            continue;
        }
        let Some(data) = data else {
            errors.push("git_staged_blob_failed".to_string());
            continue;
        };
        if bytes_scanned + data.len() > max_total_bytes {
            truncated = true;
            break;
        }
        let (found, scanned_bytes) = scan_blob(
            &data,
            &normalized,
            "staged",
            None,
            max_findings.saturating_sub(findings.len()),
        );
        files_scanned += 1;
        bytes_scanned += scanned_bytes;
        findings.extend(found);
        if findings.len() >= max_findings {
            truncated = true;
            break;
        }
    }

    let (ordered, dropped) = dedup_findings(findings, max_findings);
    if dropped {
        truncated = true;
    }

    RepositorySecretScanResult {
        findings: ordered,
        files_scanned,
        commits_scanned: 0,
        bytes_scanned,
        history_enabled: false,
        truncated,
        errors: {
            errors.sort();
            errors
        },
        truncation_reasons: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Known detector oracle: `github-token` strong-format rule (same fixture
    // line as the repository_scanner tests).
    const SECRET_LINE: &str = "GH_TOKEN = ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345";

    fn temp_root(tag: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "guard-scanner-staged-{tag}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn finding(path: &str, line: usize, candidate: &str, confidence_score: f64) -> SecretFinding {
        SecretFinding {
            rule_id: "github-token",
            family: "GitHub token",
            severity: "critical",
            confidence: "high",
            confidence_score,
            line,
            path: path.to_string(),
            source: "staged".to_string(),
            commit: None,
            validation: "github",
            entropy: 5.0,
            context_reasons: vec!["provider-format"],
            candidate: candidate.to_string(),
        }
    }

    #[test]
    fn missing_root_fails_closed_like_python() {
        // Python `resolve()` is non-strict: the path resolves to itself, the
        // git root lookup fails, and the result carries
        // `git_repository_root_failed`.
        let result = scan_staged_secrets(
            Path::new("/nonexistent/rtm032-staged-root"),
            &StagedScanOptions::default(),
        );
        assert!(result.truncated);
        assert_eq!(result.errors, ["git_repository_root_failed"]);
        assert!(result.findings.is_empty());
        assert_eq!(result.files_scanned, 0);
        assert_eq!(result.commits_scanned, 0);
        assert_eq!(result.bytes_scanned, 0);
        assert!(!result.history_enabled);
        assert!(result.truncation_reasons.is_empty());
    }

    #[test]
    fn non_git_directory_reports_no_staged_findings() {
        let dir = temp_root("nogit");
        fs::write(dir.join("staged.env"), SECRET_LINE).unwrap();
        let result = scan_staged_secrets(&dir, &StagedScanOptions::default());
        // Working-tree files are never inspected; only index content counts.
        assert!(result.findings.is_empty());
        assert_eq!(result.errors, ["git_repository_root_failed"]);
        assert!(result.truncated);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn option_defaults_match_python_module() {
        let options = StagedScanOptions::default();
        assert_eq!(options.max_files, 5_000);
        assert_eq!(options.max_file_bytes, 2 * 1024 * 1024);
        assert_eq!(options.max_total_bytes, 128 * 1024 * 1024);
        assert_eq!(options.max_findings, 500);
    }

    #[test]
    fn dedup_prefers_confidence_and_orders_like_python() {
        // Same (path, line, candidate) key twice: higher confidence wins.
        // Then findings sort by (path, line, rule_id).
        let findings = vec![
            finding("b.env", 4, "tok-c", 0.5),
            finding("a.env", 7, "tok-a", 0.9),
            finding("b.env", 2, "tok-b", 0.6),
            finding("a.env", 7, "tok-a", 0.4), // duplicate key, weaker
        ];
        let (ordered, dropped) = dedup_findings(findings, 10);
        assert!(!dropped);
        assert_eq!(ordered.len(), 3);
        let keys: Vec<(&str, usize, &str)> = ordered
            .iter()
            .map(|f| (f.path.as_str(), f.line, f.candidate.as_str()))
            .collect();
        assert_eq!(
            keys,
            [
                ("a.env", 7, "tok-a"),
                ("b.env", 2, "tok-b"),
                ("b.env", 4, "tok-c")
            ]
        );
        assert_eq!(ordered[0].confidence_score.to_bits(), 0.9f64.to_bits());
    }

    #[test]
    fn dedup_cap_reports_truncation() {
        let findings = vec![
            finding("a.env", 1, "tok-1", 0.5),
            finding("a.env", 2, "tok-2", 0.5),
            finding("a.env", 3, "tok-3", 0.5),
        ];
        let (ordered, dropped) = dedup_findings(findings, 2);
        assert!(dropped);
        assert_eq!(ordered.len(), 2);
        // Sorted by (path, line, rule_id): first two lines survive.
        assert_eq!(ordered[0].line, 1);
        assert_eq!(ordered[1].line, 2);
    }

    /// End-to-end proof that the real `git_read::run_git` path works: init a
    /// repository, stage a `.env` carrying an AWS-style credential, and scan
    /// the index. The scanner must traverse `rev-parse` → `diff --cached` →
    /// `cat-file` and surface at least one finding with no errors.
    #[test]
    fn staged_secret_in_real_git_repo_is_detected() {
        let dir = temp_root("staged-e2e");
        for args in [
            &["init", "-q"][..],
            &["config", "user.email", "t@t"][..],
            &["config", "user.name", "t"][..],
            &["config", "core.hooksPath", ""][..],
        ] {
            run_git(&dir, args, GIT_TIMEOUT_SECONDS).unwrap();
        }
        std::fs::write(dir.join(".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7REALKEY\n").unwrap();
        run_git(&dir, &["add", ".env"], GIT_TIMEOUT_SECONDS).unwrap();

        let result = scan_staged_secrets(&dir, &StagedScanOptions::default());
        assert!(
            result.errors.is_empty(),
            "unexpected errors: {:?}",
            result.errors
        );
        assert!(
            result.findings.iter().any(|f| f.path == ".env"),
            "expected a finding on .env, got {:?}",
            result.findings
        );

        // Sanity: the same content left unstaged after removal must vanish.
        run_git(&dir, &["reset", "-q"], GIT_TIMEOUT_SECONDS).unwrap();
        std::fs::remove_file(dir.join(".env")).unwrap();
        let clean = scan_staged_secrets(&dir, &StagedScanOptions::default());
        assert!(
            clean.findings.is_empty(),
            "unstaged file leaked: {:?}",
            clean.findings
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
