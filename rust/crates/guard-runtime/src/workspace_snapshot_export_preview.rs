//! `workspace-export-preview --stdin`: what a source export of named workspace
//! files would contain, computed locally and never sent.
//!
//! The caller names the root-relative files an operation asked for. Each one
//! is reached from the root one component at a time without following a
//! symlink, so a link anywhere on the path, a `..` component or an absolute
//! path cannot pull in a file outside the root. Files the snapshot never
//! reads (credential stores, key material, policy directories such as `.git`
//! or `node_modules`) stay excluded even when named, and so do binary and
//! oversize files.
//!
//! Every included file is redacted with the shared secret detector: each
//! matched secret is replaced by a fixed marker and the result is scanned
//! again. When a match survives, or the detector hit its per-file cap, the
//! file is reported as `redaction_failed` and the whole bundle is `blocked`.
//! A blocked bundle stops only the export; local scanning is unaffected.
//!
//! The result lists paths, byte counts, digests and the rule ids that were
//! redacted. It never carries file content or matched text. `bundle_digest`
//! binds the redacted bytes of every included file, the worktree and the
//! detector version, so an export built later can be checked against the
//! preview the user agreed to.

use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

use guard_command::local_supply_chain::is_audit_sensitive_basename;
use guard_scanner::repository_scanner::decode_text;
use guard_scanner::secret_detection::{
    detector_version, scan_secret_text, SecretFinding, SecretScanSummary,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::secrets::{is_credential_store, MAX_PATH_BYTES};
use super::{keyed_digest, SKIP_DIRS};
use crate::workspace_snapshot_file::{hash_stable, DirHandle, HashError, Kind};
use crate::workspace_snapshot_git::git_identity;

pub(crate) const COMMAND: &str = "workspace-export-preview";
pub(crate) const FEATURE: &str = "workspace-export-preview-v1";
const RESULT_SCHEMA: &str = "guard.workspace-export-preview.v1";
const BUNDLE_DOMAIN: &str = "guard.workspace-export-bundle.v1";
const SOURCE: &str = "export_preview";
/// Replaces every matched secret in the exported text.
pub(super) const REDACTION_MARKER: &str = "[REDACTED]";

pub(super) const MAX_PATHS: usize = 200;
const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024;
const DEFAULT_MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024;
const HARD_MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const HARD_MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
/// A file with this many detector hits is not trusted to be fully redacted.
pub(super) const MAX_FINDINGS_PER_FILE: usize = 200;

/// The secret detector, passed in so tests can stand in a detector that a
/// redaction cannot satisfy.
pub(super) type Scanner = fn(&str, &str, usize) -> SecretScanSummary;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportPreviewRequest {
    pub(crate) root: String,
    /// Root-relative files, `/`-separated. Duplicates are previewed once.
    pub(crate) paths: Vec<String>,
    #[serde(default)]
    pub(crate) max_file_bytes: u64,
    #[serde(default)]
    pub(crate) max_total_bytes: u64,
}

struct Limits {
    file_bytes: u64,
    total_bytes: u64,
}

impl Limits {
    fn from_request(request: &ExportPreviewRequest) -> Self {
        fn bounded(value: u64, default: u64, hard: u64) -> u64 {
            if value == 0 {
                default
            } else {
                value.min(hard)
            }
        }
        Self {
            file_bytes: bounded(
                request.max_file_bytes,
                DEFAULT_MAX_FILE_BYTES,
                HARD_MAX_FILE_BYTES,
            ),
            total_bytes: bounded(
                request.max_total_bytes,
                DEFAULT_MAX_TOTAL_BYTES,
                HARD_MAX_TOTAL_BYTES,
            ),
        }
    }
}

/// One named file after redaction. Only digests and counts are kept.
struct Included {
    path: String,
    bytes: u64,
    source_sha256: String,
    export_bytes: u64,
    export_sha256: String,
    redactions: usize,
    rules: Vec<&'static str>,
}

/// Why a named file is not in the bundle.
enum Outcome {
    Included(Included),
    Excluded(&'static str),
}

pub(super) enum Redaction {
    Clean {
        text: Zeroizing<String>,
        redactions: usize,
        rules: Vec<&'static str>,
    },
    Failed,
}

pub(crate) fn run_command(bytes: &[u8]) -> Result<Value, String> {
    let request: ExportPreviewRequest = serde_json::from_slice(bytes)
        .map_err(|_| "workspace_export_preview_request_invalid".to_owned())?;
    Ok(match preview(&request) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(error) => json!({"ok": false, "error": error}),
    })
}

pub(crate) fn preview(request: &ExportPreviewRequest) -> Result<Value, String> {
    preview_with(request, scan)
}

fn scan(text: &str, path: &str, max_findings: usize) -> SecretScanSummary {
    scan_secret_text(text, path, SOURCE, None, max_findings)
}

pub(super) fn preview_with(
    request: &ExportPreviewRequest,
    scanner: Scanner,
) -> Result<Value, String> {
    if request.paths.len() > MAX_PATHS {
        return Err("workspace_export_preview_too_many_paths".to_owned());
    }
    let requested = PathBuf::from(&request.root);
    if !requested.is_absolute() {
        return Err("workspace_export_preview_root_not_absolute".to_owned());
    }
    let root = fs::canonicalize(&requested).map_err(|_| "workspace_export_preview_root_missing")?;
    let root_text = root
        .to_str()
        .ok_or("workspace_export_preview_root_not_utf8")?
        .to_owned();
    let handle = DirHandle::open_root(&root).ok_or("workspace_export_preview_root_unreadable")?;
    let limits = Limits::from_request(request);
    let git = git_identity(&root);
    let worktree_key = keyed_digest("worktree", &root_text);
    let codebase_key = keyed_digest(
        "codebase",
        git.common_dir.as_deref().unwrap_or(root_text.as_str()),
    );

    let mut paths: Vec<&str> = request.paths.iter().map(String::as_str).collect();
    paths.sort_unstable();
    paths.dedup();
    let mut included: Vec<Included> = Vec::new();
    let mut excluded: Vec<Value> = Vec::new();
    let mut total: u64 = 0;
    let mut blocked = false;
    for path in paths {
        match preview_file(&handle, path, &limits, &mut total, scanner) {
            Outcome::Included(file) => included.push(file),
            Outcome::Excluded(reason) => {
                blocked |= reason == "redaction_failed";
                excluded.push(json!({"path": path, "reason": reason}));
            }
        }
    }

    let version = detector_version();
    let bundle_digest = bundle_digest(&worktree_key, &version, &included);
    let export_bytes: u64 = included.iter().map(|file| file.export_bytes).sum();
    let redactions: usize = included.iter().map(|file| file.redactions).sum();
    let status = if blocked {
        "blocked"
    } else if included.is_empty() {
        "empty"
    } else {
        "ready"
    };
    let files: Vec<Value> = included
        .iter()
        .map(|file| {
            json!({
                "path": file.path,
                "bytes": file.bytes,
                "source_sha256": file.source_sha256,
                "export_bytes": file.export_bytes,
                "export_sha256": file.export_sha256,
                "redactions": file.redactions,
                "redaction_rules": file.rules,
            })
        })
        .collect();
    Ok(json!({
        "schema": RESULT_SCHEMA,
        "status": status,
        "root": root_text,
        "worktree_key": worktree_key,
        "codebase_key": codebase_key,
        "git": {"head_commit": git.head_commit, "head_ref": git.head_ref},
        "detector_version": version,
        "bundle_digest": bundle_digest,
        "file_count": files.len(),
        "export_bytes": export_bytes,
        "redactions": redactions,
        "files": files,
        "excluded": excluded,
        "limits": {
            "max_paths": MAX_PATHS,
            "max_file_bytes": limits.file_bytes,
            "max_total_bytes": limits.total_bytes,
        },
    }))
}

/// Components of a root-relative `/`-separated path, or `None` when it is
/// empty, absolute, too long, or names `.`/`..`, an empty component or a
/// backslash. On Windows a component may not hold `:`, end in `.` or a
/// space, or look like an 8.3 short name: Windows drops trailing dots and
/// spaces and resolves short names, so `.env.` or `ENV~1` would open `.env`
/// while slipping past the name checks.
fn components(path: &str) -> Option<Vec<&str>> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.contains(['\\', '\0']) {
        return None;
    }
    let parts: Vec<&str> = path.split('/').collect();
    let invalid = |part: &&str| {
        part.is_empty()
            || *part == "."
            || *part == ".."
            || (cfg!(windows)
                && (part.contains(':') || part.ends_with(['.', ' ']) || may_be_short_name(part)))
    };
    if parts.iter().any(invalid) {
        return None;
    }
    Some(parts)
}

/// Whether `part` could be an 8.3 short name, which holds `~` followed by a
/// digit. A long name of that shape is refused too.
pub(super) fn may_be_short_name(part: &str) -> bool {
    part.split('~')
        .skip(1)
        .any(|tail| tail.starts_with(|c: char| c.is_ascii_digit()))
}

/// `SKIP_DIRS` names are lowercase, and a case-insensitive filesystem opens
/// `.GIT` as `.git`, so the caller's spelling is compared without case.
fn is_policy_directory(name: &str) -> bool {
    SKIP_DIRS.iter().any(|skip| skip.eq_ignore_ascii_case(name))
}

fn preview_file(
    root: &DirHandle,
    path: &str,
    limits: &Limits,
    total: &mut u64,
    scanner: Scanner,
) -> Outcome {
    let Some(parts) = components(path) else {
        return Outcome::Excluded("invalid_path");
    };
    let (name, directories) = parts.split_last().expect("components are never empty");
    let mut opened: Option<DirHandle> = None;
    for directory in directories {
        let current = opened.as_ref().unwrap_or(root);
        let Some(node) = current.stat(OsStr::new(directory)) else {
            return Outcome::Excluded("not_found");
        };
        match node.kind {
            Kind::Symlink => return Outcome::Excluded("symlink"),
            Kind::Directory if is_policy_directory(directory) => {
                return Outcome::Excluded("policy_directory")
            }
            Kind::Directory => match current.open_dir(OsStr::new(directory), &node) {
                Ok(next) => opened = Some(next),
                Err(HashError::Unstable) => return Outcome::Excluded("unstable"),
                Err(HashError::Unreadable) => return Outcome::Excluded("unreadable"),
            },
            _ => return Outcome::Excluded("not_found"),
        }
    }
    let directory = opened.as_ref().unwrap_or(root);
    let Some(node) = directory.stat(OsStr::new(name)) else {
        return Outcome::Excluded("not_found");
    };
    match node.kind {
        Kind::Symlink => return Outcome::Excluded("symlink"),
        Kind::Directory => return Outcome::Excluded("not_a_file"),
        Kind::Special => return Outcome::Excluded("special"),
        Kind::File => {}
    }
    if is_audit_sensitive_basename(name) || is_credential_store(&path.to_ascii_lowercase()) {
        return Outcome::Excluded("sensitive");
    }
    if node.len > limits.file_bytes {
        return Outcome::Excluded("oversize");
    }
    if total.saturating_add(node.len) > limits.total_bytes {
        return Outcome::Excluded("byte_budget");
    }
    let Some(file) = directory.open_file(OsStr::new(name)) else {
        return Outcome::Excluded("unreadable");
    };
    let mut content = Zeroizing::new(Vec::new());
    let (source_sha256, bytes) =
        match hash_stable(file, &node, limits.file_bytes, Some(&mut *content)) {
            Ok(hashed) => hashed,
            Err(HashError::Unstable) => return Outcome::Excluded("unstable"),
            Err(HashError::Unreadable) => return Outcome::Excluded("unreadable"),
        };
    // The budget bounds what is read and scanned, so a file excluded after
    // reading still spends it.
    *total += bytes;
    let Some(text) = decode_text(path, &content[..]) else {
        return Outcome::Excluded("not_text");
    };
    let Redaction::Clean {
        text,
        redactions,
        rules,
    } = redact(text, path, scanner)
    else {
        return Outcome::Excluded("redaction_failed");
    };
    Outcome::Included(Included {
        path: path.to_owned(),
        bytes,
        source_sha256,
        export_bytes: text.len() as u64,
        export_sha256: hex::encode(Sha256::digest(text.as_bytes())),
        redactions,
        rules,
    })
}

/// Replace every secret the detector finds with the marker, then require a
/// second scan of the result to find nothing. Every occurrence of every
/// matched secret is located first and the output is built in one pass, so a
/// file with many findings is not copied once per finding. Overlapping
/// occurrences collapse into a single marker.
pub(super) fn redact(text: &str, path: &str, scanner: Scanner) -> Redaction {
    let summary = scanner(text, path, MAX_FINDINGS_PER_FILE);
    let mut findings = summary.findings;
    if findings.len() >= MAX_FINDINGS_PER_FILE
        || findings.iter().any(|finding| finding.candidate.is_empty())
    {
        wipe(&mut findings);
        return Redaction::Failed;
    }
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut redactions = 0;
    let mut rules: Vec<&'static str> = Vec::new();
    for (index, finding) in findings.iter().enumerate() {
        let candidate = finding.candidate.as_str();
        // The same secret found again (on another line, or by another rule)
        // is one redaction.
        let repeated = findings[..index]
            .iter()
            .any(|earlier| earlier.candidate == candidate);
        let before = ranges.len();
        if !repeated {
            ranges.extend(
                text.match_indices(candidate)
                    .map(|(start, matched)| (start, start + matched.len())),
            );
        }
        if ranges.len() > before {
            redactions += 1;
        }
        rules.push(finding.rule_id);
    }
    wipe(&mut findings);
    ranges.sort_unstable();
    // Sized up front so the buffer holding source text is never reallocated
    // and left behind unwiped.
    let mut redacted = Zeroizing::new(String::with_capacity(
        text.len() + ranges.len() * REDACTION_MARKER.len(),
    ));
    let mut cursor = 0;
    for (start, end) in ranges {
        if start >= cursor {
            redacted.push_str(&text[cursor..start]);
            redacted.push_str(REDACTION_MARKER);
        }
        cursor = cursor.max(end);
    }
    redacted.push_str(&text[cursor..]);
    let mut recheck = scanner(&redacted, path, 1).findings;
    if !recheck.is_empty() {
        wipe(&mut recheck);
        return Redaction::Failed;
    }
    rules.sort_unstable();
    rules.dedup();
    Redaction::Clean {
        text: redacted,
        redactions,
        rules,
    }
}

fn wipe(findings: &mut [SecretFinding]) {
    for finding in findings {
        finding.candidate.zeroize();
    }
}

fn bundle_digest(worktree_key: &str, detector_version: &str, files: &[Included]) -> String {
    let mut hasher = Sha256::new();
    for part in [BUNDLE_DOMAIN, worktree_key, detector_version] {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }
    for file in files {
        hasher.update(
            format!(
                "{}\0{}\0{}\n",
                file.path, file.export_sha256, file.export_bytes
            )
            .as_bytes(),
        );
    }
    hex::encode(hasher.finalize())
}
