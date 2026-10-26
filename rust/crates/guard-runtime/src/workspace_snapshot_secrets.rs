//! Deterministic secret detection over the bytes a workspace snapshot hashed.
//!
//! The detector is the shared `guard-scanner` engine; this module only decides
//! which snapshot files it may read and reduces each finding to a value that
//! is safe to store. A reported finding carries the rule id, severity, the
//! root-relative path, the line, and a keyed fingerprint. The matched text is
//! dropped here, at the boundary, and is never serialized, logged or kept in a
//! returned structure.
//!
//! Findings leave this module in their final stored shape: normalized
//! severity, a stable `finding_id`, and one finding per distinct secret in a
//! file with every line it appears on. Python only validates and stores them.
//!
//! The fingerprint key is a per-install secret the caller supplies on stdin.
//! It never appears in a result, a log line or a `Debug` rendering, so a stored
//! fingerprint cannot be used to test guessed secret values.
//!
//! Files Guard treats as credential stores (`.env*`, key and certificate
//! files, and every path the secret-path probe recognizes) are not read for
//! this scan. They are counted as skips so coverage reports what was left out;
//! a skip is never a finding.

use std::collections::HashMap;
use std::fmt;

use guard_command::secret_path_probe::is_secret_path;
use guard_scanner::repository_scanner::decode_text;
use guard_scanner::secret_detection::{detector_version, scan_secret_text, SecretFinding};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub(super) const RESULT_SCHEMA: &str = "guard.workspace-secrets.v1";
pub(super) const MAX_SECRET_FINDINGS: usize = 500;
/// Hex characters kept from the keyed digest: 128 bits dedupes a secret across
/// runs without storing the full digest.
const FINGERPRINT_HEX_CHARS: usize = 32;
const FINDING_ID_HEX_CHARS: usize = 32;
const SOURCE: &str = "working_tree";
/// Shortest per-install key the scan accepts, in bytes.
pub(super) const MIN_KEY_BYTES: usize = 32;
/// Longest root-relative path the scan reads. A longer path is left unread and
/// reported as a truncation, so a finding is never lost to a path bound later.
pub(super) const MAX_PATH_BYTES: usize = 4096;
/// Lines kept per finding; `occurrences` still counts every one.
const MAX_LINES_PER_FINDING: usize = 16;
const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];

/// Key, certificate and keystore files. The secret-path probe only knows
/// credential-store names, so file types that hold key material by format are
/// listed here.
const KEY_MATERIAL_EXTENSIONS: [&str; 13] = [
    "pem", "key", "p8", "p12", "pfx", "crt", "cer", "der", "jks", "keystore", "gpg", "asc", "ppk",
];

/// The per-install fingerprint key as received. Its `Debug` output is fixed
/// text and its memory is cleared on drop.
#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct SecretKey(String);

impl SecretKey {
    pub(super) fn is_usable(&self) -> bool {
        self.0.len() >= MIN_KEY_BYTES
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKey(<redacted>)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct Group {
    finding_id: String,
    rule_id: &'static str,
    family: &'static str,
    severity: &'static str,
    confidence: &'static str,
    path: String,
    fingerprint: String,
    lines: Vec<usize>,
    occurrences: usize,
}

pub(super) struct SecretScan {
    pub(super) fingerprint_key: Zeroizing<[u8; 32]>,
    worktree_key: String,
    groups: Vec<Group>,
    group_index: HashMap<(&'static str, String, String), usize>,
    locations: usize,
    files_scanned: usize,
    bytes_scanned: u64,
    skipped_credential_store: usize,
    skipped_not_text: usize,
    finding_cap_hit: bool,
    path_too_long: bool,
}

/// Counts the walk already holds that describe files this scan never read.
pub(super) struct WalkSkips {
    pub(super) sensitive: usize,
    pub(super) oversize: usize,
}

impl SecretScan {
    /// `private_key` is the per-install secret and `codebase_key` scopes the
    /// fingerprint to a repository, so one secret dedupes across worktrees and
    /// runs without matching another repository's fingerprints.
    pub(super) fn new(private_key: &SecretKey, codebase_key: &str, worktree_key: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"guard.workspace-secret-fingerprint.v2\0");
        hasher.update((private_key.0.len() as u64).to_be_bytes());
        hasher.update(private_key.0.as_bytes());
        hasher.update(codebase_key.as_bytes());
        Self {
            fingerprint_key: Zeroizing::new(hasher.finalize().into()),
            worktree_key: worktree_key.to_owned(),
            groups: Vec::new(),
            group_index: HashMap::new(),
            locations: 0,
            files_scanned: 0,
            bytes_scanned: 0,
            skipped_credential_store: 0,
            skipped_not_text: 0,
            finding_cap_hit: false,
            path_too_long: false,
        }
    }

    /// Whether the content of `relative` may be read for this scan. A
    /// credential store is counted as a skip and answers `false`.
    pub(super) fn admits(&mut self, relative: &str) -> bool {
        if is_credential_store(relative) {
            self.skipped_credential_store += 1;
            return false;
        }
        if relative.len() > MAX_PATH_BYTES {
            self.path_too_long = true;
            return false;
        }
        true
    }

    /// Scan the exact bytes that were hashed for `relative`.
    pub(super) fn observe(&mut self, relative: &str, content: &[u8]) {
        let Some(text) = decode_text(relative, content) else {
            self.skipped_not_text += 1;
            return;
        };
        self.files_scanned += 1;
        self.bytes_scanned += content.len() as u64;
        let remaining = MAX_SECRET_FINDINGS.saturating_sub(self.locations);
        if remaining == 0 {
            self.finding_cap_hit = true;
            return;
        }
        let summary = scan_secret_text(text, relative, SOURCE, None, remaining);
        if summary.findings.len() >= remaining {
            self.finding_cap_hit = true;
        }
        for finding in summary.findings {
            self.record(finding);
        }
    }

    /// Reduce one detector hit to its stored form and fold it into the finding
    /// for the same secret in the same file. Every hit counts toward the cap.
    fn record(&mut self, mut finding: SecretFinding) {
        self.locations += 1;
        let Ok(fingerprint) = finding.fingerprint(self.fingerprint_key.as_slice()) else {
            return;
        };
        finding.candidate.zeroize();
        let fingerprint = fingerprint[..FINGERPRINT_HEX_CHARS].to_owned();
        let key = (finding.rule_id, finding.path.clone(), fingerprint.clone());
        if let Some(&index) = self.group_index.get(&key) {
            let group = &mut self.groups[index];
            group.occurrences += 1;
            if group.lines.len() < MAX_LINES_PER_FINDING && !group.lines.contains(&finding.line) {
                group.lines.push(finding.line);
            }
            return;
        }
        let severity = SEVERITIES
            .iter()
            .copied()
            .find(|known| finding.severity.eq_ignore_ascii_case(known))
            .unwrap_or("unknown");
        self.group_index.insert(key, self.groups.len());
        self.groups.push(Group {
            finding_id: self.finding_id(finding.rule_id, &finding.path, &fingerprint),
            rule_id: finding.rule_id,
            family: finding.family,
            severity,
            confidence: finding.confidence,
            path: finding.path,
            fingerprint,
            lines: vec![finding.line],
            occurrences: 1,
        });
    }

    /// The line is left out of the identity so a secret keeps its finding when
    /// surrounding lines move.
    fn finding_id(&self, rule_id: &str, path: &str, fingerprint: &str) -> String {
        let mut hasher = Sha256::new();
        for part in [
            "guard.workspace-finding.v1",
            self.worktree_key.as_str(),
            "secret",
            rule_id,
            path,
            fingerprint,
        ] {
            hasher.update(part.as_bytes());
            hasher.update(b"\0");
        }
        let mut id = hex::encode(hasher.finalize());
        id.truncate(FINDING_ID_HEX_CHARS);
        id
    }

    /// `incomplete_reasons` names the snapshot limits that left files unread;
    /// the scan is incomplete under any of them or when it hit its own cap.
    pub(super) fn report(&self, skips: &WalkSkips, incomplete_reasons: &[&str]) -> Value {
        let mut truncation: Vec<&str> = incomplete_reasons.to_vec();
        if self.finding_cap_hit {
            truncation.push("max_findings");
        }
        if self.path_too_long {
            truncation.push("path_too_long");
        }
        truncation.sort_unstable();
        truncation.dedup();
        let mut groups: Vec<&Group> = self.groups.iter().collect();
        groups.sort_by(|a, b| {
            (&a.path, a.rule_id, &a.fingerprint).cmp(&(&b.path, b.rule_id, &b.fingerprint))
        });
        let findings: Vec<Value> = groups
            .into_iter()
            .map(|group| {
                json!({
                    "finding_id": group.finding_id,
                    "rule_id": group.rule_id,
                    "family": group.family,
                    "severity": group.severity,
                    "confidence": group.confidence,
                    "path": group.path,
                    "line": group.lines[0],
                    "lines": group.lines,
                    "occurrences": group.occurrences,
                    "fingerprint": group.fingerprint,
                })
            })
            .collect();
        json!({
            "schema": RESULT_SCHEMA,
            "detector_version": detector_version(),
            "status": if truncation.is_empty() { "complete" } else { "incomplete" },
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "skipped": {
                "credential_store": skips.sensitive + self.skipped_credential_store,
                "not_text": self.skipped_not_text,
                "oversize": skips.oversize,
            },
            "truncation_reasons": truncation,
            "findings": findings,
        })
    }
}

fn is_credential_store(relative: &str) -> bool {
    let basename = relative.rsplit('/').next().unwrap_or(relative);
    if let Some((_, extension)) = basename.rsplit_once('.') {
        if KEY_MATERIAL_EXTENSIONS
            .iter()
            .any(|known| extension.eq_ignore_ascii_case(known))
        {
            return true;
        }
    }
    is_secret_path(relative, None, None)
}
