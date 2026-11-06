//! Whether a request may name a directory, decided where the runtime lives.
//!
//! The daemon used to settle this in Python before it called the resident:
//! `directory_path_authority.validate_guard_directory_path` for the hook's
//! `home`, `guard-home` and `workspace`, and the server's own guard-home
//! equality check. Those rules are here now, so a hook's directories are
//! trusted by the same runtime that decides the call.

use crate::guard_paths::{self, PathError};
use crate::hook_path_rules;
use crate::resident_diagnostics::{observe_value, Phase};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Why a directory is not one the caller may name. The wire spelling is the
/// `reason` the daemon used to record, so its counters keep their meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DirectoryTrustRejection {
    /// The value does not name an absolute path.
    RelativePath,
    /// The path cannot be resolved, or is spelled in a way this runtime
    /// refuses to guess at, such as another user's `~name`.
    PathResolveFailed,
    /// The path resolves outside every root the caller may reach.
    UnexpectedRoot,
    /// A `guard-home` that resolves somewhere other than the running store.
    UnexpectedGuardHome,
    /// An out-of-band payload reference that Guard's own writer could not
    /// have put where it is.
    UntrustedPayloadReference,
}

impl DirectoryTrustRejection {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::RelativePath => "relative_path",
            Self::PathResolveFailed => "path_resolve_failed",
            Self::UnexpectedRoot => "unexpected_root",
            Self::UnexpectedGuardHome => "unexpected_guard_home",
            Self::UntrustedPayloadReference => "untrusted_payload_reference",
        }
    }
}

fn unresolvable(error: PathError) -> DirectoryTrustRejection {
    match error {
        PathError::Relative => DirectoryTrustRejection::RelativePath,
        PathError::Unusable => DirectoryTrustRejection::PathResolveFailed,
    }
}

/// `canonical_guard_home_path`: the spelling identity-scoped state is keyed
/// by. A home that will not resolve keeps its expanded spelling, as in
/// Python, so a missing directory still has one stable key.
pub(crate) fn canonical_guard_home_path(
    guard_home: &str,
    home_dir: &str,
) -> Result<String, DirectoryTrustRejection> {
    let expanded = guard_paths::expanduser(guard_home, home_dir).map_err(unresolvable)?;
    let candidate = match guard_paths::python_realpath_lax(Path::new(&expanded)) {
        Ok(resolved) => resolved.to_string_lossy().into_owned(),
        Err(_) => expanded,
    };
    guard_paths::normpath(&candidate).map_err(unresolvable)
}

/// `trusted_guard_directory_roots`: the current home, plus the directory
/// holding the Guard home when that sits outside the home.
pub(crate) fn trusted_guard_directory_roots(
    guard_home: &str,
    home_dir: &str,
) -> Result<Vec<PathBuf>, DirectoryTrustRejection> {
    let current_home = resolved(home_dir, home_dir)?;
    let guard_home_root = resolved(guard_home, home_dir)?
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    let mut roots = vec![current_home.clone()];
    if guard_home_root != current_home && !guard_home_root.starts_with(&current_home) {
        roots.push(guard_home_root);
    }
    Ok(roots)
}

fn resolved(value: &str, home_dir: &str) -> Result<PathBuf, DirectoryTrustRejection> {
    let expanded = guard_paths::expanduser(value, home_dir).map_err(unresolvable)?;
    guard_paths::python_realpath_lax(Path::new(&expanded)).map_err(unresolvable)
}

/// `validate_guard_directory_path`: the path the caller may use, or why it
/// may not. A workspace may also name a directory the caller owns under a
/// temporary root, which is where harnesses put scratch checkouts.
pub(crate) fn validate_guard_directory_path(
    value: &str,
    roots: &[PathBuf],
    home_dir: &str,
    temp_dir: &Path,
    allow_owned_temporary: bool,
) -> Result<PathBuf, DirectoryTrustRejection> {
    let expanded = guard_paths::expanduser(value, home_dir).map_err(unresolvable)?;
    if !Path::new(&expanded).is_absolute() {
        return Err(DirectoryTrustRejection::RelativePath);
    }
    let candidate = guard_paths::python_realpath_lax(Path::new(&expanded)).map_err(unresolvable)?;
    for root in roots {
        let root_path = guard_paths::python_realpath_lax(root).map_err(unresolvable)?;
        if candidate == root_path {
            return Ok(root_path);
        }
        if candidate.starts_with(&root_path) {
            return Ok(candidate);
        }
    }
    if allow_owned_temporary {
        if let Some(workspace) = validated_owned_temporary_workspace(&candidate, home_dir, temp_dir)
        {
            return Ok(workspace);
        }
    }
    Err(DirectoryTrustRejection::UnexpectedRoot)
}

/// `validated_owned_temporary_workspace`: a directory the caller owns,
/// strictly under a temporary root. The shared root itself is never a
/// workspace; hook normalization already reads it as "no workspace".
pub(crate) fn validated_owned_temporary_workspace(
    candidate: &Path,
    home_dir: &str,
    temp_dir: &Path,
) -> Option<PathBuf> {
    let canonical = guard_paths::python_realpath_lax(candidate).ok()?;
    let temporary_root =
        guard_paths::trusted_temporary_root_for_path(&canonical, temp_dir).ok()??;
    let root_path = guard_paths::python_realpath_lax(&temporary_root).ok()?;
    if canonical == root_path || !canonical.starts_with(&root_path) {
        return None;
    }
    let metadata = std::fs::metadata(&canonical).ok()?;
    if !metadata.is_dir() {
        return None;
    }
    if cfg!(unix) {
        if !guard_paths::owned_by_current_user(&canonical) {
            return None;
        }
    } else {
        // Without a uid to compare, Python only trusts a temporary root that
        // is the caller's home or sits inside it.
        let current_home = guard_paths::python_realpath_lax(Path::new(home_dir)).ok()?;
        if !root_path.starts_with(&current_home) {
            return None;
        }
    }
    Some(canonical)
}

/// The server's `_validated_hook_guard_home`: a `guard-home` the caller sends
/// has to resolve to the store this runtime is serving.
pub(crate) fn validated_hook_guard_home(
    value: &str,
    expected_guard_home: &str,
    home_dir: &str,
) -> Result<PathBuf, DirectoryTrustRejection> {
    let expanded = guard_paths::expanduser(value, home_dir).map_err(unresolvable)?;
    if !Path::new(&expanded).is_absolute() {
        return Err(DirectoryTrustRejection::RelativePath);
    }
    let candidate = guard_paths::python_realpath_lax(Path::new(&expanded)).map_err(unresolvable)?;
    let expected = resolved(expected_guard_home, home_dir)?;
    if candidate != expected {
        return Err(DirectoryTrustRejection::UnexpectedGuardHome);
    }
    Ok(expected)
}

/// One directory the caller wants to use, and the rule it is held to.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryTrustCandidateV1 {
    /// The hook parameter this value arrived as: `home`, `guard-home` or
    /// `workspace`. It labels the verdict the caller reads back, and names
    /// the rule unless `rule` names a different one.
    pub parameter: String,
    pub value: String,
    /// The rule to hold this value to, when a request carries several
    /// spellings of the same directory and needs them told apart. A caller
    /// that predates this sends none, and the parameter names the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryTrustRequestV1 {
    pub schema: String,
    pub request_id: String,
    /// The Guard home the caller is serving, which a `guard-home` candidate
    /// has to resolve to.
    pub guard_home: String,
    pub home_dir: String,
    /// The caller's `tempfile.gettempdir()`. This process has its own, which
    /// may differ, and the temporary-root rules follow the caller's.
    pub temp_dir: String,
    pub candidates: Vec<DirectoryTrustCandidateV1>,
}

pub(crate) const DIRECTORY_TRUST_REQUEST_SCHEMA: &str = "guard-directory-trust-request.v1";
pub(crate) const DIRECTORY_TRUST_RESULT_SCHEMA: &str = "guard-directory-trust-result.v1";

/// A request names a handful of paths; anything larger is not one of ours.
const DIRECTORY_TRUST_MAX_BYTES: usize = 64 * 1024;

/// Announced so a daemon that predates this operation keeps its own rules
/// instead of calling one the runtime does not answer.
pub(crate) const DIRECTORY_TRUST_FEATURE: &str = "directory-trust-v1";

/// Announced separately, because a daemon that sends `hook-workspace`,
/// `exec-workdir` or `payload-reference` to a runtime that predates them
/// would have its spellings read as plain directories.
pub(crate) const HOOK_PATH_RULES_FEATURE: &str = "hook-path-rules-v1";

/// What one candidate settled to. A hook spelling has a third answer the
/// directory parameters do not: the request named no directory at all.
enum CandidateVerdict {
    Trusted(PathBuf),
    Absent,
    Rejected(DirectoryTrustRejection),
}

impl From<Result<PathBuf, DirectoryTrustRejection>> for CandidateVerdict {
    fn from(verdict: Result<PathBuf, DirectoryTrustRejection>) -> Self {
        match verdict {
            Ok(path) => Self::Trusted(path),
            Err(rejection) => Self::Rejected(rejection),
        }
    }
}

/// Settles every candidate in one call. A rejection carries the parameter and
/// the reason the daemon's counters already use; it never carries the path.
pub(crate) fn evaluate_directory_trust_request(
    request: &DirectoryTrustRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound and digest the whole request before any path work, so the answer
    // the caller binds to covers exactly the bytes it sent.
    let request_sha256 =
        crate::package_authority_op::request_digest_with_limit(request, DIRECTORY_TRUST_MAX_BYTES)
            .map_err(|_| "native_directory_trust_too_large".to_owned())?;
    let body = if request.schema == DIRECTORY_TRUST_REQUEST_SCHEMA {
        observe_value(Phase::DirectoryTrust, || evaluate(request))
    } else {
        json!({"status": "error", "code": "native_directory_trust_schema_mismatch"})
    };
    let mut result = json!({
        "schema": DIRECTORY_TRUST_RESULT_SCHEMA,
        "request_id": request.request_id,
        "request_sha256": request_sha256,
    });
    let object = result.as_object_mut().expect("a JSON object");
    for (key, value) in body.as_object().expect("a JSON object") {
        object.insert(key.clone(), value.clone());
    }
    serde_json::to_vec(&result).map_err(|error| error.to_string())
}

/// A hook spelling that named something is held to the workspace rule,
/// which is the rule the daemon applied to it before.
fn trusted_workspace(
    value: &str,
    roots: &Result<Vec<PathBuf>, DirectoryTrustRejection>,
    request: &DirectoryTrustRequestV1,
    temp_dir: &Path,
) -> CandidateVerdict {
    match roots {
        Ok(roots) => {
            validate_guard_directory_path(value, roots, &request.home_dir, temp_dir, true).into()
        }
        Err(rejection) => CandidateVerdict::Rejected(*rejection),
    }
}

fn evaluate(request: &DirectoryTrustRequestV1) -> Value {
    let temp_dir = PathBuf::from(&request.temp_dir);
    let roots = trusted_guard_directory_roots(&request.guard_home, &request.home_dir);
    let results: Vec<Value> = request
        .candidates
        .iter()
        .map(|candidate| {
            let rule = candidate.rule.as_deref().unwrap_or(&candidate.parameter);
            let verdict: CandidateVerdict = match rule {
                "guard-home" => validated_hook_guard_home(
                    &candidate.value,
                    &request.guard_home,
                    &request.home_dir,
                )
                .into(),
                "payload-reference" => {
                    match hook_path_rules::trusted_payload_reference(&candidate.value, &temp_dir) {
                        Some(path) => CandidateVerdict::Trusted(path),
                        None => CandidateVerdict::Rejected(
                            DirectoryTrustRejection::UntrustedPayloadReference,
                        ),
                    }
                }
                rule @ ("hook-workspace" | "exec-workdir") => {
                    let normalized = if rule == "hook-workspace" {
                        hook_path_rules::normalized_hook_workspace(
                            &candidate.value,
                            &request.home_dir,
                            &temp_dir,
                        )
                    } else {
                        hook_path_rules::normalized_exec_workdir(
                            &candidate.value,
                            &request.home_dir,
                            &temp_dir,
                        )
                    };
                    match normalized {
                        Err(error) => CandidateVerdict::Rejected(unresolvable(error)),
                        Ok(None) => CandidateVerdict::Absent,
                        Ok(Some(value)) => trusted_workspace(&value, &roots, request, &temp_dir),
                    }
                }
                rule => match &roots {
                    Ok(roots) => validate_guard_directory_path(
                        &candidate.value,
                        roots,
                        &request.home_dir,
                        &temp_dir,
                        rule == "workspace",
                    )
                    .into(),
                    Err(rejection) => CandidateVerdict::Rejected(*rejection),
                },
            };
            match verdict {
                CandidateVerdict::Trusted(path) => json!({
                    "parameter": candidate.parameter,
                    "trusted": true,
                    "path": path.to_string_lossy(),
                }),
                CandidateVerdict::Absent => json!({
                    "parameter": candidate.parameter,
                    "trusted": false,
                    "absent": true,
                }),
                CandidateVerdict::Rejected(rejection) => json!({
                    "parameter": candidate.parameter,
                    "trusted": false,
                    "reason": rejection.reason(),
                }),
            }
        })
        .collect();
    json!({
        "status": "ok",
        "code": "ok",
        "canonical_guard_home":
            canonical_guard_home_path(&request.guard_home, &request.home_dir).ok(),
        "results": results,
    })
}

#[cfg(all(test, unix))]
#[path = "directory_trust_tests.rs"]
mod tests;
