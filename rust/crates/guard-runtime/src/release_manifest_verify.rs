//! Signed release-manifest verification for machine-owned runtimes.
//!
//! A machine install ships `release-manifest.json` next to its runtime. The
//! manifest names the release (version, build, installer identity, platform)
//! and lists every runtime file with its SHA-256. Verification checks the
//! manifest's provenance and signature, binds it to the installed native
//! package and the managed minimum version, hashes every listed file through a
//! no-follow descriptor, and walks the runtime so an unlisted file, a link or
//! a reparse point is caught as well as a changed one.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::Metadata;
use std::io::ErrorKind;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use guard_command::inventory_fingerprints::python_compact_json;
use pep440_rs::Version;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde_json::{Map, Value};

#[path = "release_manifest_coverage.rs"]
mod coverage;
#[path = "release_manifest_files.rs"]
mod files;

use coverage::{runtime_file_paths, Coverage};
use files::{hash_regular_file, read_bounded_regular_file, HashFailure};

pub(crate) const RELEASE_MANIFEST_SCHEMA_VERSION: &str = "hol-guard-release-manifest.v1";

/// The traversal and hashing budgets, fixed in production and narrowed by tests.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) runtime_files: usize,
    pub(crate) runtime_directories: usize,
    pub(crate) runtime_entries: usize,
    pub(crate) runtime_bytes: u64,
    pub(crate) runtime_file_bytes: u64,
    pub(crate) traversal: Duration,
}

pub(crate) const LIMITS: Limits = Limits {
    runtime_files: 100_000,
    runtime_directories: 100_000,
    runtime_entries: 200_000,
    runtime_bytes: 2 * 1024 * 1024 * 1024,
    runtime_file_bytes: 512 * 1024 * 1024,
    traversal: Duration::from_secs(30),
};

/// What the caller expects of the manifest and the runtime it covers.
#[derive(Debug, Default)]
pub(crate) struct Expectations {
    pub(crate) trusted_keys: BTreeMap<String, Vec<u8>>,
    pub(crate) require_signature: bool,
    pub(crate) platform: Option<String>,
    pub(crate) architecture: Option<String>,
    pub(crate) owner_uid: Option<u32>,
    pub(crate) installer_identity: Option<String>,
    pub(crate) native_version: Option<String>,
    pub(crate) minimum_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Verification {
    pub(crate) status: &'static str,
    pub(crate) reason_code: &'static str,
    pub(crate) version: Option<String>,
    pub(crate) build_id: Option<String>,
    pub(crate) installer_identity: Option<String>,
    pub(crate) signature_state: &'static str,
}

impl Verification {
    fn bare(status: &'static str, reason_code: &'static str) -> Self {
        Self {
            status,
            reason_code,
            version: None,
            build_id: None,
            installer_identity: None,
            signature_state: "unverified",
        }
    }
}

/// A failure the verifier reports as `release_manifest_invalid`.
struct Invalid;

impl From<std::io::Error> for Invalid {
    fn from(_: std::io::Error) -> Self {
        Invalid
    }
}

/// The identity a verdict past the manifest's identity fields carries.
struct Identity {
    version: String,
    build_id: String,
    installer_identity: String,
}

impl Identity {
    fn verdict(
        &self,
        status: &'static str,
        reason_code: &'static str,
        signature_state: &'static str,
    ) -> Verification {
        Verification {
            status,
            reason_code,
            version: Some(self.version.clone()),
            build_id: Some(self.build_id.clone()),
            installer_identity: Some(self.installer_identity.clone()),
            signature_state,
        }
    }
}

/// Verify manifest identity, signature, complete runtime coverage, and every file hash.
pub(crate) fn verify_release_manifest(
    manifest_path: &Path,
    runtime_root: &Path,
    expected: &Expectations,
    limits: &Limits,
) -> Verification {
    verify(manifest_path, runtime_root, expected, limits)
        .unwrap_or_else(|Invalid| Verification::bare("tampered", "release_manifest_invalid"))
}

fn verify(
    manifest_path: &Path,
    runtime_root: &Path,
    expected: &Expectations,
    limits: &Limits,
) -> Result<Verification, Invalid> {
    let manifest_lstat = match std::fs::symlink_metadata(manifest_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Ok(Verification::bare("absent", "release_manifest_absent"));
        }
        Err(_) => return Err(Invalid),
    };
    if manifest_lstat.file_type().is_symlink() {
        return Ok(Verification::bare(
            "tampered",
            "release_manifest_path_escape",
        ));
    }
    let (manifest_bytes, manifest_metadata) = read_bounded_regular_file(manifest_path)?;
    if let Some(owner_uid) = expected.owner_uid {
        match owner_verdict(&manifest_metadata, owner_uid)? {
            OwnerVerdict::WrongOwner => {
                return Ok(Verification::bare(
                    "tampered",
                    "release_manifest_wrong_owner",
                ));
            }
            OwnerVerdict::Writable => {
                return Ok(Verification::bare(
                    "tampered",
                    "release_manifest_insecure_permissions",
                ));
            }
            OwnerVerdict::Restricted => {}
        }
    }
    let payload: Map<String, Value> = match serde_json::from_slice(&manifest_bytes) {
        Ok(Value::Object(payload)) => payload,
        _ => return Err(Invalid),
    };
    if payload.get("schemaVersion").and_then(Value::as_str) != Some(RELEASE_MANIFEST_SCHEMA_VERSION)
    {
        return Err(Invalid);
    }
    let field = |name: &str| match payload.get(name) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        _ => Err(Invalid),
    };
    let identity = Identity {
        version: field("version")?,
        build_id: field("buildId")?,
        installer_identity: field("installerIdentity")?,
    };
    field("sourceCommit")?;
    let manifest_platform = field("platform")?;
    let architecture = field("architecture")?;
    field("policySchemaVersion")?;
    let Ok(manifest_version) = Version::from_str(&identity.version) else {
        return Ok(identity.verdict("tampered", "release_manifest_version_invalid", "unverified"));
    };
    if expected
        .platform
        .as_deref()
        .is_some_and(|platform| platform != manifest_platform)
    {
        return Ok(identity.verdict(
            "unsupported",
            "release_manifest_platform_mismatch",
            "unverified",
        ));
    }
    if expected
        .architecture
        .as_deref()
        .is_some_and(|expected| expected.to_lowercase() != architecture.to_lowercase())
    {
        return Ok(identity.verdict(
            "unsupported",
            "release_manifest_architecture_mismatch",
            "unverified",
        ));
    }

    let signature_state = match payload.get("signature") {
        None | Some(Value::Null) if expected.require_signature => {
            return Ok(identity.verdict("tampered", "release_manifest_unsigned", "unsigned"));
        }
        None | Some(Value::Null) => "unsigned",
        Some(Value::Object(signature)) => {
            let (Some(Value::String(key_id)), Some(Value::String(encoded))) =
                (signature.get("keyId"), signature.get("value"))
            else {
                return Err(Invalid);
            };
            let Some(key) = expected.trusted_keys.get(key_id) else {
                let reason = if expected.trusted_keys.is_empty() {
                    "release_manifest_trust_anchor_absent"
                } else {
                    "release_manifest_untrusted_key"
                };
                return Ok(identity.verdict("tampered", reason, "unverified"));
            };
            verify_signature(key, encoded, &payload)?;
            "valid"
        }
        Some(_) => return Err(Invalid),
    };

    if expected
        .installer_identity
        .as_deref()
        .is_some_and(|installer| installer != identity.installer_identity)
    {
        return Ok(identity.verdict(
            "tampered",
            "release_manifest_installer_identity_mismatch",
            signature_state,
        ));
    }
    // Both package builders stamp the exact release version into native
    // metadata and this manifest. Equality keeps a validly signed native
    // binary from authenticating a different release payload.
    if let Some(native_version) = expected.native_version.as_deref() {
        let native_version = Version::from_str(native_version).map_err(|_| Invalid)?;
        if manifest_version != native_version {
            return Ok(identity.verdict(
                "tampered",
                "release_manifest_native_version_mismatch",
                signature_state,
            ));
        }
    }
    if let Some(minimum_version) = expected.minimum_version.as_deref() {
        let minimum_version = Version::from_str(minimum_version).map_err(|_| Invalid)?;
        if manifest_version < minimum_version {
            return Ok(identity.verdict(
                "tampered",
                "release_manifest_version_rollback",
                signature_state,
            ));
        }
    }

    let files = match payload.get("files") {
        Some(Value::Array(files)) if !files.is_empty() => files,
        _ => return Err(Invalid),
    };
    if files.len() > limits.runtime_files {
        return Ok(identity.verdict(
            "tampered",
            "release_manifest_file_limit_exceeded",
            signature_state,
        ));
    }
    let resolved_root = std::fs::canonicalize(runtime_root)?;
    let resolved_manifest = std::fs::canonicalize(manifest_path)?;
    if !resolved_manifest.starts_with(&resolved_root) {
        return Ok(identity.verdict("tampered", "release_manifest_path_escape", signature_state));
    }
    let mut listed_paths = BTreeSet::new();
    let mut total_runtime_bytes = 0_u64;
    for entry in files {
        let Value::Object(entry) = entry else {
            return Err(Invalid);
        };
        let relative = entry
            .get("path")
            .and_then(Value::as_str)
            .filter(|path| valid_relative_path(path))
            .ok_or(Invalid)?;
        let digest = match entry.get("sha256") {
            Some(Value::String(digest)) if digest.chars().count() == 64 => digest,
            _ => return Err(Invalid),
        };
        if !listed_paths.insert(relative.to_owned()) {
            return Ok(identity.verdict(
                "tampered",
                "release_manifest_duplicate_path",
                signature_state,
            ));
        }
        let unresolved_candidate = resolved_root.join(relative);
        if std::fs::symlink_metadata(&unresolved_candidate)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Ok(identity.verdict(
                "tampered",
                "release_manifest_path_escape",
                signature_state,
            ));
        }
        if std::fs::metadata(&unresolved_candidate).is_err() {
            return Ok(identity.verdict(
                "tampered",
                "release_manifest_file_missing",
                signature_state,
            ));
        }
        let candidate = std::fs::canonicalize(&unresolved_candidate)?;
        if !candidate.starts_with(&resolved_root)
            || !std::fs::metadata(&candidate).is_ok_and(|metadata| metadata.is_file())
        {
            return Ok(identity.verdict(
                "tampered",
                "release_manifest_path_escape",
                signature_state,
            ));
        }
        let remaining = limits.runtime_bytes.saturating_sub(total_runtime_bytes);
        let (actual, hashed_bytes, metadata) =
            match hash_regular_file(&candidate, limits.runtime_file_bytes.min(remaining)) {
                Ok(hashed) => hashed,
                Err(HashFailure::TooLarge) => {
                    return Ok(identity.verdict(
                        "tampered",
                        "release_manifest_size_limit_exceeded",
                        signature_state,
                    ));
                }
                Err(HashFailure::Unreadable) => return Err(Invalid),
            };
        total_runtime_bytes += hashed_bytes;
        if let Some(owner_uid) = expected.owner_uid {
            match owner_verdict(&metadata, owner_uid)? {
                OwnerVerdict::WrongOwner => {
                    return Ok(identity.verdict(
                        "tampered",
                        "release_runtime_wrong_owner",
                        signature_state,
                    ));
                }
                OwnerVerdict::Writable => {
                    return Ok(identity.verdict(
                        "tampered",
                        "release_runtime_insecure_permissions",
                        signature_state,
                    ));
                }
                OwnerVerdict::Restricted => {}
            }
        }
        if actual != digest.to_lowercase() {
            return Ok(identity.verdict(
                "tampered",
                "release_manifest_hash_mismatch",
                signature_state,
            ));
        }
    }
    let (actual_paths, unnameable) =
        match runtime_file_paths(&resolved_root, &resolved_manifest, limits)? {
            Coverage::Files { paths, unnameable } => (paths, unnameable),
            Coverage::Refused(reason_code) => {
                return Ok(identity.verdict("tampered", reason_code, signature_state));
            }
        };
    if unnameable || actual_paths.iter().any(|path| !listed_paths.contains(path)) {
        return Ok(identity.verdict("tampered", "release_manifest_coverage_gap", signature_state));
    }
    if listed_paths.iter().any(|path| !actual_paths.contains(path)) {
        return Ok(identity.verdict("tampered", "release_manifest_file_missing", signature_state));
    }
    Ok(identity.verdict("healthy", "release_manifest_valid", signature_state))
}

/// The signature covers the manifest without its `signature` member, encoded
/// as Python's `json.dumps(sort_keys=True, separators=(",", ":"))`.
fn verify_signature(
    key: &[u8],
    encoded: &str,
    payload: &Map<String, Value>,
) -> Result<(), Invalid> {
    if key.len() != 32 {
        return Err(Invalid);
    }
    let signature = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| Invalid)?;
    let mut unsigned = payload.clone();
    unsigned.remove("signature");
    let canonical = python_compact_json(&Value::Object(unsigned));
    UnparsedPublicKey::new(&ED25519, key)
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| Invalid)
}

/// A POSIX relative path with no parent step and no backslash.
fn valid_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.split('/').any(|part| part == "..")
}

enum OwnerVerdict {
    Restricted,
    WrongOwner,
    Writable,
}

#[cfg(unix)]
fn owner_verdict(metadata: &Metadata, owner_uid: u32) -> Result<OwnerVerdict, Invalid> {
    use std::os::unix::fs::MetadataExt;
    Ok(if metadata.uid() != owner_uid {
        OwnerVerdict::WrongOwner
    } else if metadata.mode() & 0o022 != 0 {
        OwnerVerdict::Writable
    } else {
        OwnerVerdict::Restricted
    })
}

/// Windows ownership is an ACL, not a uid; a caller that asks for a uid there
/// cannot be answered.
#[cfg(not(unix))]
fn owner_verdict(_metadata: &Metadata, _owner_uid: u32) -> Result<OwnerVerdict, Invalid> {
    Err(Invalid)
}

#[cfg(test)]
#[path = "release_manifest_verify_tests.rs"]
mod tests;
