//! Loading machine authority from the native machine source.
//!
//! `load_managed_policy` (mdm/policy.py:352) decides what the machine says
//! before any local configuration is read, and the resident needs the same
//! answer: today it refuses to run whenever a managed path merely exists, which
//! sends every managed machine back to the Python path.
//!
//! The authority is the administrator-owned policy file and nothing else. A
//! path that is not root-owned, is group- or world-writable, or reaches the
//! file through a symlink is not authority, and neither is the cache on a
//! platform whose ownership cannot be verified here. On Windows the authority
//! is the registry key `managed_policy_registry` reads.

// The load lands ahead of its caller: the native guard-config load reads the
// state it returns next, in place of today's blanket refusal.
#![allow(dead_code)]

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::managed_policy::{parse_managed_policy, ManagedPolicy};
use crate::managed_policy_file_trust::{
    create_restricted_directory, machine_controlled_directory_is_trusted,
    machine_controlled_file_is_trusted, replace_restricted_file,
};
use crate::managed_policy_plist::parse_plist;
use crate::managed_policy_registry::load_registry_policy;
pub(crate) use crate::managed_policy_registry::RegistryAuthority;

/// `_MAX_POLICY_BYTES` (mdm/policy.py:31).
pub(crate) const MAX_POLICY_BYTES: u64 = 1024 * 1024;

/// How far a detail string travels, as Python's `str(exc)[:256]`.
const MAX_DETAIL_CHARS: usize = 256;

/// `ManagedPolicyStatus` (mdm/contracts.py).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManagedPolicyStatus {
    /// No machine authority applies.
    Absent,
    /// A policy loaded and governs this machine.
    Active,
    /// Authority is configured but could not be read as a policy.
    Invalid,
    /// Authority is configured and could not be read at all.
    Inaccessible,
    /// Authority is configured and its source is not trustworthy.
    Tampered,
}

impl ManagedPolicyStatus {
    /// The name the status is reported under, as Python's literal.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Active => "active",
            Self::Invalid => "invalid",
            Self::Inaccessible => "inaccessible",
            Self::Tampered => "tampered",
        }
    }

    /// Whether a caller must fall back to the non-weaker floor: configured
    /// authority that did not load is never treated as no authority.
    pub(crate) fn fails_closed(self) -> bool {
        matches!(self, Self::Invalid | Self::Inaccessible | Self::Tampered)
    }
}

/// `ManagedPolicyState` (mdm/contracts.py:417).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ManagedPolicyState {
    pub(crate) status: ManagedPolicyStatus,
    pub(crate) source: String,
    pub(crate) policy: Option<ManagedPolicy>,
    pub(crate) reason_code: Option<&'static str>,
    pub(crate) detail: Option<String>,
}

/// The reason a build with no registry reports when it is asked for a Windows
/// machine's authority. A Windows build reads the registry instead.
pub(crate) const REGISTRY_UNREADABLE: &str = "managed_policy_registry_unreadable";

impl ManagedPolicyState {
    pub(crate) fn new(
        status: ManagedPolicyStatus,
        source: &str,
        reason_code: &'static str,
    ) -> Self {
        Self {
            status,
            source: source.to_owned(),
            policy: None,
            reason_code: Some(reason_code),
            detail: None,
        }
    }

    /// Whether this runtime could not read the machine's authority at all, as
    /// opposed to reading it and finding it unusable.
    ///
    /// Only a build with no registry reports this for a Windows machine. Its
    /// policy is unknown rather than broken: the settings floor still governs
    /// the decision, but a caller cannot conclude from this status that an
    /// administrator installed a policy this machine is failing to honour.
    pub(crate) fn authority_unreadable(&self) -> bool {
        self.reason_code == Some(REGISTRY_UNREADABLE)
    }

    pub(crate) fn with_detail(mut self, detail: &str) -> Self {
        self.detail = Some(detail.chars().take(MAX_DETAIL_CHARS).collect());
        self
    }
}

/// The platform the machine paths are resolved for. The target decides it in
/// production; the tests name it so both platforms' rules stay exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MachineSystem {
    Darwin,
    Windows,
    Other,
}

/// This build's platform, as `platform.system()` reports it to Python.
#[cfg(target_os = "macos")]
const CURRENT_SYSTEM: MachineSystem = MachineSystem::Darwin;
#[cfg(windows)]
const CURRENT_SYSTEM: MachineSystem = MachineSystem::Windows;
#[cfg(all(not(windows), not(target_os = "macos")))]
const CURRENT_SYSTEM: MachineSystem = MachineSystem::Other;

impl MachineSystem {
    /// This build's platform.
    pub(crate) fn current() -> Self {
        CURRENT_SYSTEM
    }

    /// `default_machine_paths(...).policy_path` (mdm/contracts.py:292).
    fn policy_path(self) -> Option<PathBuf> {
        match self {
            Self::Darwin => Some(PathBuf::from(
                "/Library/Managed Preferences/org.hol.guard.plist",
            )),
            // Windows authority is the registry, not a path.
            Self::Windows => None,
            Self::Other => Some(PathBuf::from("/etc/hol-guard/managed-policy.json")),
        }
    }

    /// `_cache_path` (mdm/policy.py:294).
    fn cache_path(self) -> PathBuf {
        match self {
            Self::Darwin => PathBuf::from(
                "/Library/Application Support/HOL Guard State/managed-policy-cache.json",
            ),
            Self::Windows => PathBuf::from(r"C:\ProgramData\HOL Guard\managed-policy-cache.json"),
            Self::Other => PathBuf::from("/var/lib/hol-guard/managed-policy-cache.json"),
        }
    }
}

/// Where a load reads from, so the tests can place a machine root of their own
/// without a root-owned filesystem.
pub(crate) struct ManagedPolicySource {
    pub(crate) system: MachineSystem,
    /// An explicit policy file, which is read without the ownership walk the
    /// native path requires — Python's `policy_path=` argument.
    pub(crate) policy_path: Option<PathBuf>,
    /// Whether a successful native load refreshes the cache.
    pub(crate) write_cache: bool,
    /// A prefix the machine paths resolve under. Production reads the real
    /// machine root; a harness that cannot own `/` names its own, and a path
    /// below it is never machine-owned, so it is read exactly as an untrusted
    /// profile is.
    pub(crate) machine_root: Option<PathBuf>,
    /// Where a Windows load reads the registry value from.
    pub(crate) registry: RegistryAuthority,
}

impl ManagedPolicySource {
    /// The production source: this platform's native machine paths.
    pub(crate) fn native() -> Self {
        Self {
            system: MachineSystem::current(),
            policy_path: None,
            write_cache: true,
            machine_root: None,
            registry: RegistryAuthority::Native,
        }
    }

    /// The machine policy file this load reads.
    fn native_policy_path(&self) -> Option<PathBuf> {
        self.system
            .policy_path()
            .map(|path| under_root(self.machine_root.as_deref(), path))
    }

    /// The cache beside it.
    fn cache_path(&self) -> PathBuf {
        under_root(self.machine_root.as_deref(), self.system.cache_path())
    }
}

/// Resolve an absolute machine path under an alternate root.
fn under_root(root: Option<&Path>, path: PathBuf) -> PathBuf {
    let Some(root) = root else {
        return path;
    };
    match path.strip_prefix("/") {
        Ok(relative) => root.join(relative),
        // A Windows machine path carries a drive letter, not a leading slash.
        Err(_) => root.join(path.to_string_lossy().replace([':', '\\'], "/")),
    }
}

/// `load_managed_policy` (mdm/policy.py:352).
pub(crate) fn load_managed_policy(source: &ManagedPolicySource) -> ManagedPolicyState {
    if let Some(path) = source.policy_path.as_deref() {
        return load_explicit(path);
    }
    if source.system == MachineSystem::Windows {
        return load_registry_policy(source);
    }
    let Some(native_path) = source.native_policy_path() else {
        return ManagedPolicyState::new(
            ManagedPolicyStatus::Absent,
            "native",
            "managed_policy_absent",
        );
    };
    let display = native_path.to_string_lossy().into_owned();
    // A missing profile is no authority. Any other lstat failure means the
    // runtime could not tell, and that is not a license to use the local
    // configuration: the floor stands in until the profile can be read.
    match fs::symlink_metadata(&native_path) {
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return load_cache(source).unwrap_or_else(|| {
                ManagedPolicyState::new(
                    ManagedPolicyStatus::Absent,
                    &display,
                    "managed_policy_absent",
                )
            });
        }
        Err(_) => {
            return ManagedPolicyState::new(
                ManagedPolicyStatus::Inaccessible,
                &display,
                "managed_policy_inaccessible",
            );
        }
        Ok(_) => {}
    }
    if !machine_controlled_file_is_trusted(&native_path, source.system) {
        return ManagedPolicyState::new(
            ManagedPolicyStatus::Tampered,
            &display,
            "managed_policy_source_tampered",
        );
    }
    match read_policy_document(&native_path).and_then(|payload| {
        let policy = parse_managed_policy(&payload).map_err(LoadError::from)?;
        Ok((payload, policy))
    }) {
        Ok((payload, policy)) => {
            if source.write_cache {
                write_cache(&payload, source);
            }
            ManagedPolicyState {
                status: ManagedPolicyStatus::Active,
                source: display,
                policy: Some(policy),
                reason_code: None,
                detail: None,
            }
        }
        Err(LoadError::Inaccessible) => ManagedPolicyState::new(
            ManagedPolicyStatus::Inaccessible,
            &display,
            "managed_policy_inaccessible",
        ),
        Err(LoadError::Invalid(detail)) => ManagedPolicyState::new(
            ManagedPolicyStatus::Invalid,
            &display,
            "managed_policy_invalid",
        )
        .with_detail(&detail),
    }
}

/// An explicit path is a caller's own file: it is read as given, with no
/// ownership walk and no cache, exactly as Python's `policy_path=` is.
fn load_explicit(path: &Path) -> ManagedPolicyState {
    let display = path.to_string_lossy().into_owned();
    if !path.exists() {
        return ManagedPolicyState::new(
            ManagedPolicyStatus::Absent,
            &display,
            "managed_policy_absent",
        );
    }
    match read_policy_document(path)
        .and_then(|payload| parse_managed_policy(&payload).map_err(LoadError::from))
    {
        Ok(policy) => ManagedPolicyState {
            status: ManagedPolicyStatus::Active,
            source: display,
            policy: Some(policy),
            reason_code: None,
            detail: None,
        },
        Err(LoadError::Inaccessible) => ManagedPolicyState::new(
            ManagedPolicyStatus::Inaccessible,
            &display,
            "managed_policy_inaccessible",
        ),
        Err(LoadError::Invalid(detail)) => ManagedPolicyState::new(
            ManagedPolicyStatus::Invalid,
            &display,
            "managed_policy_invalid",
        )
        .with_detail(&detail),
    }
}

/// Python separates `PermissionError` from every other read failure, because
/// unreadable authority and unparseable authority are different states.
enum LoadError {
    Inaccessible,
    Invalid(String),
}

impl From<String> for LoadError {
    fn from(message: String) -> Self {
        Self::Invalid(message)
    }
}

type LoadResult<T> = Result<T, LoadError>;

/// `_read_policy_file` (mdm/policy.py:254).
fn read_policy_document(path: &Path) -> LoadResult<Value> {
    let metadata = fs::metadata(path).map_err(read_error)?;
    if metadata.len() > MAX_POLICY_BYTES {
        return Err(LoadError::Invalid(
            "managed policy exceeds size limit".to_owned(),
        ));
    }
    let bytes = fs::read(path).map_err(read_error)?;
    let is_plist = path
        .extension()
        .is_some_and(|suffix| suffix.to_string_lossy().eq_ignore_ascii_case("plist"));
    if is_plist {
        return parse_plist(&bytes).map_err(LoadError::from);
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| LoadError::Invalid(format!("managed policy is not valid JSON: {error}")))
}

fn read_error(error: std::io::Error) -> LoadError {
    match error.kind() {
        ErrorKind::PermissionDenied => LoadError::Inaccessible,
        _ => LoadError::Invalid(format!("managed policy could not be read: {error}")),
    }
}

/// `_load_policy_cache` (mdm/policy.py:326). A cached policy records that the
/// profile was removed, which is not the same as never having had one.
pub(crate) fn load_cache(source: &ManagedPolicySource) -> Option<ManagedPolicyState> {
    let path = source.cache_path();
    fs::symlink_metadata(&path).ok()?;
    let display = path.to_string_lossy().into_owned();
    // A Windows cache is never trusted: its owner and DACL need native
    // security APIs, and POSIX mode bits say nothing there. Its presence still
    // records a managed state that fails closed.
    if !machine_controlled_file_is_trusted(&path, source.system) {
        return Some(ManagedPolicyState::new(
            ManagedPolicyStatus::Tampered,
            &display,
            "managed_policy_cache_tampered",
        ));
    }
    let state = match read_policy_document(&path)
        .and_then(|payload| parse_managed_policy(&payload).map_err(LoadError::from))
    {
        Ok(policy) => ManagedPolicyState {
            status: ManagedPolicyStatus::Active,
            source: display,
            policy: Some(policy),
            reason_code: Some("managed_policy_profile_removed_cached"),
            detail: None,
        },
        Err(LoadError::Inaccessible) => ManagedPolicyState::new(
            ManagedPolicyStatus::Invalid,
            &display,
            "managed_policy_cache_invalid",
        ),
        Err(LoadError::Invalid(detail)) => ManagedPolicyState::new(
            ManagedPolicyStatus::Invalid,
            &display,
            "managed_policy_cache_invalid",
        )
        .with_detail(&detail),
    };
    Some(state)
}

/// `_write_policy_cache` (mdm/policy.py:311). Only an administrator writes the
/// cache, so an unprivileged runtime never creates a file it would later have
/// to distrust.
pub(crate) fn write_cache(payload: &Value, source: &ManagedPolicySource) {
    if !payload.is_object() || !administrator_context(source.system) {
        return;
    }
    let path = source.cache_path();
    let Some(parent) = path.parent() else {
        return;
    };
    if create_restricted_directory(parent).is_err() {
        return;
    }
    // A directory another account can write is a directory another account can
    // swap, and this runtime would be the one writing the policy that replaces
    // it. A cache that cannot be written safely is simply not written: the next
    // load reads the profile, and a removed profile reports no cached policy.
    if !machine_controlled_directory_is_trusted(parent, source.system) {
        return;
    }
    let Ok(mut serialized) = canonical_cache_bytes(payload) else {
        return;
    };
    serialized.push(b'\n');
    let _ = replace_restricted_file(&path, &serialized);
}

/// `json.dumps(payload, sort_keys=True)`, which the cache is written as. A
/// `serde_json` object is a `BTreeMap` here, so serialising it is already the
/// key-sorted form at every level.
fn canonical_cache_bytes(payload: &Value) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(payload)
}

/// `_administrator_context` (mdm/policy.py:299).
#[cfg(unix)]
fn administrator_context(_system: MachineSystem) -> bool {
    nix::unistd::geteuid().as_raw() == 0
}

#[cfg(not(unix))]
fn administrator_context(_system: MachineSystem) -> bool {
    false
}

#[cfg(test)]
#[path = "managed_policy_load_tests.rs"]
mod tests;
