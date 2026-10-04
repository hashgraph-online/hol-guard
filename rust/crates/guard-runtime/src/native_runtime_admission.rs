//! Native-runtime admission: manifest verification + bundled-candidate policy.
//!
//! Port of `native_runtime.py` (`_manifest_for_bundled_identity`,
//! `_is_bundled_candidate`, `_restore_bundled_runtime_execute_bit`,
//! `_windows_native_dll_directories`, `_isolated_environment`). These are the
//! admission gate for a runtime artifact: the manifest is read through
//! `guard-secure-fs::read_bounded` (regular file, single link, no write bits,
//! symlink leaf rejected, identity revalidated), decoded by
//! `guard_contracts::decode_runtime_manifest`, then cross-checked against the
//! runtime's `FileIdentity` and the caller-supplied package version.
//!
//! The isolated spawn environment lives here too so a one-shot runtime launch
//! never inherits user-controlled PATH/loader vars.
//!
//! The capabilities-probe + status walker land below: `run_native_process`
//! routes a bounded launch through `hook_process_spawn::run_isolated_hook_
//! process`; `CapabilitiesProbe` caches successful probes per binary identity
//! and applies a short retry backoff on failure; `native_runtime_status`
//! walks the candidate list to a mode-aware `NativeRuntimeStatusV1`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use guard_contracts::{
    decode_native_capabilities, decode_runtime_manifest, NativeMode, NativeRuntimeCapabilitiesV1,
    NativeRuntimeManifestV1, NativeRuntimeStatusV1, RuntimeIdentityV1,
};
use guard_secure_fs::{read_bounded, SecureReadError};

use crate::hook_process_spawn::{isolated_hook_environment, run_isolated_hook_process};

/// `_NATIVE_MANIFEST_NAME` (`native_runtime.py:57`).
#[allow(dead_code)]
pub const NATIVE_MANIFEST_NAME: &str = "runtime-manifest.json";
/// `_NATIVE_MANIFEST_SCHEMA` (`native_runtime.py:58`).
#[allow(dead_code)]
pub const NATIVE_MANIFEST_SCHEMA: &str = "hol-guard-native-runtime.v1";
/// `_MAX_MANIFEST_BYTES` (`native_runtime.py:59`).
#[allow(dead_code)]
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024;
/// `_NATIVE_PROTOCOL_VERSION` — keep in lockstep with the resident protocol.
#[allow(dead_code)]
pub const NATIVE_MANIFEST_PROTOCOL_VERSION: i64 = 1;

/// Caller-supplied runtime identity, mirroring `NativeRuntimeIdentity`
/// (`native_runtime_values.py:58-62`) — path + size + sha256 are the fields the
/// manifest cross-check consumes. `mtime_ns` is carried for parity/debugging.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeIdentity {
    pub path: PathBuf,
    pub size: i64,
    pub mtime_ns: u64,
    pub sha256: String,
}

/// The reason-code contract is stable across the Python/Rust boundary —
/// `native_runtime_status` surfaces these to `integrity reasons`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ManifestReject {
    /// `native_manifest_missing`
    Missing,
    /// `native_manifest_invalid` (bad type, size, perms, owner, or decode)
    Invalid,
    /// `native_manifest_runtime_mismatch` (size/sha256 vs the binary)
    RuntimeMismatch,
    /// `native_manifest_version_mismatch` (vs the installed package version)
    VersionMismatch,
}

#[allow(dead_code)]
impl ManifestReject {
    /// Python reason string (`native_runtime_values.py:_INTEGRITY_FAILURE_REASONS`).
    pub fn reason(self) -> &'static str {
        match self {
            Self::Missing => "native_manifest_missing",
            Self::Invalid => "native_manifest_invalid",
            Self::RuntimeMismatch => "native_manifest_runtime_mismatch",
            Self::VersionMismatch => "native_manifest_version_mismatch",
        }
    }
}

/// `_manifest_for_bundled_identity` (`native_runtime.py:151-181`).
///
/// `package_version` is `_python_package_version()` resolved by the caller —
/// the Python wheel's version is not knowable in Rust; `None` skips the
/// version cross-check exactly as Python does. Returns the decoded manifest or
/// a stable reject reason. Fail-closed: any malformed/oversized/wrong-owner
/// manifest rejects before decode.
#[allow(dead_code)]
pub fn manifest_for_bundled_identity(
    identity: &RuntimeIdentity,
    package_version: Option<&str>,
) -> Result<NativeRuntimeManifestV1, ManifestReject> {
    let manifest_path = identity.path.with_file_name(NATIVE_MANIFEST_NAME);

    // Owner check must precede read: `read_bounded` enforces type/perm/link
    // but does not restrict uid. Mirror `st_uid in {0, euid}` (unix only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(&manifest_path).map_err(|e| map_err(&e))?;
        let mode = meta.mode();
        if meta.file_type().is_symlink() || !meta.file_type().is_file() {
            return Err(ManifestReject::Invalid);
        }
        if meta.size() == 0 || meta.size() > MAX_MANIFEST_BYTES as u64 {
            return Err(ManifestReject::Invalid);
        }
        if mode & 0o022 != 0 {
            return Err(ManifestReject::Invalid);
        }
        let uid = nix::unistd::geteuid().as_raw();
        let owner = meta.uid();
        if owner != 0 && owner != uid {
            return Err(ManifestReject::Invalid);
        }
    }
    // Read through the digest-bound bounded read so the bytes we decode are
    // the bytes whose identity was admitted (TOCTOU-safe).
    let read = match read_bounded(&manifest_path, MAX_MANIFEST_BYTES) {
        Ok(r) => r,
        Err(e) => {
            // SecureReadError has no NotFound variant: a missing leaf surfaces
            // as UnresolvedPath/ReadFailed/PermissionDenied. Re-probe to
            // distinguish "absent" from "present but unreadable".
            use SecureReadError as E;
            return Err(match e {
                E::UnresolvedPath | E::ReadFailed | E::PermissionDenied => {
                    if manifest_path.exists() {
                        ManifestReject::Invalid
                    } else {
                        ManifestReject::Missing
                    }
                }
                _ => ManifestReject::Invalid,
            });
        }
    };

    let payload: serde_json::Value =
        serde_json::from_slice(&read.bytes).map_err(|_| ManifestReject::Invalid)?;
    let manifest = decode_runtime_manifest(
        &payload,
        NATIVE_MANIFEST_SCHEMA,
        NATIVE_MANIFEST_PROTOCOL_VERSION,
    )
    .ok_or(ManifestReject::Invalid)?;

    if manifest.runtime_size != identity.size || manifest.runtime_sha256 != identity.sha256 {
        return Err(ManifestReject::RuntimeMismatch);
    }
    if let Some(expected) = package_version {
        if manifest.package_version != expected {
            return Err(ManifestReject::VersionMismatch);
        }
    }
    Ok(manifest)
}

#[cfg(unix)]
#[allow(dead_code)]
fn map_err(e: &std::io::Error) -> ManifestReject {
    if e.kind() == std::io::ErrorKind::NotFound {
        ManifestReject::Missing
    } else {
        ManifestReject::Invalid
    }
}

/// `_is_bundled_candidate` (`native_runtime.py:184-188`). `bundled` is the
/// resolved `_bundled_runtime_candidate()` path supplied by the caller —
/// resolving `__file__` is a Python-packaging detail that stays host-side.
#[allow(dead_code)]
pub fn is_bundled_candidate(candidate: &Path, bundled: &Path) -> bool {
    match (
        candidate
            .canonicalize()
            .or_else(|_| Ok::<PathBuf, std::io::Error>(expanduser(candidate))),
        bundled
            .canonicalize()
            .or_else(|_| Ok::<PathBuf, std::io::Error>(bundled.to_path_buf())),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[allow(dead_code)]
fn expanduser(p: &Path) -> PathBuf {
    p.to_path_buf()
}

/// `_restore_bundled_runtime_execute_bit` (`native_runtime.py:191-206`).
/// PyInstaller DATA extracts without the owner-exec bit; spawn needs it.
/// Only touches the bundled candidate; no-op on Windows or on a file that
/// already has exec, has write bits, is a symlink/non-regular, or is owned by
/// someone else. Fail-silent like Python.
#[cfg(unix)]
#[allow(dead_code)]
pub fn restore_bundled_runtime_execute_bit(path: &Path, bundled: &Path) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !is_bundled_candidate(path, bundled) {
        return;
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    let mode = meta.mode();
    if meta.file_type().is_symlink()
        || !meta.file_type().is_file()
        || mode & 0o022 != 0
        || mode & 0o100 != 0
    {
        return;
    }
    let uid = nix::unistd::geteuid().as_raw();
    if meta.uid() != 0 && meta.uid() != uid {
        return;
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode | 0o111));
}
#[cfg(not(unix))]
#[allow(dead_code)]
pub fn restore_bundled_runtime_execute_bit(_path: &Path, _bundled: &Path) {}

/// `_windows_native_dll_directories` (`native_runtime.py:209-241`).
/// Windows-only CRT search path for the dynamically-linked runtime. Order
/// preserved, deduped by casefold. `base_prefix` is `sys.base_prefix`; the
/// caller resolves it. Non-Windows returns empty.
#[cfg(target_os = "windows")]
pub fn windows_native_dll_directories(base_prefix: Option<&Path>, bundled: &Path) -> Vec<String> {
    let mut roots: Vec<String> = Vec::new();
    let system_root = std::env::var("SYSTEMROOT")
        .ok()
        .or_else(|| std::env::var("WINDIR").ok());
    if let Some(sr) = system_root {
        if !sr.is_empty() {
            roots.push(
                Path::new(&sr)
                    .join("System32")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    if let Some(bp) = base_prefix {
        let has_crt = ["vcruntime140.dll", "vcruntime140_1.dll"]
            .iter()
            .any(|n| bp.join(n).is_file());
        if has_crt {
            roots.push(bp.to_string_lossy().into_owned());
        }
    }
    let runtime_dir = bundled.parent().map(Path::to_path_buf);
    if let Some(rd) = runtime_dir {
        if rd.is_dir() {
            roots.push(rd.to_string_lossy().into_owned());
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut unique = Vec::new();
    for r in roots {
        let key = r.to_lowercase();
        if seen.insert(key) {
            unique.push(r);
        }
    }
    unique
}
#[cfg(not(target_os = "windows"))]
#[allow(dead_code)]
pub fn windows_native_dll_directories(_bp: Option<&Path>, _bundled: &Path) -> Vec<String> {
    Vec::new()
}

/// `_isolated_environment` (`native_runtime.py:244-264`).
/// The allowlist blocklist — only the named vars + `LC_*` survive, so the
/// child never inherits user PATH/LD_*/credential env. On Windows the only
/// PATH the child sees is the CRT search dirs (DLL isolation); POSIX children
/// get no PATH at all (spawn resolves the binary by absolute path).
#[allow(dead_code)]
pub fn isolated_environment(
    base_env: &BTreeMap<String, String>,
    base_prefix: Option<&Path>,
    bundled: &Path,
) -> BTreeMap<String, String> {
    const ALLOWED: &[&str] = &[
        "COMSPEC",
        "HOME",
        "LANG",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    ];
    let mut environment = BTreeMap::new();
    for (key, value) in base_env {
        let upper = key.to_uppercase();
        if ALLOWED.contains(&upper.as_str()) || upper.starts_with("LC_") {
            environment.insert(key.clone(), value.clone());
        }
    }
    #[cfg(target_os = "windows")]
    {
        let dll = windows_native_dll_directories(base_prefix, bundled);
        if !dll.is_empty() {
            environment.insert("PATH".to_string(), dll.join(";"));
        }
        let _ = base_prefix;
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (base_prefix, bundled);
    }
    environment
}

// ─── capabilities probe + status walker ─────────────────────────────────
// `_run_native_process` / `_capabilities_for_identity` / `native_runtime_
// status` (`native_runtime.py:267-439`). The probe caches only successful
// decodes; failures carry a short retry backoff so a cold-start miss cannot
// poison every later native check, and a caller-supplied deadline caps how
// long the probe may run so a one-shot request never overspends its budget.

#[allow(dead_code)]
const CAPABILITIES_PROBE_TIMEOUT: f64 = 5.0;
#[allow(dead_code)]
const CAPABILITIES_RETRY_BACKOFF: Duration = Duration::from_millis(250);
#[allow(dead_code)]
const CAPABILITIES_CACHE_MAX: usize = 16;
#[allow(dead_code)]
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
#[allow(dead_code)]
const RESIDENT_PROTOCOL_FEATURE: &str = "resident-protocol-v2";
#[allow(dead_code)]
const NATIVE_PROTOCOL_VERSION: i64 = 1;

/// `_run_native_process` (`native_runtime.py:267-284`): launch `path args`
/// through the isolated kernel with the runtime's own allowlist env, bounded
/// output and a deadline; `None` on any transport/limit/containment failure
/// or a non-zero exit.
#[allow(dead_code)]
pub fn run_native_process(
    path: &Path,
    args: &[&str],
    input_text: &str,
    timeout_seconds: f64,
    base_env: &BTreeMap<String, String>,
    base_prefix: Option<&Path>,
) -> Option<String> {
    let mut command = Vec::with_capacity(args.len() + 1);
    command.push(path.to_string_lossy().to_string());
    command.extend(args.iter().map(|s| s.to_string()));
    let cwd = path.parent().unwrap_or_else(|| Path::new("."));
    let environment = isolated_environment(base_env, base_prefix, path);
    let result = run_isolated_hook_process(
        &command,
        input_text,
        cwd,
        &environment,
        Some(timeout_seconds),
        Some(MAX_RESPONSE_BYTES),
        None,
        None,
    );
    if result.returncode != Some(0)
        || result.timed_out
        || result.output_limit_exceeded
        || result.containment_failed
    {
        return None;
    }
    Some(result.stdout)
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
struct ProbeKey {
    path: String,
    size: i64,
    mtime_ns: u64,
    sha256: String,
}

/// `_capabilities_probe_lock`/`_capabilities_cache`/`_capabilities_retry_after`
/// — one global probe per binary identity. Bounded at `CAPABILITIES_CACHE_MAX`
/// entries; the oldest entry is evicted on insert (Python pops `next(iter(..))`).
#[allow(dead_code)]
pub struct CapabilitiesProbe {
    cache: Mutex<BTreeMap<ProbeKey, NativeRuntimeCapabilitiesV1>>,
    retry_after: Mutex<BTreeMap<ProbeKey, Instant>>,
}

#[allow(dead_code)]
impl CapabilitiesProbe {
    fn global() -> &'static Self {
        static PROBE: OnceLock<CapabilitiesProbe> = OnceLock::new();
        PROBE.get_or_init(|| CapabilitiesProbe {
            cache: Mutex::new(BTreeMap::new()),
            retry_after: Mutex::new(BTreeMap::new()),
        })
    }

    fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `_clear_capabilities_probe_state` (`native_runtime.py:299-302`) —
    /// test hook parity; called by `native_runtime_status` only in tests.
    pub fn clear() {
        let p = Self::global();
        Self::lock(&p.cache).clear();
        Self::lock(&p.retry_after).clear();
    }
}

/// `_capabilities_for_identity` (`native_runtime.py:307-353`): probe once
/// per `(path,size,mtime_ns,sha256)`; cache successes, apply a short retry
/// backoff to failures, and cap the spawn at the caller's remaining budget.
/// Returns `Err(reason)` only for protocol-level mismatches (bad protocol
/// version, missing resident feature) — those are permanent compatibility
/// rejects the status walker surfaces verbatim. Transport/decode misses and
/// cached-miss backoffs are `Ok(None)`.
#[allow(dead_code)]
pub fn capabilities_for_identity(
    identity: &RuntimeIdentity,
    deadline: Option<Instant>,
    base_env: &BTreeMap<String, String>,
    base_prefix: Option<&Path>,
) -> Result<Option<NativeRuntimeCapabilitiesV1>, &'static str> {
    let key = ProbeKey {
        path: identity.path.to_string_lossy().to_string(),
        size: identity.size,
        mtime_ns: identity.mtime_ns,
        sha256: identity.sha256.clone(),
    };
    let probe = CapabilitiesProbe::global();
    let now = Instant::now();
    {
        let cache = CapabilitiesProbe::lock(&probe.cache);
        let retry = CapabilitiesProbe::lock(&probe.retry_after);
        if let Some(hit) = cache.get(&key) {
            return Ok(Some(hit.clone()));
        }
        if let Some(&until) = retry.get(&key) {
            if now < until {
                return Ok(None);
            }
        }
    }
    let mut timeout = CAPABILITIES_PROBE_TIMEOUT;
    if let Some(dl) = deadline {
        let remaining = dl.saturating_duration_since(now).as_secs_f64();
        if remaining <= 0.0 {
            // The caller's budget is already spent; starting a fresh probe
            // would overshoot the request deadline.
            return Ok(None);
        }
        timeout = timeout.min(remaining);
    }
    let output = run_native_process(
        &identity.path,
        &["capabilities", "--json"],
        "",
        timeout,
        base_env,
        base_prefix,
    );
    let capabilities = output
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|payload| decode_native_capabilities(&payload));
    if capabilities.is_none() {
        CapabilitiesProbe::lock(&probe.retry_after).insert(key, now + CAPABILITIES_RETRY_BACKOFF);
        return Ok(None);
    }
    let capabilities = capabilities.unwrap();
    if capabilities.protocol_version != NATIVE_PROTOCOL_VERSION {
        return Err("native_capabilities_protocol_version_mismatch");
    }
    if !capabilities
        .features
        .iter()
        .any(|f| f == RESIDENT_PROTOCOL_FEATURE)
    {
        return Err("native_capabilities_missing_resident_protocol");
    }
    {
        let mut cache = CapabilitiesProbe::lock(&probe.cache);
        if cache.len() >= CAPABILITIES_CACHE_MAX {
            let oldest = cache.keys().next().cloned();
            if let Some(k) = oldest {
                cache.remove(&k);
            }
        }
        cache.insert(key.clone(), capabilities.clone());
        CapabilitiesProbe::lock(&probe.retry_after).remove(&key);
    }
    Ok(Some(capabilities))
}

/// `native_runtime_status` (`native_runtime.py:355-439`): walk the bundled +
/// env-runtime candidates, admit the first manifest-clean identity, probe
/// capabilities, and apply mode-aware compatibility. `candidates` is the
/// resolved list (`_runtime_candidates` order) — path resolution is
/// host-side. `package_version` is `_python_package_version()`.
#[allow(dead_code)]
pub fn native_runtime_status(
    mode: NativeMode,
    candidates: &[RuntimeIdentity],
    package_version: Option<&str>,
    env_binary: Option<&RuntimeIdentity>,
    deadline: Option<Instant>,
    base_env: &BTreeMap<String, String>,
    base_prefix: Option<&Path>,
) -> NativeRuntimeStatusV1 {
    if mode == NativeMode::Off {
        return NativeRuntimeStatusV1 {
            mode,
            available: false,
            compatible: false,
            reason: "native_disabled".to_string(),
            identity: None,
            capabilities: None,
            manifest: None,
        };
    }
    for identity in candidates {
        let bundled = env_binary.map(|e| e != identity).unwrap_or(true);
        let manifest = if bundled {
            match manifest_for_bundled_identity(identity, package_version) {
                Ok(m) => Some(m),
                Err(_) => continue,
            }
        } else {
            None
        };
        let capabilities =
            match capabilities_for_identity(identity, deadline, base_env, base_prefix) {
                Ok(c) => c,
                // Probe gave a permanent reject (protocol mismatch / missing
                // resident feature): still walk to the next candidate — this
                // identity is not compatible.
                Err(_) => continue,
            };
        let Some(capabilities) = capabilities else {
            continue;
        };
        // Compatibility is transport-level (protocol + resident feature).
        // Python then re-checks capabilities against the bundled manifest
        // (protocol / package_version / rule_digest / source_sha — `native_runtime.py:402-414`);
        // any divergence marks the runtime incompatible before mode-aware
        // `compatible` is computed.
        let manifest_reason: Option<&'static str> = manifest.as_ref().and_then(|m| {
            if capabilities.protocol_version != m.protocol_version {
                Some("native_manifest_protocol_mismatch")
            } else if capabilities.runtime_version != m.package_version {
                Some("native_manifest_version_mismatch")
            } else if capabilities.rule_digest != m.rule_digest {
                Some("native_manifest_rule_mismatch")
            } else if capabilities.build_sha != m.source_sha {
                Some("native_manifest_build_mismatch")
            } else {
                None
            }
        });
        // Package-version equality is advisory: shadow/force downgrade it to
        // a non-blocking `native_version_mismatch`; auto still enforces.
        let version_compatible = package_version
            .map(|v| v == capabilities.runtime_version)
            .unwrap_or(false);
        let compatible = manifest_reason.is_none()
            && (version_compatible || matches!(mode, NativeMode::Shadow | NativeMode::Force));
        return NativeRuntimeStatusV1 {
            mode,
            available: true,
            compatible,
            reason: if let Some(reason) = manifest_reason {
                reason.to_string()
            } else if compatible {
                "native_ready".to_string()
            } else {
                "native_version_mismatch".to_string()
            },
            identity: Some(RuntimeIdentityV1 {
                path: identity.path.to_string_lossy().to_string(),
                size: identity.size,
                mtime_ns: identity.mtime_ns,
                sha256: identity.sha256.clone(),
            }),
            capabilities: Some(capabilities),
            manifest,
        };
    }
    NativeRuntimeStatusV1 {
        mode,
        available: false,
        compatible: false,
        reason: "native_unavailable".to_string(),
        identity: None,
        capabilities: None,
        manifest: None,
    }
}

// `isolated_hook_environment` is re-exported for callers that want the hook
// launch's (broader) allowlist; `isolated_environment` is the runtime's
// narrower manifest-admission env. Both are consumed by the spawn kernel.
#[allow(unused_imports)]
use isolated_hook_environment as _isolated_hook_environment;

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    fn tmp_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("nra-{}-{}-{}", std::process::id(), tag, n));
        fs::create_dir_all(&p).expect("create tmp dir");
        // `/var` is a symlink on macOS; read_bounded walks every component, so
        // hand the caller the canonical (symlink-free) path.
        fs::canonicalize(&p).expect("canonicalize tmp dir")
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, bytes).expect("write fixture");
        p
    }

    /// `read_bounded` rejects any leaf write bit (`0o222`); the real bundled
    /// manifest is installed read-only. Mirror that in fixtures.
    fn write_readonly(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = write(dir, name, bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perm = fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o444);
            fs::set_permissions(&p, perm).unwrap();
        }
        p
    }

    /// Build the `RuntimeIdentity` for an on-disk binary the same way the
    /// bundled-candidate probe does: path + size + mtime_ns + sha256.
    fn identity_of(bin: &Path) -> RuntimeIdentity {
        let meta = fs::metadata(bin).expect("bin metadata");
        let mtime_ns = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        RuntimeIdentity {
            path: bin.to_path_buf(),
            size: meta.len() as i64,
            mtime_ns,
            sha256: format!("{:x}", sha2::Sha256::digest(fs::read(bin).unwrap())),
        }
    }

    #[cfg(unix)]
    fn valid_manifest(size: i64, sha: &str) -> serde_json::Value {
        serde_json::json!({
            "schema": NATIVE_MANIFEST_SCHEMA,
            "protocol_version": NATIVE_MANIFEST_PROTOCOL_VERSION,
            "package_version": "3.16.5",
            "target": "aarch64-apple-darwin",
            "platform_tag": "macosx_14_0_arm64",
            "source_sha": "a".repeat(40),
            "rule_digest": "b".repeat(64),
            "runtime_size": size,
            "runtime_sha256": sha,
        })
    }

    #[test]
    fn missing_manifest_file_is_missing() {
        let dir = tmp_dir("missing_manifest");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::Missing);
    }

    #[test]
    fn malformed_manifest_json_is_invalid() {
        let dir = tmp_dir("malformed_manifest");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        write_readonly(&dir, NATIVE_MANIFEST_NAME, b"{not-json");
        let id = identity_of(&bin);
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::Invalid);
    }

    #[test]
    fn wrong_manifest_schema_is_invalid() {
        let dir = tmp_dir("wrong_schema");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let m = serde_json::json!({"schema":"other","protocol_version":1,"runtime_size":6,"runtime_sha256":"x"});
        write_readonly(&dir, NATIVE_MANIFEST_NAME, m.to_string().as_bytes());
        let id = identity_of(&bin);
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::Invalid);
    }

    // Windows read_bounded fail-closes before decode (no descriptor path
    // walk). These checks run only where a bounded read can succeed.
    #[cfg(unix)]
    #[test]
    fn size_mismatch_is_runtime_mismatch() {
        let dir = tmp_dir("size_mismatch");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        // manifest claims a different size than the on-disk identity.
        let m = valid_manifest(id.size + 1, &id.sha256);
        write_readonly(&dir, NATIVE_MANIFEST_NAME, m.to_string().as_bytes());
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::RuntimeMismatch);
    }

    #[cfg(unix)]
    #[test]
    fn sha_mismatch_is_runtime_mismatch() {
        let dir = tmp_dir("sha_mismatch");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        let m = valid_manifest(id.size, &"00".repeat(32));
        write_readonly(&dir, NATIVE_MANIFEST_NAME, m.to_string().as_bytes());
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::RuntimeMismatch);
    }

    #[cfg(unix)]
    #[test]
    fn version_mismatch_flagged() {
        let dir = tmp_dir("version_mismatch");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        // Real sha/size of the file so only the package_version check fails.
        let mut m = valid_manifest(id.size, &id.sha256);
        m["package_version"] = serde_json::json!("9.9.9");
        write_readonly(&dir, NATIVE_MANIFEST_NAME, m.to_string().as_bytes());
        let err = manifest_for_bundled_identity(&id, Some("3.16.5")).unwrap_err();
        assert_eq!(err, ManifestReject::VersionMismatch);
    }

    #[cfg(unix)]
    #[test]
    fn valid_manifest_accepted() {
        let dir = tmp_dir("valid_manifest");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        let m = valid_manifest(id.size, &id.sha256);
        write_readonly(&dir, NATIVE_MANIFEST_NAME, m.to_string().as_bytes());
        let got = manifest_for_bundled_identity(&id, Some("3.16.5")).expect("accepted");
        assert_eq!(got.runtime_size, id.size);
        assert_eq!(got.runtime_sha256, id.sha256);
        assert_eq!(got.package_version, "3.16.5");
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_manifest_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp_dir("writable_manifest");
        let bin = write(&dir, "hol-guard-runtime", b"binary");
        let id = identity_of(&bin);
        let mp = write_readonly(
            &dir,
            NATIVE_MANIFEST_NAME,
            valid_manifest(id.size, &id.sha256).to_string().as_bytes(),
        );
        let mut perm = fs::metadata(&mp).unwrap().permissions();
        perm.set_mode(0o666);
        fs::set_permissions(&mp, perm).unwrap();
        let err = manifest_for_bundled_identity(&id, None).unwrap_err();
        assert_eq!(err, ManifestReject::Invalid);
    }

    #[test]
    fn isolated_env_drops_injected_keys() {
        let mut base = BTreeMap::new();
        base.insert("PATH".to_string(), "/evil".to_string());
        base.insert("LD_PRELOAD".to_string(), "/evil.so".to_string());
        base.insert("AWS_SECRET".to_string(), "x".to_string());
        base.insert("HOME".to_string(), "/u".to_string());
        base.insert("LC_ALL".to_string(), "C".to_string());
        base.insert("TMPDIR".to_string(), "/tmp".to_string());
        let env = isolated_environment(&base, None, Path::new("/bundled"));
        assert!(!env.contains_key("PATH") || cfg!(windows));
        assert!(!env.contains_key("LD_PRELOAD"));
        assert!(!env.contains_key("AWS_SECRET"));
        assert_eq!(env.get("HOME").map(String::as_str), Some("/u"));
        assert_eq!(env.get("LC_ALL").map(String::as_str), Some("C"));
        assert_eq!(env.get("TMPDIR").map(String::as_str), Some("/tmp"));
    }

    #[test]
    fn reject_reason_strings_stable() {
        assert_eq!(ManifestReject::Missing.reason(), "native_manifest_missing");
        assert_eq!(ManifestReject::Invalid.reason(), "native_manifest_invalid");
        assert_eq!(
            ManifestReject::RuntimeMismatch.reason(),
            "native_manifest_runtime_mismatch"
        );
        assert_eq!(
            ManifestReject::VersionMismatch.reason(),
            "native_manifest_version_mismatch"
        );
    }

    // ─── capabilities probe + status walker ─────────────────────────────

    /// Write an executable shell script that prints the capabilities JSON —
    /// the probe only requires `run_native_process` to return `Some(text)`
    /// that decodes through `decode_native_capabilities`.
    #[cfg(unix)]
    fn write_fake_runtime(dir: &Path, capabilities_json: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join("hol-guard-runtime");
        let script = format!("#!/bin/sh\nprintf '%s' '{capabilities_json}'\n");
        fs::write(&bin, script).unwrap();
        let mut perm = fs::metadata(&bin).unwrap().permissions();
        perm.set_mode(0o555);
        fs::set_permissions(&bin, perm).unwrap();
        bin
    }

    fn empty_env() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[cfg(unix)]
    #[test]
    fn capabilities_probe_caches_success() {
        CapabilitiesProbe::clear();
        let dir = tmp_dir("cap");
        let caps = serde_json::json!({
            "protocol_version": 1,
            "runtime_version": "3.16.5",
            "rule_digest": "d".repeat(64),
            "build_sha": "e".repeat(40),
            "target": "aarch64-apple-darwin",
            "features": ["resident-protocol-v2"],
        });
        let bin = write_fake_runtime(&dir, &caps.to_string());
        let id = identity_of(&bin);
        let first = capabilities_for_identity(&id, None, &empty_env(), None).expect("probe");
        let caps = first.expect("capabilities");
        assert_eq!(caps.protocol_version, 1);
        assert!(caps.features.iter().any(|f| f == "resident-protocol-v2"));
        // Second call hits the cache: no spawn, same object.
        let second = capabilities_for_identity(&id, None, &empty_env(), None).expect("probe2");
        assert_eq!(second, Some(caps));
    }

    #[cfg(unix)]
    #[test]
    fn capabilities_probe_rejects_bad_protocol() {
        CapabilitiesProbe::clear();
        let dir = tmp_dir("capbad");
        let caps = serde_json::json!({
            "protocol_version": 99,
            "runtime_version": "3.16.5",
            "rule_digest": "d".repeat(64),
            "build_sha": "e".repeat(40),
            "target": "aarch64-apple-darwin",
            "features": ["resident-protocol-v2"],
        });
        let bin = write_fake_runtime(&dir, &caps.to_string());
        let id = identity_of(&bin);
        let err = capabilities_for_identity(&id, None, &empty_env(), None).unwrap_err();
        assert_eq!(err, "native_capabilities_protocol_version_mismatch");
    }

    #[cfg(unix)]
    #[test]
    fn capabilities_probe_rejects_missing_resident_feature() {
        CapabilitiesProbe::clear();
        let dir = tmp_dir("capfeat");
        let caps = serde_json::json!({
            "protocol_version": 1,
            "runtime_version": "3.16.5",
            "rule_digest": "d".repeat(64),
            "build_sha": "e".repeat(40),
            "target": "aarch64-apple-darwin",
            "features": ["some-other-feature"],
        });
        let bin = write_fake_runtime(&dir, &caps.to_string());
        let id = identity_of(&bin);
        let err = capabilities_for_identity(&id, None, &empty_env(), None).unwrap_err();
        assert_eq!(err, "native_capabilities_missing_resident_protocol");
    }

    #[cfg(unix)]
    #[test]
    fn capabilities_probe_transport_failure_backoff() {
        CapabilitiesProbe::clear();
        let dir = tmp_dir("capdead");
        // Script that never produces JSON — exits non-zero.
        use std::os::unix::fs::PermissionsExt;
        let bin = dir.join("hol-guard-runtime");
        fs::write(&bin, "#!/bin/sh\nexit 7\n").unwrap();
        let mut perm = fs::metadata(&bin).unwrap().permissions();
        perm.set_mode(0o555);
        fs::set_permissions(&bin, perm).unwrap();
        let id = identity_of(&bin);
        let first = capabilities_for_identity(&id, None, &empty_env(), None).expect("probe");
        assert!(first.is_none());
        // Immediate second call is inside the retry backoff — returns None
        // without respawning.
        let second = capabilities_for_identity(&id, None, &empty_env(), None).expect("probe2");
        assert!(second.is_none());
    }

    #[test]
    fn status_native_disabled_when_off() {
        let status = native_runtime_status(
            NativeMode::Off,
            &[],
            Some("3.16.5"),
            None,
            None,
            &empty_env(),
            None,
        );
        assert_eq!(status.mode, NativeMode::Off);
        assert!(!status.available);
        assert!(!status.compatible);
        assert_eq!(status.reason, "native_disabled");
    }

    #[test]
    fn status_unavailable_with_no_candidates() {
        let status = native_runtime_status(
            NativeMode::Auto,
            &[],
            Some("3.16.5"),
            None,
            None,
            &empty_env(),
            None,
        );
        assert!(!status.available);
        assert_eq!(status.reason, "native_unavailable");
    }

    #[cfg(unix)]
    #[test]
    fn status_ready_with_valid_manifest_and_capabilities() {
        CapabilitiesProbe::clear();
        let dir = tmp_dir("status");
        let caps = serde_json::json!({
            "protocol_version": 1,
            "runtime_version": "3.16.5",
            "rule_digest": "d".repeat(64),
            "build_sha": "e".repeat(40),
            "target": "aarch64-apple-darwin",
            "features": ["resident-protocol-v2"],
        });
        let bin = write_fake_runtime(&dir, &caps.to_string());
        let id = identity_of(&bin);
        // Write the admission manifest that matches the binary's identity.
        let manifest = serde_json::json!({
            "schema": NATIVE_MANIFEST_SCHEMA,
            "protocol_version": NATIVE_MANIFEST_PROTOCOL_VERSION,
            "package_version": "3.16.5",
            "target": "aarch64-apple-darwin",
            "platform_tag": "macosx_14_0_arm64",
            "source_sha": "e".repeat(40),
            "rule_digest": "d".repeat(64),
            "runtime_sha256": id.sha256,
            "runtime_size": id.size,
        });
        write_readonly(&dir, NATIVE_MANIFEST_NAME, manifest.to_string().as_bytes());
        // No env_binary → this identity is bundled → manifest admission runs.
        let status = native_runtime_status(
            NativeMode::Auto,
            &[id.clone()],
            Some("3.16.5"),
            None,
            None,
            &empty_env(),
            None,
        );
        assert!(status.available, "expected native_ready, got {status:?}");
        assert!(status.compatible);
        assert_eq!(status.reason, "native_ready");
        assert_eq!(
            status.identity.as_ref().map(|i| i.sha256.as_str()),
            Some(id.sha256.as_str())
        );
        assert!(status.manifest.is_some());
    }

    /// Greptile P2 parity: capabilities disagreeing with the bundled manifest
    /// on protocol / package_version / rule_digest / build_sha must mark the
    /// runtime incompatible with the matching `native_manifest_*_mismatch`
    /// reason (`native_runtime.py:402-414`).
    #[cfg(unix)]
    #[test]
    fn status_rejects_manifest_field_mismatch() {
        CapabilitiesProbe::clear();
        for (idx, (rule_digest, build_sha, want)) in [
            (
                "x".repeat(64),
                "e".repeat(40),
                "native_manifest_rule_mismatch",
            ),
            (
                "d".repeat(64),
                "x".repeat(40),
                "native_manifest_build_mismatch",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let dir = tmp_dir(&format!("status-mismatch-{idx}"));
            let caps = serde_json::json!({
                "protocol_version": 1,
                "runtime_version": "3.16.5",
                "rule_digest": rule_digest,
                "build_sha": build_sha,
                "target": "aarch64-apple-darwin",
                "features": ["resident-protocol-v2"],
            });
            let bin = write_fake_runtime(&dir, &caps.to_string());
            let id = identity_of(&bin);
            let manifest = serde_json::json!({
                "schema": NATIVE_MANIFEST_SCHEMA,
                "protocol_version": NATIVE_MANIFEST_PROTOCOL_VERSION,
                "package_version": "3.16.5",
                "target": "aarch64-apple-darwin",
                "platform_tag": "macosx_14_0_arm64",
                "source_sha": "e".repeat(40),
                "rule_digest": "d".repeat(64),
                "runtime_sha256": id.sha256,
                "runtime_size": id.size,
            });
            write_readonly(&dir, NATIVE_MANIFEST_NAME, manifest.to_string().as_bytes());
            let status = native_runtime_status(
                NativeMode::Auto,
                &[id],
                Some("3.16.5"),
                None,
                None,
                &empty_env(),
                None,
            );
            assert!(status.available);
            assert!(!status.compatible, "expected incompatible for {want}");
            assert_eq!(status.reason, want);
        }
    }

    #[cfg(unix)]
    #[test]
    fn status_env_candidate_skips_manifest() {
        CapabilitiesProbe::clear();
        let dir = tmp_dir("statusenv");
        let caps = serde_json::json!({
            "protocol_version": 1,
            "runtime_version": "3.16.5",
            "rule_digest": "d".repeat(64),
            "build_sha": "e".repeat(40),
            "target": "aarch64-apple-darwin",
            "features": ["resident-protocol-v2"],
        });
        let bin = dir.join("hol-guard-runtime-env");
        {
            use std::os::unix::fs::PermissionsExt;
            let script = format!("#!/bin/sh\nprintf '%s' '{caps}'\n");
            fs::write(&bin, script).unwrap();
            let mut perm = fs::metadata(&bin).unwrap().permissions();
            perm.set_mode(0o555);
            fs::set_permissions(&bin, perm).unwrap();
        }
        let id = identity_of(&bin);
        let status = native_runtime_status(
            NativeMode::Auto,
            &[id.clone()],
            Some("3.16.5"),
            Some(&id), // marks this identity as the env-override candidate
            None,
            &empty_env(),
            None,
        );
        assert!(status.available);
        assert!(status.manifest.is_none());
    }
}
