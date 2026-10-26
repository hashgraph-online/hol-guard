//! Bounded, privacy-safe resilience state for the native Guard runtime.
//!
//! Port of `native_runtime_resilience.py`. Owns only process-local
//! availability controls: it does not persist commands, prompts, paths,
//! payloads, tokens, proofs, or exception text. Python remains the
//! authoritative policy and fallback control plane.
//!
//! State is keyed by a privacy-safe digest (`_privacy_safe_key`): sha256 of
//! `identity_sha256[:128] + b"\0" + os.fsencode(resolved guard_home)` — the
//! raw local path is never retained. Per-identity mutable health lives in an
//! insertion-ordered map bounded at `_MAX_HEALTH_ENTRIES`; a global
//! bounded semaphore caps concurrent one-shot recovery slots.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use sha2::{Digest, Sha256};

#[allow(dead_code)]
const MAX_HEALTH_ENTRIES: usize = 128;
#[allow(dead_code)]
const CIRCUIT_FAILURE_THRESHOLD: i64 = 3;
#[allow(dead_code)]
const CIRCUIT_COOLDOWN_SECONDS: f64 = 15.0;
#[allow(dead_code)]
const ONESHOT_RETRY_COOLDOWN_SECONDS: f64 = 0.05;
#[allow(dead_code)]
const GLOBAL_ONESHOT_LIMIT: i64 = 2;
#[allow(dead_code)]
const REASON_MAX_LENGTH: usize = 96;

/// Aggregate-only native runtime health suitable for local diagnostics.
/// Mirrors `NativeRuntimeHealthSnapshot` (`native_runtime_resilience.py:29`).
#[derive(Debug, Clone, PartialEq)]
pub struct NativeRuntimeHealthSnapshot {
    pub state: String,
    pub reason: String,
    pub circuit_open: bool,
    pub consecutive_failures: i64,
    pub resident_failures: i64,
    pub oneshot_failures: i64,
    pub overloads: i64,
    pub starts: i64,
    pub restarts: i64,
    pub cooldown_remaining_seconds: f64,
}

/// `_MutableNativeRuntimeHealth` (`native_runtime_resilience.py:45`).
#[derive(Debug)]
#[allow(dead_code)]
struct MutableNativeRuntimeHealth {
    state: String,
    reason: String,
    consecutive_failures: i64,
    resident_failures: i64,
    oneshot_failures: i64,
    overloads: i64,
    starts: i64,
    restarts: i64,
    circuit_until: f64,
    permanently_quarantined: bool,
    oneshot_in_flight: bool,
    next_oneshot_allowed_at: f64,
}

impl Default for MutableNativeRuntimeHealth {
    fn default() -> Self {
        Self {
            state: "unknown".to_string(),
            reason: "native_state_uninitialized".to_string(),
            consecutive_failures: 0,
            resident_failures: 0,
            oneshot_failures: 0,
            overloads: 0,
            starts: 0,
            restarts: 0,
            circuit_until: 0.0,
            permanently_quarantined: false,
            oneshot_in_flight: false,
            next_oneshot_allowed_at: 0.0,
        }
    }
}

/// Insertion-ordered health map preserving Python `OrderedDict` semantics:
/// first-inserted is the eviction candidate; `move_to_end` on hit.
#[allow(dead_code)]
struct OrderedStates {
    order: Vec<String>,
    map: BTreeMap<String, MutableNativeRuntimeHealth>,
}

#[allow(dead_code)]
impl OrderedStates {
    fn new() -> Self {
        Self {
            order: Vec::new(),
            map: BTreeMap::new(),
        }
    }
    fn get(&mut self, key: &str) -> Option<&mut MutableNativeRuntimeHealth> {
        self.map.get_mut(key)
    }
    fn insert(&mut self, key: String, value: MutableNativeRuntimeHealth) {
        if !self.map.contains_key(&key) {
            self.order.push(key.clone());
        }
        self.map.insert(key, value);
    }
    fn move_to_end(&mut self, key: &str) {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            let k = self.order.remove(pos);
            self.order.push(k);
        }
    }
    fn remove(&mut self, key: &str) -> Option<MutableNativeRuntimeHealth> {
        if let Some(pos) = self.order.iter().position(|k| k == key) {
            self.order.remove(pos);
        }
        self.map.remove(key)
    }
    fn len(&self) -> usize {
        self.map.len()
    }
    /// `_evict_if_needed`: evict oldest non-`oneshot_in_flight` entries until
    /// within bound; never evict an in-flight lease.
    fn evict_if_needed(&mut self) {
        while self.len() > MAX_HEALTH_ENTRIES {
            let candidate = self
                .order
                .iter()
                .find(|k| {
                    !self
                        .map
                        .get(*k)
                        .map(|s| s.oneshot_in_flight)
                        .unwrap_or(false)
                })
                .cloned();
            match candidate {
                Some(k) => {
                    self.remove(&k);
                }
                None => break,
            }
        }
    }
}

fn states() -> &'static Mutex<OrderedStates> {
    static STATES: OnceLock<Mutex<OrderedStates>> = OnceLock::new();
    STATES.get_or_init(|| Mutex::new(OrderedStates::new()))
}

fn states_lock() -> MutexGuard<'static, OrderedStates> {
    states().lock().unwrap_or_else(|e| e.into_inner())
}

/// Global bounded semaphore for one-shot recovery slots. Count of slots
/// currently held; acquisition succeeds while `held < GLOBAL_ONESHOT_LIMIT`.
fn global_oneshot_held() -> &'static AtomicI64 {
    static HELD: OnceLock<AtomicI64> = OnceLock::new();
    HELD.get_or_init(|| AtomicI64::new(0))
}

/// `_privacy_safe_key` (`native_runtime_resilience.py:66`): sha256 of
/// `identity_sha256[:128] + 0x00 + os.fsencode(resolved guard_home)`.
#[allow(dead_code)]
fn privacy_safe_key(identity_sha256: &str, guard_home: &Path) -> String {
    let mut digest = Sha256::new();
    let id_bytes: Vec<u8> = identity_sha256.bytes().filter(|b| b.is_ascii()).collect();
    digest.update(&id_bytes[..id_bytes.len().min(128)]);
    digest.update([0u8]);
    digest.update(normalize_guard_home(guard_home));
    hex::encode(digest.finalize())
}

/// `os.fsencode(guard_home.expanduser().resolve(strict=False))` with fallback
/// to `os.fsencode(str(guard_home))` on resolution failure.
#[allow(dead_code)]
fn normalize_guard_home(guard_home: &Path) -> Vec<u8> {
    let expanded = expanduser(guard_home);
    match std::fs::canonicalize(&expanded) {
        Ok(p) => path_bytes(&p),
        Err(_) => path_bytes(guard_home),
    }
}

#[allow(dead_code)]
fn path_bytes(p: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        p.as_os_str().as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        p.as_os_str().to_string_lossy().as_bytes().to_vec()
    }
}

#[allow(dead_code)]
fn expanduser(p: &Path) -> PathBuf {
    let s = p.as_os_str().to_string_lossy();
    if let Some(rest) = s.strip_prefix('~') {
        if rest.is_empty() || rest.starts_with('/') {
            if let Some(home) = std::env::var_os("HOME") {
                let mut b = PathBuf::from(home);
                if rest.len() > 1 {
                    b.push(&rest[1..]);
                }
                return b;
            }
        }
    }
    p.to_path_buf()
}

/// `_public_reason` (`native_runtime_resilience.py:80`): lowercase, strip,
/// truncate to `_REASON_MAX_LENGTH`, accept only alnum + `_-.` else fallback.
#[allow(dead_code)]
fn public_reason(reason: &str, fallback: &str) -> String {
    let candidate: String = reason
        .trim()
        .to_lowercase()
        .chars()
        .take(REASON_MAX_LENGTH)
        .collect();
    if !candidate.is_empty()
        && candidate
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return candidate;
    }
    fallback.to_string()
}

#[allow(dead_code)]
fn monotonic() -> f64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs_f64()
}

#[allow(dead_code)]
fn state_for<'a>(
    states: &'a mut OrderedStates,
    identity_sha256: &str,
    guard_home: &Path,
) -> (String, &'a mut MutableNativeRuntimeHealth) {
    let key = privacy_safe_key(identity_sha256, guard_home);
    if !states.map.contains_key(&key) {
        states.insert(key.clone(), MutableNativeRuntimeHealth::default());
        states.evict_if_needed();
    } else {
        states.move_to_end(&key);
    }
    let entry = states.map.get_mut(&key).expect("state inserted");
    (key, entry)
}

/// `_refresh_circuit` (`native_runtime_resilience.py:112`): half-open after
/// cooldown unless permanently quarantined.
#[allow(dead_code)]
fn refresh_circuit(state: &mut MutableNativeRuntimeHealth, now: f64) {
    if state.permanently_quarantined || state.circuit_until <= 0.0 || now < state.circuit_until {
        return;
    }
    state.circuit_until = 0.0;
    state.consecutive_failures = (CIRCUIT_FAILURE_THRESHOLD - 1).max(0);
    state.state = "recovering".to_string();
    state.reason = "native_circuit_half_open".to_string();
}

/// `_record_failure` (`native_runtime_resilience.py:121`).
#[allow(dead_code)]
fn record_failure(
    state: &mut MutableNativeRuntimeHealth,
    reason: &str,
    fallback_reason: &str,
    now: f64,
) {
    if state.permanently_quarantined {
        return;
    }
    state.consecutive_failures += 1;
    state.reason = public_reason(reason, fallback_reason);
    if state.consecutive_failures >= CIRCUIT_FAILURE_THRESHOLD {
        state.state = "circuit_open".to_string();
        state.reason = "native_circuit_open".to_string();
        state.circuit_until = now + CIRCUIT_COOLDOWN_SECONDS;
    } else {
        state.state = "degraded".to_string();
    }
}

#[allow(dead_code)]
pub fn native_record_starting(identity_sha256: &str, guard_home: &Path) {
    let mut states = states_lock();
    let (_, state) = state_for(&mut states, identity_sha256, guard_home);
    if state.permanently_quarantined {
        return;
    }
    state.starts += 1;
    state.state = "starting".to_string();
    state.reason = "native_starting".to_string();
}

#[allow(dead_code)]
pub fn native_record_restart(identity_sha256: &str, guard_home: &Path) {
    let mut states = states_lock();
    let (_, state) = state_for(&mut states, identity_sha256, guard_home);
    if state.permanently_quarantined {
        return;
    }
    state.restarts += 1;
    state.state = "recovering".to_string();
    state.reason = "native_recovering".to_string();
}

#[allow(dead_code)]
pub fn native_record_resident_success(identity_sha256: &str, guard_home: &Path) {
    let mut states = states_lock();
    let (_, state) = state_for(&mut states, identity_sha256, guard_home);
    if state.permanently_quarantined {
        return;
    }
    state.state = "healthy".to_string();
    state.reason = "native_ready".to_string();
    state.consecutive_failures = 0;
    state.circuit_until = 0.0;
}

#[allow(dead_code)]
pub fn native_record_resident_failure(identity_sha256: &str, guard_home: &Path, reason: &str) {
    let mut states = states_lock();
    let (_, state) = state_for(&mut states, identity_sha256, guard_home);
    state.resident_failures += 1;
    record_failure(state, reason, "native_resident_failed", monotonic());
}

#[allow(dead_code)]
pub fn native_record_oneshot_success(identity_sha256: &str, guard_home: &Path) {
    let mut states = states_lock();
    let (_, state) = state_for(&mut states, identity_sha256, guard_home);
    if state.permanently_quarantined {
        return;
    }
    state.state = "degraded".to_string();
    state.reason = "native_oneshot_fallback".to_string();
    state.consecutive_failures = 0;
    state.circuit_until = 0.0;
}

#[allow(dead_code)]
pub fn native_record_oneshot_failure(identity_sha256: &str, guard_home: &Path, reason: &str) {
    let mut states = states_lock();
    let (_, state) = state_for(&mut states, identity_sha256, guard_home);
    state.oneshot_failures += 1;
    record_failure(state, reason, "native_oneshot_failed", monotonic());
}

#[allow(dead_code)]
pub fn native_record_overload(identity_sha256: &str, guard_home: &Path) {
    let mut states = states_lock();
    let (_, state) = state_for(&mut states, identity_sha256, guard_home);
    if state.permanently_quarantined {
        return;
    }
    state.overloads += 1;
    state.state = "overloaded".to_string();
    state.reason = "native_overloaded".to_string();
}

#[allow(dead_code)]
pub fn native_record_integrity_failure(identity_sha256: &str, guard_home: &Path, reason: &str) {
    let mut states = states_lock();
    let (_, state) = state_for(&mut states, identity_sha256, guard_home);
    state.state = "quarantined".to_string();
    state.reason = public_reason(reason, "native_integrity_failed");
    state.permanently_quarantined = true;
    state.circuit_until = f64::INFINITY;
    state.consecutive_failures = state.consecutive_failures.max(CIRCUIT_FAILURE_THRESHOLD);
}

/// `native_runtime_health_snapshot` (`native_runtime_resilience.py:244`).
#[allow(dead_code)]
pub fn native_runtime_health_snapshot(
    identity_sha256: &str,
    guard_home: &Path,
) -> NativeRuntimeHealthSnapshot {
    let mut states = states_lock();
    let (_, state) = state_for(&mut states, identity_sha256, guard_home);
    let now = monotonic();
    refresh_circuit(state, now);
    let circuit_open = state.permanently_quarantined || state.circuit_until > now;
    let cooldown = if state.permanently_quarantined {
        CIRCUIT_COOLDOWN_SECONDS
    } else {
        (state.circuit_until - now).max(0.0)
    };
    NativeRuntimeHealthSnapshot {
        state: state.state.clone(),
        reason: state.reason.clone(),
        circuit_open,
        consecutive_failures: state.consecutive_failures,
        resident_failures: state.resident_failures,
        oneshot_failures: state.oneshot_failures,
        overloads: state.overloads,
        starts: state.starts,
        restarts: state.restarts,
        cooldown_remaining_seconds: (cooldown * 1000.0).round() / 1000.0,
    }
}

/// RAII guard for one bounded process-wide one-shot recovery slot.
/// Mirrors `native_oneshot_lease` (`native_runtime_resilience.py:269`). The
/// boolean reports whether the lease was granted; dropping releases slots.
pub struct OneshotLease {
    acquired_global: bool,
    acquired_key: bool,
    key: String,
}

#[allow(dead_code)]
impl OneshotLease {
    pub fn granted(&self) -> bool {
        self.acquired_global && self.acquired_key
    }
}

impl Drop for OneshotLease {
    fn drop(&mut self) {
        if self.acquired_global {
            global_oneshot_held().fetch_sub(1, Ordering::SeqCst);
        }
        if self.acquired_key {
            let mut states = states_lock();
            if let Some(current) = states.get(&self.key) {
                current.oneshot_in_flight = false;
            }
        }
    }
}

/// `native_oneshot_lease` acquisition half. On global-capacity failure the
/// per-key flag is rolled back and the state is marked overloaded
/// (`native_oneshot_capacity`), matching the Python contextmanager.
#[allow(dead_code)]
pub fn native_oneshot_lease_acquire(identity_sha256: &str, guard_home: &Path) -> OneshotLease {
    let key = privacy_safe_key(identity_sha256, guard_home);
    let mut acquired_global = false;
    let mut acquired_key = false;
    {
        let mut states = states_lock();
        let (_, state) = state_for(&mut states, identity_sha256, guard_home);
        let now = monotonic();
        refresh_circuit(state, now);
        let circuit_open = state.permanently_quarantined || state.circuit_until > now;
        if !circuit_open && !state.oneshot_in_flight && now >= state.next_oneshot_allowed_at {
            state.oneshot_in_flight = true;
            state.next_oneshot_allowed_at = now + ONESHOT_RETRY_COOLDOWN_SECONDS;
            acquired_key = true;
        }
    }
    if acquired_key {
        let held = global_oneshot_held();
        // CAS-style bounded acquire: only take a slot under the limit.
        let prev = held.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |h| {
            if h < GLOBAL_ONESHOT_LIMIT {
                Some(h + 1)
            } else {
                None
            }
        });
        acquired_global = prev.is_ok();
        if !acquired_global {
            let mut states = states_lock();
            if let Some(current) = states.get(&key) {
                current.oneshot_in_flight = false;
                current.overloads += 1;
                current.state = "overloaded".to_string();
                current.reason = "native_oneshot_capacity".to_string();
            }
            acquired_key = false;
        }
    }
    OneshotLease {
        acquired_global,
        acquired_key,
        key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn home(tag: &str) -> PathBuf {
        let n = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("nrr-{}-{}-{}", std::process::id(), tag, n));
        std::fs::create_dir_all(&p).expect("tmp home");
        // Canonicalize so identity keys are stable across symlinked /var.
        std::fs::canonicalize(&p).unwrap_or(p)
    }

    #[test]
    fn privacy_key_is_sha256_hex_and_path_free() {
        let k = privacy_safe_key("abc123", Path::new("/some/dir"));
        assert_eq!(k.len(), 64);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
        // Distinct identity or home -> distinct key; never contains the path.
        assert_ne!(k, privacy_safe_key("def456", Path::new("/some/dir")));
        assert_ne!(k, privacy_safe_key("abc123", Path::new("/other/dir")));
        assert!(!k.contains('/'));
    }

    #[test]
    fn public_reason_sanitizes() {
        assert_eq!(public_reason("Native_Failed", "fb"), "native_failed");
        assert_eq!(public_reason("ok-reason.1", "fb"), "ok-reason.1");
        assert_eq!(public_reason("bad reason with space", "fb"), "fb");
        assert_eq!(public_reason("", "fb"), "fb");
        assert_eq!(
            public_reason(&"x".repeat(200), "fb").len(),
            REASON_MAX_LENGTH
        );
    }

    #[test]
    fn circuit_opens_after_threshold_failures() {
        let h = home("circuit");
        let id = "sha-circuit";
        for _ in 0..CIRCUIT_FAILURE_THRESHOLD {
            native_record_resident_failure(id, &h, "boom");
        }
        let snap = native_runtime_health_snapshot(id, &h);
        assert_eq!(snap.state, "circuit_open");
        assert_eq!(snap.reason, "native_circuit_open");
        assert!(snap.circuit_open);
        assert_eq!(snap.consecutive_failures, CIRCUIT_FAILURE_THRESHOLD);
        assert_eq!(snap.resident_failures, CIRCUIT_FAILURE_THRESHOLD);
        assert!(snap.cooldown_remaining_seconds > 0.0);
    }

    #[test]
    fn resident_success_resets_circuit() {
        let h = home("reset");
        let id = "sha-reset";
        native_record_resident_failure(id, &h, "x");
        native_record_resident_failure(id, &h, "x");
        native_record_resident_success(id, &h);
        let snap = native_runtime_health_snapshot(id, &h);
        assert_eq!(snap.state, "healthy");
        assert_eq!(snap.reason, "native_ready");
        assert_eq!(snap.consecutive_failures, 0);
        assert!(!snap.circuit_open);
    }

    #[test]
    fn integrity_failure_permanently_quarantines() {
        let h = home("quarantine");
        let id = "sha-quar";
        native_record_integrity_failure(id, &h, "digest_mismatch");
        let snap = native_runtime_health_snapshot(id, &h);
        assert_eq!(snap.state, "quarantined");
        assert!(snap.circuit_open);
        assert_eq!(snap.consecutive_failures, CIRCUIT_FAILURE_THRESHOLD);
        // Permanent: subsequent success records are ignored.
        native_record_resident_success(id, &h);
        let snap2 = native_runtime_health_snapshot(id, &h);
        assert_eq!(snap2.state, "quarantined");
    }

    #[test]
    fn oneshot_lease_granted_then_released() {
        let h = home("lease");
        let id = "sha-lease";
        {
            let lease = native_oneshot_lease_acquire(id, &h);
            assert!(lease.granted());
        } // drop releases both slots
          // Acquiring set next_oneshot_allowed_at = now + 50ms; a retry inside
          // the cooldown is denied, so wait it out like a real caller.
        std::thread::sleep(std::time::Duration::from_millis(60));
        let lease2 = native_oneshot_lease_acquire(id, &h);
        assert!(lease2.granted());
    }

    #[test]
    fn oneshot_lease_refuses_while_in_flight() {
        let h = home("lease2");
        let id = "sha-lease2";
        let l1 = native_oneshot_lease_acquire(id, &h);
        assert!(l1.granted());
        // Same identity: second acquire denied while first held.
        let l2 = native_oneshot_lease_acquire(id, &h);
        assert!(!l2.granted());
    }

    #[test]
    fn snapshot_cooldown_zero_when_healthy() {
        let h = home("cool");
        let id = "sha-cool";
        native_record_resident_success(id, &h);
        let snap = native_runtime_health_snapshot(id, &h);
        assert_eq!(snap.cooldown_remaining_seconds, 0.0);
    }
}
