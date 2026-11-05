//! Resident-side state for the Pulse factor: the transport seam, the Yanez
//! key cache, the pending-request table, the Pulse cooldown and the local
//! single-use ledger. No lock here is ever held across a network call.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use guard_yanez_pulse::client::{HttpPulseTransport, PulseTransport};
use guard_yanez_pulse::jws::JwkSet;
use guard_yanez_pulse::receipt::{verify_receipt, ReceiptPolicy, VerifiedReceipt};
use guard_yanez_pulse::PulseError;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::approval_gate_grants::ApprovalGateErrorV1;
use crate::approval_gate_pulse::{err, factor_generation, pulse_enabled, pulse_error};
use crate::approval_gate_state::{constant_time_eq, epoch, iso_from_epoch, optional_int};
use crate::approval_gate_verify::current_totp_session_binding;

pub(crate) const PULSE_COOLDOWN_STATE_KEY: &str = "pulse_cooldown";
const PULSE_LEDGER_STATE_KEY: &str = "pulse_consumed";
const PULSE_LEDGER_MAX: usize = 512;
/// How long a spent receipt stays in the ledger after its consent bound.
/// `verify_receipt` refuses any receipt once `now` passes that bound, so the
/// entry only has to outlive it by a margin for the local clock moving back.
const PULSE_LEDGER_GRACE_SECONDS: i64 = 600;
const MAX_PENDING_PER_HOME: usize = 16;
const JWKS_TTL: Duration = Duration::from_secs(600);
/// Unknown-`kid` refresh throttle. Zero in tests so rotation can be driven
/// without sleeping.
const JWKS_REFRESH_INTERVAL: Duration = if cfg!(test) {
    Duration::ZERO
} else {
    Duration::from_secs(30)
};

// ---------------------------------------------------------------- errors

/// Too many Pulse requests are waiting for this Guard.
pub(crate) fn pulse_busy() -> ApprovalGateErrorV1 {
    err(
        "approval_gate_pulse_busy",
        "Too many Yanez Pulse requests are waiting. Approve or reject the ones in the YID app, or wait a few minutes, then try again.",
        429,
    )
}

/// The ledger of spent receipts is full of receipts that can still verify.
pub(crate) fn ledger_error(refusal: LedgerRefusal) -> ApprovalGateErrorV1 {
    match refusal {
        LedgerRefusal::Replayed => pulse_error(&PulseError::Replayed),
        LedgerRefusal::Full => err(
            "approval_gate_pulse_ledger_full",
            "Guard is holding too many recent Yanez Pulse approvals. Wait a few minutes, then approve again.",
            429,
        ),
    }
}

/// Whether the Pulse factor in `fresh` is still the one `config` was loaded
/// from: Pulse on, the same factor generation, the same YID and secrets.
/// Checked after every network wait, because another operation can disable
/// or replace Pulse while the resident waits on Yanez.
pub(crate) fn same_pulse_factor(earlier: &Value, fresh: &Value) -> bool {
    pulse_enabled(fresh)
        && factor_generation(earlier) == factor_generation(fresh)
        && [
            "pulse_yid",
            "pulse_agent_secret_id",
            "pulse_binding_secret_id",
        ]
        .iter()
        .all(|key| earlier.get(*key) == fresh.get(*key))
}

// ---------------------------------------------------------------- transport

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_TRANSPORT: std::cell::RefCell<
        Option<std::rc::Rc<guard_yanez_pulse::testkit::FakePulse>>,
    > = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Runs once, right after the next transport call: lets a test change
    /// the saved state while the resident waits on Yanez.
    pub(crate) static TEST_AFTER_TRANSPORT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

/// Run `f` against the Pulse transport.
pub(crate) fn with_transport<R>(
    agent_key: &str,
    f: impl FnOnce(&dyn PulseTransport) -> Result<R, PulseError>,
) -> Result<R, PulseError> {
    #[cfg(test)]
    if let Some(fake) = TEST_TRANSPORT.with(|t| t.borrow().clone()) {
        let result = f(fake.as_ref());
        if let Some(after) = TEST_AFTER_TRANSPORT.with(|h| h.borrow_mut().take()) {
            after();
        }
        return result;
    }
    let transport = HttpPulseTransport::new(agent_key)?;
    f(&transport)
}

struct CachedKeys {
    keys: JwkSet,
    fetched: Instant,
}

fn jwks_cache() -> &'static Mutex<Option<CachedKeys>> {
    static CACHE: OnceLock<Mutex<Option<CachedKeys>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

fn fetch_keys(transport: &dyn PulseTransport) -> Result<JwkSet, PulseError> {
    let keys = transport.public_keys()?;
    if let Ok(mut cache) = jwks_cache().lock() {
        *cache = Some(CachedKeys {
            keys: keys.clone(),
            fetched: Instant::now(),
        });
    }
    Ok(keys)
}

/// Verify with cached Yanez keys; on an unknown `kid`, refresh the set at
/// most once per 30 seconds and try again. The cache lock is never held
/// across the fetch.
pub(crate) fn verify_with_cached_keys(
    transport: &dyn PulseTransport,
    artifact: &str,
    policy: &ReceiptPolicy<'_>,
) -> Result<VerifiedReceipt, PulseError> {
    let cached = jwks_cache().lock().ok().and_then(|cache| {
        cache
            .as_ref()
            .filter(|c| c.fetched.elapsed() < JWKS_TTL)
            .map(|c| (c.keys.clone(), c.fetched))
    });
    let (keys, fetched) = match cached {
        Some(hit) => hit,
        None => (fetch_keys(transport)?, Instant::now()),
    };
    match verify_receipt(artifact, &keys, policy) {
        Err(PulseError::UnknownSigningKey) if fetched.elapsed() >= JWKS_REFRESH_INTERVAL => {
            let keys = fetch_keys(transport)?;
            verify_receipt(artifact, &keys, policy)
        }
        other => other,
    }
}

// ----------------------------------------------------------- pending table

pub(crate) enum PendingKind {
    Approval,
    Enrollment {
        agent_key: Zeroizing<String>,
        binding_key: Zeroizing<Vec<u8>>,
        yid: String,
    },
}

pub(crate) struct PendingPulse {
    pub kind: PendingKind,
    pub binding: String,
    pub request_nonce: String,
    pub terms: Value,
    pub session_binding: String,
    pub factor_generation: i64,
    pub consent_not_after: i64,
    pub artifact: Option<String>,
}

pub(crate) type PendingKey = (String, String);

pub(crate) fn pending() -> &'static Mutex<HashMap<PendingKey, PendingPulse>> {
    static PENDING: OnceLock<Mutex<HashMap<PendingKey, PendingPulse>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn pending_key(guard_home: &Path, request_id: &str) -> PendingKey {
    (
        guard_home.to_string_lossy().into_owned(),
        request_id.to_owned(),
    )
}

/// Whether this home can hold one more pending request. A full table refuses
/// new requests instead of evicting older ones, so a caller that keeps asking
/// cannot push the request the user is looking at out of the table.
pub(crate) fn pending_has_room(guard_home: &Path, now: i64) -> bool {
    let home = guard_home.to_string_lossy().into_owned();
    pending().lock().is_ok_and(|mut table| {
        table.retain(|_, e| e.consent_not_after >= now);
        table.keys().filter(|k| k.0 == home).count() < MAX_PENDING_PER_HOME
    })
}

/// Add a pending request. Returns `false`, and keeps the table as it was,
/// when this home already holds `MAX_PENDING_PER_HOME` live requests.
pub(crate) fn insert_pending(
    guard_home: &Path,
    request_id: &str,
    entry: PendingPulse,
    now: i64,
) -> bool {
    let home = guard_home.to_string_lossy().into_owned();
    let Ok(mut table) = pending().lock() else {
        return false;
    };
    table.retain(|_, e| e.consent_not_after >= now);
    if table.keys().filter(|k| k.0 == home).count() >= MAX_PENDING_PER_HOME {
        return false;
    }
    table.insert(pending_key(guard_home, request_id), entry);
    true
}

/// Drop every pending request of this home. Used when the Pulse factor is
/// turned off or replaced: those requests can no longer verify.
pub(crate) fn clear_pending_for_home(guard_home: &Path) {
    let home = guard_home.to_string_lossy().into_owned();
    if let Ok(mut table) = pending().lock() {
        table.retain(|k, _| k.0 != home);
    }
}

/// Take a pending entry out of the table. Only one verify can hold it.
pub(crate) fn take_pending(guard_home: &Path, request_id: &str) -> Option<PendingPulse> {
    pending()
        .lock()
        .ok()
        .and_then(|mut t| t.remove(&pending_key(guard_home, request_id)))
}

/// Put back an entry that was taken but not yet decided.
pub(crate) fn restore_pending(guard_home: &Path, request_id: &str, entry: PendingPulse) {
    if let Ok(mut table) = pending().lock() {
        table.insert(pending_key(guard_home, request_id), entry);
    }
}

#[cfg(test)]
pub(crate) fn pending_len(guard_home: &Path) -> usize {
    let home = guard_home.to_string_lossy().into_owned();
    pending()
        .lock()
        .map(|t| t.keys().filter(|k| k.0 == home).count())
        .unwrap_or(0)
}

// ------------------------------------------------------------ cooldown

fn cooldown_mac(key: &[u8], record: &Map<String, Value>) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key");
    mac.update(b"hol-guard-pulse-cooldown-v1");
    for field in [
        "purpose",
        "scope",
        "session_binding",
        "expires_at",
        "factor_generation",
    ] {
        let value = record.get(field).map(Value::to_string).unwrap_or_default();
        mac.update(&(value.len() as u64).to_be_bytes());
        mac.update(value.as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

/// Whether an open Pulse cooldown covers this action. A cooldown covers only
/// the same purpose and scope, from the same OS session, in the same factor
/// generation, and its record must carry a valid MAC.
pub(crate) fn pulse_cooldown_covers(
    state: &Value,
    binding_key: &[u8],
    purpose: &str,
    scope: Option<&str>,
    now_epoch: f64,
) -> bool {
    let Some(record) = state
        .get(PULSE_COOLDOWN_STATE_KEY)
        .and_then(Value::as_object)
    else {
        return false;
    };
    let Some(mac) = record.get("mac").and_then(Value::as_str) else {
        return false;
    };
    if !constant_time_eq(mac.as_bytes(), cooldown_mac(binding_key, record).as_bytes()) {
        return false;
    }
    let field = |k: &str| record.get(k).and_then(Value::as_str);
    field("purpose") == Some(purpose)
        && field("scope") == Some(scope.unwrap_or(""))
        && field("session_binding") == Some(current_totp_session_binding().as_str())
        && record
            .get("factor_generation")
            .and_then(|v| optional_int(Some(v)))
            == Some(factor_generation(state))
        && epoch(field("expires_at")) > now_epoch
}

pub(crate) fn record_pulse_cooldown(
    state: &mut Value,
    binding_key: &[u8],
    purpose: &str,
    scope: Option<&str>,
    seconds: i64,
    now_epoch: f64,
) -> String {
    let expires_at = iso_from_epoch(now_epoch + seconds as f64);
    let mut record = Map::new();
    record.insert("purpose".into(), json!(purpose));
    record.insert("scope".into(), json!(scope.unwrap_or("")));
    record.insert(
        "session_binding".into(),
        json!(current_totp_session_binding()),
    );
    record.insert("expires_at".into(), json!(expires_at));
    record.insert("factor_generation".into(), json!(factor_generation(state)));
    let mac = cooldown_mac(binding_key, &record);
    record.insert("mac".into(), json!(mac));
    if let Some(o) = state.as_object_mut() {
        o.insert(PULSE_COOLDOWN_STATE_KEY.into(), Value::Object(record));
    }
    expires_at
}

// --------------------------------------------------------------- ledger

/// Why `ledger_reserve` refused a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LedgerRefusal {
    /// This receipt was already spent.
    Replayed,
    /// The ledger holds `PULSE_LEDGER_MAX` receipts that can still verify.
    Full,
}

/// Durable, local single-use record of receipts Guard has spent, written
/// before the remote consume. An entry is kept until its consent bound plus
/// `PULSE_LEDGER_GRACE_SECONDS`: after the bound the receipt no longer
/// verifies, so dropping the entry cannot reopen a replay.
pub(crate) fn ledger_reserve(
    state: &mut Value,
    receipt: &VerifiedReceipt,
    now: i64,
) -> Result<(), LedgerRefusal> {
    let Some(o) = state.as_object_mut() else {
        return Err(LedgerRefusal::Full);
    };
    let ledger = o
        .entry(PULSE_LEDGER_STATE_KEY)
        .or_insert_with(|| Value::Object(Map::new()));
    if !ledger.is_object() {
        *ledger = Value::Object(Map::new());
    }
    let map = ledger.as_object_mut().expect("object");
    map.retain(|_, v| {
        v.as_i64()
            .is_some_and(|until| until + PULSE_LEDGER_GRACE_SECONDS >= now)
    });
    if map.contains_key(&receipt.jti) {
        return Err(LedgerRefusal::Replayed);
    }
    if map.len() >= PULSE_LEDGER_MAX {
        // Refuse rather than forget: a full ledger must not reopen replay.
        return Err(LedgerRefusal::Full);
    }
    map.insert(receipt.jti.clone(), json!(receipt.consent_not_after));
    Ok(())
}

#[cfg(test)]
pub(crate) const TEST_PULSE_LEDGER_MAX: usize = PULSE_LEDGER_MAX;
#[cfg(test)]
pub(crate) const TEST_MAX_PENDING_PER_HOME: usize = MAX_PENDING_PER_HOME;
