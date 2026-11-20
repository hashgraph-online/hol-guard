//! The Guard OAuth refresh circuit: it parks refresh while a grant is known to
//! be dead, rejected or rate-limited, so every sync, poll and hook caller stops
//! asking the token endpoint at once.
//!
//! The state lives in the `guard_oauth_refresh_circuit` sync payload, keyed by
//! a salted PBKDF2 fingerprint of the refresh grant, so a peer that re-paired
//! (a new grant) clears the circuit on sight. The resident refresh and the
//! `oauth_refresh_circuit` action of `cloud-event-sync` share this one copy.

use base64ct::{Base64, Encoding};
use guard_command::local_supply_chain::{parse_timestamp, SupplyChainStore, Timestamp};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const STATE_KEY: &str = "guard_oauth_refresh_circuit";
const SALT_KEY: &str = "guard_oauth_refresh_circuit_fingerprint_salt";
/// PBKDF2-HMAC-SHA256 work factor for the fingerprint.
const FINGERPRINT_ITERATIONS: u32 = 600_000;
const BASE_BACKOFF_ENV: &str = "GUARD_OAUTH_REFRESH_CIRCUIT_BASE_BACKOFF_SECONDS";
const MAX_BACKOFF_ENV: &str = "GUARD_OAUTH_REFRESH_CIRCUIT_MAX_BACKOFF_SECONDS";
const BASE_BACKOFF_DEFAULT: f64 = 30.0;
const MAX_BACKOFF_DEFAULT: f64 = 300.0;
/// The longest server `Retry-After` the circuit honours.
const MAX_RATE_LIMIT_SECONDS: i64 = 3600;

/// The token endpoint answered `invalid_grant` twice.
pub(crate) const REVOKED: &str = "revoked";
/// The token endpoint refused the request with another error.
pub(crate) const REJECTED: &str = "rejected";

/// What a refresh may do now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Check {
    /// Nothing parked for this grant.
    Open,
    /// The grant needs a new sign-in; `rejected` keeps the reauthorization
    /// error instead of the revoked one.
    Parked { rejected: bool },
    /// Wait this many seconds before the next probe.
    RateLimited { wait_seconds: i64 },
}

/// A recorded dead grant, and whether its one reconnect notice is still owed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeadGrant {
    pub(crate) fingerprint: String,
    pub(crate) notice_due: bool,
}

fn backoff_seconds(env_key: &str, default: f64) -> f64 {
    std::env::var(env_key)
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(default)
}

fn stored_salt(store: &dyn SupplyChainStore) -> Option<Vec<u8>> {
    let payload = store.get_sync_payload(SALT_KEY)?;
    let encoded = payload.get("salt").and_then(Value::as_str)?;
    if encoded.is_empty() {
        return None;
    }
    Base64::decode_vec(encoded).ok()
}

/// The persisted per-installation salt, minted on first use. Two racing
/// writers converge on whichever write the store kept.
fn salt(store: &dyn SupplyChainStore) -> Vec<u8> {
    if let Some(salt) = stored_salt(store) {
        return salt;
    }
    let mut fresh = [0u8; 32];
    if getrandom::fill(&mut fresh).is_err() {
        // The fingerprint is a lookup key, not a credential; without an OS
        // RNG a home-bound digest still keeps it usable and non-reversible.
        let mut seed = Sha256::new();
        seed.update(Timestamp::now_utc().unix_seconds().to_be_bytes());
        seed.update(store.guard_home().to_string_lossy().as_bytes());
        return seed.finalize().to_vec();
    }
    store.set_sync_payload(SALT_KEY, &json!({"salt": Base64::encode_string(&fresh)}));
    stored_salt(store).unwrap_or_else(|| fresh.to_vec())
}

/// PBKDF2-HMAC-SHA256 of the grant, truncated to 32 hex characters.
pub(crate) fn fingerprint(refresh_grant: &str, salt: &[u8]) -> String {
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        refresh_grant.as_bytes(),
        salt,
        FINGERPRINT_ITERATIONS,
        &mut out,
    );
    hex::encode(out)[..32].to_owned()
}

fn load(store: &dyn SupplyChainStore) -> Map<String, Value> {
    match store.get_sync_payload(STATE_KEY) {
        Some(Value::Object(state)) => state,
        _ => Map::new(),
    }
}

fn save(store: &dyn SupplyChainStore, state: Value) {
    store.set_sync_payload(STATE_KEY, &state);
}

fn stored_fingerprint(state: &Map<String, Value>) -> Option<&str> {
    state
        .get("refresh_token_fingerprint")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn truthy(state: &Map<String, Value>, key: &str) -> bool {
    state.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// The state recorded for this grant, or empty when it was recorded for
/// another one.
fn state_for(store: &dyn SupplyChainStore, fingerprint: &str) -> Map<String, Value> {
    let state = load(store);
    if stored_fingerprint(&state) == Some(fingerprint) {
        state
    } else {
        Map::new()
    }
}

/// Whether a refresh of `refresh_grant` may go ahead at `now`. A stored
/// fingerprint for another grant clears the circuit, and one probe passes
/// each time the backoff window elapses.
pub(crate) fn check(store: &dyn SupplyChainStore, refresh_grant: &str, now: Timestamp) -> Check {
    let state = load(store);
    let Some(recorded) = stored_fingerprint(&state) else {
        return Check::Open;
    };
    if recorded != fingerprint(refresh_grant, &salt(store)) {
        clear(store, now);
        return Check::Open;
    }
    let next_allowed = state
        .get("next_refresh_allowed_at")
        .and_then(Value::as_str)
        .and_then(parse_timestamp);
    let Some(next_allowed) = next_allowed.filter(|next| *next > now) else {
        return Check::Open;
    };
    if truthy(&state, "needs_reauthorization") {
        let rejected = state.get("failure_kind").and_then(Value::as_str) == Some(REJECTED);
        return Check::Parked { rejected };
    }
    let wait = (next_allowed.unix_seconds_f64() - now.unix_seconds_f64()).trunc();
    Check::RateLimited {
        wait_seconds: (wait as i64).max(1),
    }
}

/// Mark the grant as needing a new sign-in and push the next probe out. The
/// backoff doubles from the last one, up to the maximum. A revoked grant owes
/// its reconnect notice at once; a rejected one only once the next probe is
/// rejected too.
pub(crate) fn record_dead_grant(
    store: &dyn SupplyChainStore,
    refresh_grant: &str,
    failure_kind: &str,
    now: Timestamp,
) -> DeadGrant {
    let fingerprint = fingerprint(refresh_grant, &salt(store));
    let state = state_for(store, &fingerprint);
    let failures = state
        .get("consecutive_failures")
        .and_then(Value::as_i64)
        .map_or(1, |previous| previous.saturating_add(1));
    let backoff = match state.get("backoff_seconds").and_then(Value::as_f64) {
        Some(previous) if previous > 0.0 => {
            (previous * 2.0).min(backoff_seconds(MAX_BACKOFF_ENV, MAX_BACKOFF_DEFAULT))
        }
        _ => backoff_seconds(BASE_BACKOFF_ENV, BASE_BACKOFF_DEFAULT),
    };
    let notice_sent = truthy(&state, "notice_sent");
    let notice_due = !notice_sent && (failure_kind != REJECTED || failures > 1);
    save(
        store,
        json!({
            "refresh_token_fingerprint": fingerprint,
            "consecutive_failures": failures,
            "needs_reauthorization": true,
            "failure_kind": failure_kind,
            "notice_sent": notice_sent,
            "backoff_seconds": backoff,
            "next_refresh_allowed_at": now.add_seconds_f64(backoff).isoformat(),
            "last_error_at": now.isoformat(),
        }),
    );
    DeadGrant {
        fingerprint,
        notice_due,
    }
}

/// Record that the reconnect notice for `fingerprint` went out.
pub(crate) fn mark_notice_sent(store: &dyn SupplyChainStore, fingerprint: &str) {
    let mut state = state_for(store, fingerprint);
    if state.is_empty() {
        return;
    }
    state.insert("notice_sent".to_owned(), Value::Bool(true));
    save(store, Value::Object(state));
}

/// Park refresh until the server's `Retry-After` elapses, at most an hour.
pub(crate) fn record_rate_limit(
    store: &dyn SupplyChainStore,
    refresh_grant: &str,
    retry_after_seconds: i64,
    now: Timestamp,
) {
    let fingerprint = fingerprint(refresh_grant, &salt(store));
    let state = state_for(store, &fingerprint);
    let bounded = retry_after_seconds.clamp(1, MAX_RATE_LIMIT_SECONDS);
    let mut parked = json!({
        "refresh_token_fingerprint": fingerprint,
        "consecutive_failures": state.get("consecutive_failures").and_then(Value::as_i64).unwrap_or(0),
        "needs_reauthorization": truthy(&state, "needs_reauthorization"),
        "notice_sent": truthy(&state, "notice_sent"),
        "backoff_seconds": bounded,
        "next_refresh_allowed_at": now.add_seconds_f64(bounded as f64).isoformat(),
        "last_error_at": now.isoformat(),
    });
    if let Some(kind) = state.get("failure_kind").filter(|kind| kind.is_string()) {
        parked["failure_kind"] = kind.clone();
    }
    save(store, parked);
}

/// Forget any parked failure after a refresh succeeded.
pub(crate) fn clear(store: &dyn SupplyChainStore, now: Timestamp) {
    if !load(store).is_empty() {
        save(store, json!({"cleared_at": now.isoformat()}));
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Op {
    Check,
    RecordDeadGrant,
    RecordRateLimit,
    NoticeSent,
    Clear,
}

/// What the caller sent for `oauth_refresh_circuit`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CircuitCall {
    op: Op,
    #[serde(default, rename = "refreshToken")]
    refresh_grant: Option<String>,
    #[serde(default)]
    failure_kind: Option<String>,
    #[serde(default)]
    retry_after_seconds: Option<i64>,
    #[serde(default)]
    fingerprint: Option<String>,
}

fn required<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, String> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("The Guard OAuth refresh circuit call is missing its {name}."))
}

/// Run one circuit call against `store`.
pub(crate) fn dispatch(store: &dyn SupplyChainStore, call: &CircuitCall) -> Result<Value, String> {
    let now = Timestamp::now_utc();
    let grant = || required(call.refresh_grant.as_deref(), "refresh grant");
    match call.op {
        Op::Check => Ok(match check(store, grant()?, now) {
            Check::Open => json!({"state": "open"}),
            Check::Parked { rejected } => json!({
                "state": "parked",
                "failureKind": if rejected { REJECTED } else { REVOKED },
            }),
            Check::RateLimited { wait_seconds } => {
                json!({"state": "rate_limited", "retryAfterSeconds": wait_seconds})
            }
        }),
        Op::RecordDeadGrant => {
            let kind = match call.failure_kind.as_deref() {
                Some(REVOKED) => REVOKED,
                Some(REJECTED) => REJECTED,
                _ => return Err("The Guard OAuth refresh failure kind is not known.".to_owned()),
            };
            let recorded = record_dead_grant(store, grant()?, kind, now);
            Ok(json!({"fingerprint": recorded.fingerprint, "noticeDue": recorded.notice_due}))
        }
        Op::RecordRateLimit => {
            let seconds = call.retry_after_seconds.ok_or_else(|| {
                "The Guard OAuth refresh circuit call is missing its wait.".to_owned()
            })?;
            record_rate_limit(store, grant()?, seconds, now);
            Ok(json!({"recorded": true}))
        }
        Op::NoticeSent => {
            mark_notice_sent(store, required(call.fingerprint.as_deref(), "fingerprint")?);
            Ok(json!({"recorded": true}))
        }
        Op::Clear => {
            clear(store, now);
            Ok(json!({"recorded": true}))
        }
    }
}

#[cfg(test)]
#[path = "oauth_refresh_circuit_tests.rs"]
mod tests;
