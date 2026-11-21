//! The Guard OAuth refresh circuit: it parks refresh while a grant is known to
//! be dead, rejected or rate-limited, so every sync, poll and hook caller stops
//! asking the token endpoint at once.
//!
//! The state lives in the `guard_oauth_refresh_circuit` row of `sync_state`,
//! keyed by a salted PBKDF2 fingerprint of the refresh grant, so a peer that
//! re-paired (a new grant) clears the circuit on sight. The resident refresh
//! and the `oauth_refresh_circuit` action of `cloud-event-sync` share this one
//! copy. Every read and write reports its failure, and every update runs in
//! one immediate transaction, so a locked or unreadable store never reads as
//! an open circuit and two writers never interleave.

use std::path::{Path, PathBuf};
use std::time::Duration;

use base64ct::{Base64, Encoding};
use guard_command::local_supply_chain::{parse_timestamp, utc_now_iso, Timestamp};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::local_store_read::STORE_FILE_NAME;

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
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

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

/// The dead-grant backoff bounds, in seconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Backoff {
    base: f64,
    max: f64,
}

impl Backoff {
    pub(crate) fn new(base: f64, max: f64) -> Self {
        Self { base, max }
    }

    /// The bounds the operator configured, or the defaults.
    pub(crate) fn from_env() -> Self {
        Self::new(
            env_seconds(BASE_BACKOFF_ENV, BASE_BACKOFF_DEFAULT),
            env_seconds(MAX_BACKOFF_ENV, MAX_BACKOFF_DEFAULT),
        )
    }

    /// The first backoff never exceeds the maximum; later ones double.
    fn next(self, previous: Option<f64>) -> f64 {
        match previous {
            Some(previous) if previous > 0.0 => (previous * 2.0).min(self.max),
            _ => self.base.min(self.max),
        }
    }
}

fn env_seconds(env_key: &str, default: f64) -> f64 {
    std::env::var(env_key)
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(default)
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

fn store_error(error: rusqlite::Error) -> String {
    format!("The Guard OAuth refresh circuit could not use the Guard store: {error}")
}

fn read_payload(conn: &Connection, key: &str) -> Result<Option<Value>, String> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT payload_json FROM sync_state WHERE state_key = ?1 LIMIT 1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .or_else(|error| {
            if error.to_string().contains("no such table") {
                Ok(None)
            } else {
                Err(store_error(error))
            }
        })?;
    raw.map(|raw| {
        serde_json::from_str(&raw)
            .map_err(|_| "The Guard OAuth refresh circuit state is not readable.".to_owned())
    })
    .transpose()
}

fn write_payload(conn: &Connection, key: &str, payload: &Value) -> Result<(), String> {
    conn.execute(
        "INSERT INTO sync_state (state_key, payload_json, updated_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT(state_key) DO UPDATE SET \
           payload_json = excluded.payload_json, updated_at = excluded.updated_at",
        rusqlite::params![key, payload.to_string(), utc_now_iso()],
    )
    .map(drop)
    .map_err(store_error)
}

/// The stored record, or empty when there is none. A stored value that is not
/// an object is unusable, so it is an error rather than an open circuit.
fn state_of(payload: Option<Value>) -> Result<Map<String, Value>, String> {
    match payload {
        None => Ok(Map::new()),
        Some(Value::Object(state)) => Ok(state),
        Some(_) => Err("The Guard OAuth refresh circuit state is not readable.".to_owned()),
    }
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

/// The stored salt, or `None` when none was minted yet. A stored salt that
/// does not decode is an error: replacing it would orphan the parked record.
fn decoded_salt(payload: Option<Value>) -> Result<Option<Vec<u8>>, String> {
    let Some(payload) = payload else {
        return Ok(None);
    };
    payload
        .get("salt")
        .and_then(Value::as_str)
        .and_then(|encoded| Base64::decode_vec(encoded).ok())
        .filter(|salt| !salt.is_empty())
        .map(Some)
        .ok_or_else(|| "The Guard OAuth refresh circuit salt is not readable.".to_owned())
}

/// The circuit of one Guard home.
pub(crate) struct Circuit {
    store_path: PathBuf,
    backoff: Backoff,
}

impl Circuit {
    pub(crate) fn new(guard_home: &Path, backoff: Backoff) -> Self {
        Self {
            store_path: guard_home.join(STORE_FILE_NAME),
            backoff,
        }
    }

    fn connect(&self) -> Result<Connection, String> {
        let conn = crate::supply_chain_egress::open_store(&self.store_path).map_err(store_error)?;
        conn.busy_timeout(BUSY_TIMEOUT).map_err(store_error)?;
        Ok(conn)
    }

    /// Run `update` in one immediate transaction and commit what it wrote.
    fn transact<T>(
        &self,
        update: impl FnOnce(&Connection) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut conn = self.connect()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(store_error)?;
        let value = update(&tx)?;
        tx.commit().map_err(store_error)?;
        Ok(value)
    }

    /// The persisted per-installation salt. The first caller mints it inside
    /// a transaction, so racing callers all read the one salt that was kept.
    fn salt(&self) -> Result<Vec<u8>, String> {
        if let Some(salt) = decoded_salt(read_payload(&self.connect()?, SALT_KEY)?)? {
            return Ok(salt);
        }
        self.transact(|conn| {
            if let Some(salt) = decoded_salt(read_payload(conn, SALT_KEY)?)? {
                return Ok(salt);
            }
            let mut fresh = [0u8; 32];
            getrandom::fill(&mut fresh).map_err(|_| {
                "The Guard OAuth refresh circuit could not create its salt.".to_owned()
            })?;
            write_payload(
                conn,
                SALT_KEY,
                &json!({"salt": Base64::encode_string(&fresh)}),
            )?;
            Ok(fresh.to_vec())
        })
    }

    fn fingerprint(&self, refresh_grant: &str) -> Result<String, String> {
        Ok(fingerprint(refresh_grant, &self.salt()?))
    }

    /// Whether a refresh of `refresh_grant` may go ahead at `now`. A record
    /// for another grant belongs to a grant that was replaced, so it is
    /// cleared; one probe passes each time the backoff window elapses.
    pub(crate) fn check(&self, refresh_grant: &str, now: Timestamp) -> Result<Check, String> {
        let state = state_of(read_payload(&self.connect()?, STATE_KEY)?)?;
        let Some(recorded) = stored_fingerprint(&state).map(str::to_owned) else {
            return Ok(Check::Open);
        };
        if recorded != self.fingerprint(refresh_grant)? {
            self.transact(|conn| {
                let current = state_of(read_payload(conn, STATE_KEY)?)?;
                if stored_fingerprint(&current) == Some(recorded.as_str()) {
                    write_payload(conn, STATE_KEY, &json!({"cleared_at": now.isoformat()}))?;
                }
                Ok(())
            })?;
            return Ok(Check::Open);
        }
        let next_allowed = state
            .get("next_refresh_allowed_at")
            .and_then(Value::as_str)
            .and_then(parse_timestamp);
        let Some(next_allowed) = next_allowed.filter(|next| *next > now) else {
            return Ok(Check::Open);
        };
        if truthy(&state, "needs_reauthorization") {
            let rejected = state.get("failure_kind").and_then(Value::as_str) == Some(REJECTED);
            return Ok(Check::Parked { rejected });
        }
        let wait = (next_allowed.unix_seconds_f64() - now.unix_seconds_f64()).trunc();
        Ok(Check::RateLimited {
            wait_seconds: (wait as i64).max(1),
        })
    }

    /// Mark the grant as needing a new sign-in and push the next probe out.
    /// A revoked grant owes its reconnect notice at once; a rejected one only
    /// once the next probe is rejected too.
    pub(crate) fn record_dead_grant(
        &self,
        refresh_grant: &str,
        failure_kind: &str,
        now: Timestamp,
    ) -> Result<DeadGrant, String> {
        let fingerprint = self.fingerprint(refresh_grant)?;
        let backoff = self.backoff;
        self.transact(|conn| {
            let state = matching(conn, &fingerprint)?;
            let failures = state
                .get("consecutive_failures")
                .and_then(Value::as_i64)
                .map_or(1, |previous| previous.saturating_add(1));
            let wait = backoff.next(state.get("backoff_seconds").and_then(Value::as_f64));
            let notice_sent = truthy(&state, "notice_sent");
            let notice_due = !notice_sent && (failure_kind != REJECTED || failures > 1);
            write_payload(
                conn,
                STATE_KEY,
                &json!({
                    "refresh_token_fingerprint": fingerprint,
                    "consecutive_failures": failures,
                    "needs_reauthorization": true,
                    "failure_kind": failure_kind,
                    "notice_sent": notice_sent,
                    "backoff_seconds": wait,
                    "next_refresh_allowed_at": now.add_seconds_f64(wait).isoformat(),
                    "last_error_at": now.isoformat(),
                }),
            )?;
            Ok(DeadGrant {
                fingerprint: fingerprint.clone(),
                notice_due,
            })
        })
    }

    /// Record that the reconnect notice for `fingerprint` went out, on the
    /// record as it is now.
    pub(crate) fn mark_notice_sent(&self, fingerprint: &str) -> Result<(), String> {
        self.transact(|conn| {
            let mut state = matching(conn, fingerprint)?;
            if state.is_empty() {
                return Ok(());
            }
            state.insert("notice_sent".to_owned(), Value::Bool(true));
            write_payload(conn, STATE_KEY, &Value::Object(state))
        })
    }

    /// Park refresh until the server's `Retry-After` elapses, at most an hour.
    pub(crate) fn record_rate_limit(
        &self,
        refresh_grant: &str,
        retry_after_seconds: i64,
        now: Timestamp,
    ) -> Result<(), String> {
        let fingerprint = self.fingerprint(refresh_grant)?;
        let bounded = retry_after_seconds.clamp(1, MAX_RATE_LIMIT_SECONDS);
        self.transact(|conn| {
            let state = matching(conn, &fingerprint)?;
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
            write_payload(conn, STATE_KEY, &parked)
        })
    }

    /// Forget any parked failure after a refresh succeeded.
    pub(crate) fn clear(&self, now: Timestamp) -> Result<(), String> {
        self.transact(|conn| {
            if state_of(read_payload(conn, STATE_KEY)?)?.is_empty() {
                return Ok(());
            }
            write_payload(conn, STATE_KEY, &json!({"cleared_at": now.isoformat()}))
        })
    }
}

/// The record for this fingerprint, or empty when it is for another grant.
fn matching(conn: &Connection, fingerprint: &str) -> Result<Map<String, Value>, String> {
    let state = state_of(read_payload(conn, STATE_KEY)?)?;
    Ok(if stored_fingerprint(&state) == Some(fingerprint) {
        state
    } else {
        Map::new()
    })
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

/// Run one circuit call against `circuit`.
pub(crate) fn dispatch(circuit: &Circuit, call: &CircuitCall) -> Result<Value, String> {
    let now = Timestamp::now_utc();
    let grant = || required(call.refresh_grant.as_deref(), "refresh grant");
    match call.op {
        Op::Check => Ok(match circuit.check(grant()?, now)? {
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
            let recorded = circuit.record_dead_grant(grant()?, kind, now)?;
            Ok(json!({"fingerprint": recorded.fingerprint, "noticeDue": recorded.notice_due}))
        }
        Op::RecordRateLimit => {
            let seconds = call.retry_after_seconds.ok_or_else(|| {
                "The Guard OAuth refresh circuit call is missing its wait.".to_owned()
            })?;
            circuit.record_rate_limit(grant()?, seconds, now)?;
            Ok(json!({"recorded": true}))
        }
        Op::NoticeSent => {
            circuit.mark_notice_sent(required(call.fingerprint.as_deref(), "fingerprint")?)?;
            Ok(json!({"recorded": true}))
        }
        Op::Clear => {
            circuit.clear(now)?;
            Ok(json!({"recorded": true}))
        }
    }
}

#[cfg(test)]
#[path = "oauth_refresh_circuit_tests.rs"]
mod tests;
