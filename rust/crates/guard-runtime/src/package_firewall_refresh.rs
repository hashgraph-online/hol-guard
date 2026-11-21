//! `package_firewall_refresh_claim`: the throttle in front of the package
//! firewall's cloud refresh.
//!
//! A denied entitlement may heal by syncing Guard Cloud, but only once per
//! interval. The claim reads `package-firewall-refresh.json` under the Guard
//! home and answers `refresh: true` only after it has stored the new attempt
//! time, so a home that cannot record the attempt never refreshes on every
//! request.
//!
//! The home is the one the resident verified for the request, never a path
//! from the arguments, so a caller cannot point the write at another
//! directory.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use guard_command::local_supply_chain::{
    package_firewall_refresh_state_path, read_package_firewall_refresh_state,
    PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS,
};
use serde_json::{json, Value};

use crate::encrypted_secret_store::atomic_write_bytes;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

/// Serializes the read, check and write of every claim this resident answers,
/// so overlapping callers cannot both pass inside one interval.
static CLAIM: Mutex<()> = Mutex::new(());

pub(crate) fn dispatch(args: &Value, guard_home: &str) -> KindResult {
    let args = args_object(args)?;
    let guard_home = Some(guard_home)
        .filter(|text| !text.contains('\0'))
        .map(Path::new)
        .filter(|home| home.is_absolute())
        .ok_or(ERR_INVALID)?;
    let now = args
        .get("now")
        .and_then(Value::as_f64)
        .filter(|now| now.is_finite())
        .ok_or(ERR_INVALID)?;
    let _claim = CLAIM.lock().unwrap_or_else(PoisonError::into_inner);
    let last_attempt = read_package_firewall_refresh_state(guard_home)
        .and_then(|state| state.get("last_refresh_attempt_at").and_then(Value::as_f64));
    if last_attempt.is_some_and(|last| now - last < PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS) {
        return Ok(json!({ "refresh": false }));
    }
    let body =
        serde_json::to_vec(&json!({ "last_refresh_attempt_at": now })).map_err(|_| ERR_INVALID)?;
    let stored = atomic_write_bytes(
        &package_firewall_refresh_state_path(guard_home),
        &body,
        0o600,
    )
    .is_ok();
    Ok(json!({ "refresh": stored }))
}

#[cfg(test)]
#[path = "package_firewall_refresh_tests.rs"]
mod tests;
