//! The legacy observation channel: a package without the probe envelope
//! leaves its decision in the receipt store, joined to the probe request by
//! the installation's correlation key.
//!
//! Ported from the key and store protocol of `_observe_configured_codex_hook`
//! and `read_legacy_codex_probe_receipt`. The key must exist, be private and
//! stay the same key for the whole observation.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use guard_command::hook_evidence_writer::{CorrelationHandle, InstallationCorrelationKey};
use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use serde_json::{Map, Value};

use super::inspect::resolve_lenient;
use super::publication::Call;
use super::publication_io::read_private;
use super::{Fault, Step};
use crate::guard_store_db::StoreError;
use crate::hook_evidence_correlation::{hmac_hex, parse_key, CORRELATION_KEY_FILE};
use crate::hook_evidence_store_gate::hold_storage_gate;

const MAX_KEY_BYTES: usize = 4096;
const MAX_BUDGET_MS: u64 = 60_000;
/// The longest the store waits for a lock; the deadline bounds the whole call.
const LOCK_WAIT_MS: u64 = 500;
const GENERATION_DOMAIN: &[u8] = b"transition-generation";
const EXPIRED: &str = "admission_deadline_expired";
const LOOKUP_FAILURES: [&str; 5] = [
    EXPIRED,
    "legacy_probe_identity_invalid",
    "legacy_probe_receipt_ambiguous",
    "legacy_probe_receipt_capacity",
    "legacy_probe_receipt_invalid",
];

/// A key that is read, not created, repaired or trusted on its mode alone.
fn load_key(home: &Path) -> Result<Option<InstallationCorrelationKey>, ()> {
    let Some(raw) = read_private(&home.join(CORRELATION_KEY_FILE), MAX_KEY_BYTES, true) else {
        return Ok(None);
    };
    if !raw.is_ascii() {
        return Err(());
    }
    let text = std::str::from_utf8(&raw).map_err(|_| ())?;
    parse_key(text).map(Some).map_err(|_| ())
}

fn generation_tag(key: &InstallationCorrelationKey) -> String {
    hmac_hex(key.material(), GENERATION_DOMAIN)
}

pub(super) fn expired(deadline: Instant) -> Step<()> {
    if Instant::now() >= deadline {
        return Err(Fault::Transition(EXPIRED));
    }
    Ok(())
}

pub(super) struct Legacy {
    home: PathBuf,
    store_path: String,
    store_source: String,
    key: InstallationCorrelationKey,
    tag: String,
    deadline: Instant,
}

impl Legacy {
    /// The store and key an observation of a legacy package needs.
    pub(super) fn open(call: &Call<'_>, home: &Path, deadline: Instant) -> Step<Self> {
        let unavailable = Fault::Transition("legacy_probe_store_unavailable");
        let store = call
            .args
            .get("legacy_store")
            .and_then(Value::as_object)
            .ok_or(unavailable)?;
        let field = |name: &str| store.get(name).and_then(Value::as_str);
        let (Some(store_home), Some(store_path), Some(store_source)) =
            (field("home"), field("path"), field("source"))
        else {
            return Err(Fault::Transition("legacy_probe_store_unavailable"));
        };
        if resolve_lenient(Path::new(store_home)) != resolve_lenient(home) {
            return Err(Fault::Transition("legacy_probe_store_unavailable"));
        }
        let key =
            load_key(home).map_err(|()| Fault::Transition("legacy_probe_correlation_invalid"))?;
        expired(deadline)?;
        let Some(key) = key else {
            return Err(Fault::Transition("legacy_probe_correlation_unavailable"));
        };
        Ok(Self {
            home: home.to_path_buf(),
            store_path: store_path.to_owned(),
            store_source: store_source.to_owned(),
            tag: generation_tag(&key),
            key,
            deadline,
        })
    }

    pub(super) fn key(&self) -> &InstallationCorrelationKey {
        &self.key
    }

    /// `check_legacy_key`: the key on disk is still the one this observation
    /// started with.
    pub(super) fn recheck(&self) -> Step<()> {
        let changed = || Fault::Transition("legacy_probe_correlation_changed");
        expired(self.deadline)?;
        let current = load_key(&self.home).map_err(|()| changed())?;
        expired(self.deadline)?;
        match current {
            Some(current)
                if current.key_id == self.key.key_id && generation_tag(&current) == self.tag =>
            {
                Ok(())
            }
            _ => Err(changed()),
        }
    }

    /// `read_legacy_codex_probe_receipt`: the one receipt matching this
    /// request since `since`, or none yet.
    pub(super) fn receipt(
        &self,
        correlation: &CorrelationHandle,
        since: &str,
    ) -> Step<Option<Value>> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Fault::Transition(EXPIRED));
        }
        let remaining_ms = u64::try_from(remaining.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(0));
        let mut args = Map::new();
        args.insert("key_id".to_owned(), correlation.key_id.clone().into());
        args.insert("digest".to_owned(), correlation.digest.clone().into());
        args.insert("since".to_owned(), since.into());
        args.insert(
            "budget_ms".to_owned(),
            remaining_ms.min(MAX_BUDGET_MS).into(),
        );
        args.insert(
            "deadline_unix_ms".to_owned(),
            unix_ms.saturating_add(remaining_ms).into(),
        );
        let request = GuardStoreRequestV1 {
            schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
            request_id: format!("legacy-probe-{}", correlation.digest),
            store_path: self.store_path.clone(),
            guard_home: self.home.to_string_lossy().into_owned(),
            method: "read_legacy_codex_probe_receipt".to_owned(),
            source: self.store_source.clone(),
            busy_timeout_ms: remaining_ms.min(LOCK_WAIT_MS),
            args,
        };
        let outcome = hold_storage_gate(&self.home, Duration::from_millis(remaining_ms))
            .map_err(|_| None::<StoreError>)
            .and_then(|_gate| crate::guard_store_op::evaluate(&request).map_err(Some));
        expired_after(self.deadline, outcome)
    }
}

/// Settle one store call: a lookup failure the caller names, a call that ran
/// out of time, or a store that could not answer.
pub(super) fn expired_after(
    deadline: Instant,
    outcome: Result<(Value, Option<i64>), Option<StoreError>>,
) -> Step<Option<Value>> {
    let late = Instant::now() >= deadline;
    match outcome {
        Ok(_) if late => Err(Fault::Transition(EXPIRED)),
        Ok((Value::Null, _)) => Ok(None),
        Ok((receipt, _)) => Ok(Some(receipt)),
        Err(Some(StoreError::Value(message))) => {
            match LOOKUP_FAILURES.iter().find(|known| **known == message) {
                Some(known) => Err(Fault::Transition(known)),
                None => Err(Fault::Transition("admission_protection_failed")),
            }
        }
        Err(_) if late => Err(Fault::Transition(EXPIRED)),
        Err(_) => Err(Fault::Transition("legacy_probe_storage_unavailable")),
    }
}
