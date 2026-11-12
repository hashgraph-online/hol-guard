//! One profile lifecycle owner shares the installer/interpreter preparation
//! lease. Its sealed SDK/data record and config writes use one short writer lane.
use super::*;
use crate::guard_config_update::io::{LifecycleFile, RootIdentity, WriteLock};
use guard_cigar_release::{
    SelectionPhase, SelectionPointer, SelectionRecord, SelectionTransaction,
};
use ring::hmac;
use zeroize::Zeroizing;

#[path = "context_assistance_switch_activation.rs"]
mod activation;
#[path = "context_assistance_switch_control.rs"]
mod control;
#[path = "context_assistance_switch_forget.rs"]
mod forget;
#[path = "context_assistance_switch_identity.rs"]
mod identity;
#[path = "context_assistance_initial_store.rs"]
mod initial;
pub(crate) use initial::{EmptyDataProof, InitialTarget};
#[path = "context_assistance_disabled_recovery_target.rs"]
mod disabled_recovery;
#[path = "context_assistance_switch_job_store.rs"]
pub(crate) mod jobs;
#[path = "context_assistance_switch_progress.rs"]
mod progress;
#[path = "context_assistance_switch_reconcile.rs"]
mod reconcile;
pub(crate) use disabled_recovery::DisabledTarget;
#[path = "context_assistance_switch_restore.rs"]
mod restore;
pub(crate) use activation::{prepare_activation, ActivationSelection};
pub(crate) use forget::DataRemoval;
#[path = "context_assistance_switch_scope_erasure.rs"]
mod scope_erasure;
pub(crate) use scope_erasure::ScopeRemoval;
#[path = "context_assistance_scope_index.rs"]
pub(crate) mod scope_index;
#[path = "context_assistance_switch_settings.rs"]
mod settings;
pub(crate) use settings::{settings_hash, SwitchSettings};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    payload: String,
    mac: String,
}

pub(crate) struct Owner {
    home: PathBuf,
    root_identity: RootIdentity,
    _lease: fs::File,
    raw: Option<Vec<u8>>,
    key: Option<Zeroizing<[u8; 32]>>,
    record: Option<SelectionRecord>,
    initial: initial::State,
}
fn storage_error(failure: crate::guard_config_update::Failure) -> String {
    match failure {
        crate::guard_config_update::Failure::Error(code)
            if code.ends_with("commit_outcome_unknown") =>
        {
            error("switch_commit_outcome_unknown")
        }
        crate::guard_config_update::Failure::Error(code) if code.ends_with("write_busy") => {
            error("switch_busy")
        }
        crate::guard_config_update::Failure::Error(code) if code == "config_file_changed" => {
            error("switch_settings_conflict")
        }
        crate::guard_config_update::Failure::Error(code)
            if code == "cigar_lifecycle_record_changed" =>
        {
            error("switch_selection_conflict")
        }
        _ => error("switch_storage_unavailable_or_changed"),
    }
}
fn state_error(e: guard_cigar_release::SwitchError) -> String {
    error(e.code())
}
fn message(home: &Path, payload: &str) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&(
        "hol-guard-cigar-lifecycle-selection.v2",
        format!("{:x}", Sha256::digest(home.as_os_str().as_encoded_bytes())),
        payload,
    ))
    .map_err(|_| error("switch_record_invalid"))
}
fn key_bytes(lock: &WriteLock) -> Result<Option<Zeroizing<[u8; 32]>>, String> {
    let Some(bytes) = lock
        .lifecycle_bytes(LifecycleFile::Key)
        .map_err(storage_error)?
    else {
        return Ok(None);
    };
    let bytes = Zeroizing::new(bytes);
    Ok(Some(Zeroizing::new(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| error("switch_key_invalid"))?,
    )))
}
fn decode(home: &Path, raw: &[u8], key: &[u8; 32]) -> Result<SelectionRecord, String> {
    let envelope: Envelope = crate::strict_json_value(raw).and_then(|v| {
        crate::strict_json::from_value(v).map_err(|_| error("switch_record_invalid"))
    })?;
    if envelope.schema != "guard-cigar-sealed-selection.v2"
        || envelope.payload.len() > 64 * 1024
        || !is_lower_hex(&envelope.mac, 64)
    {
        return Err(error("switch_record_invalid"));
    }
    let mac = hex::decode(&envelope.mac).map_err(|_| error("switch_record_invalid"))?;
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, key),
        &message(home, &envelope.payload)?,
        &mac,
    )
    .map_err(|_| error("switch_record_unauthenticated"))?;
    let record: SelectionRecord =
        crate::strict_json_value(envelope.payload.as_bytes()).and_then(|v| {
            crate::strict_json::from_value(v).map_err(|_| error("switch_record_invalid"))
        })?;
    record.validate().map_err(state_error)?;
    Ok(record)
}
impl Owner {
    pub(crate) fn acquire(home: &Path) -> Result<Self, String> {
        let lease = preparation::lifecycle_lease(home)?;
        let home = fs::canonicalize(home).map_err(|_| error("home_invalid"))?;
        let lock = WriteLock::acquire(&home).map_err(storage_error)?;
        let raw = lock
            .lifecycle_bytes(LifecycleFile::Record)
            .map_err(storage_error)?;
        let key = key_bytes(&lock)?;
        let record = match &raw {
            Some(raw) => Some(decode(
                &home,
                raw,
                key.as_deref().ok_or_else(|| error("switch_key_missing"))?,
            )?),
            None => None,
        };
        let initial = initial::State::load(&home, &lock, key.as_deref())?;
        let root_identity = lock.root_identity().map_err(storage_error)?;
        Ok(Self {
            home,
            root_identity,
            _lease: lease,
            raw,
            key,
            record,
            initial,
        })
    }
    pub(crate) fn record(&self) -> Option<&SelectionRecord> {
        self.record.as_ref()
    }
    fn check(&self, lock: &WriteLock) -> Result<(), String> {
        if lock.root_identity().map_err(storage_error)? != self.root_identity {
            return Err(error("switch_home_changed"));
        }
        if lock
            .lifecycle_bytes(LifecycleFile::Record)
            .map_err(storage_error)?
            != self.raw
        {
            return Err(error("switch_selection_conflict"));
        }
        let observed = key_bytes(lock)?;
        if observed.as_deref() != self.key.as_deref() {
            return Err(error("switch_key_changed"));
        }
        self.initial.check(lock)?;
        Ok(())
    }
    fn provision(&mut self, lock: &WriteLock) -> Result<(), String> {
        self.check(lock)?;
        if self.key.is_none() {
            let mut key = Zeroizing::new([0_u8; 32]);
            getrandom::fill(key.as_mut()).map_err(|_| error("switch_key_unavailable"))?;
            lock.publish_lifecycle(LifecycleFile::Key, None, key.as_ref())
                .map_err(storage_error)?;
            let observed = key_bytes(lock)?.ok_or_else(|| error("switch_key_missing"))?;
            if observed.as_ref() != key.as_ref() {
                return Err(error("switch_key_changed"));
            }
            self.key = Some(observed);
        }
        Ok(())
    }
    fn publish_locked(&mut self, lock: &WriteLock, record: SelectionRecord) -> Result<(), String> {
        self.check(lock)?;
        record.validate().map_err(state_error)?;
        let payload = serde_json::to_string(&record).map_err(|_| error("switch_record_invalid"))?;
        if payload.len() > 64 * 1024 {
            return Err(error("switch_record_too_large"));
        }
        let key = self
            .key
            .as_deref()
            .ok_or_else(|| error("switch_key_missing"))?;
        let mac = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, key),
            &message(&self.home, &payload)?,
        );
        let raw = serde_json::to_vec(&Envelope {
            schema: "guard-cigar-sealed-selection.v2".into(),
            payload,
            mac: hex::encode(mac.as_ref()),
        })
        .map_err(|_| error("switch_record_invalid"))?;
        // An error may follow rename. Keep the previous in-memory view and
        // require reopening/reconciliation; never replay an uncertain write.
        lock.publish_lifecycle(LifecycleFile::Record, self.raw.as_deref(), &raw)
            .map_err(storage_error)?;
        self.raw = Some(raw);
        self.record = Some(record);
        Ok(())
    }
    pub(crate) fn initialize(&mut self, current: SelectionPointer) -> Result<(), String> {
        self.check_initial_clear()?;
        current.validate().map_err(state_error)?;
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.check(&lock)?;
        if let Some(record) = &self.record {
            return if record.current == current {
                Ok(())
            } else {
                Err(error("switch_selection_conflict"))
            };
        }
        self.provision(&lock)?;
        self.publish_locked(
            &lock,
            SelectionRecord {
                schema: "guard-cigar-selection.v2".into(),
                revision: 1,
                current,
                last_good: None,
                transaction: None,
            },
        )
    }
    pub(crate) fn begin(&mut self, transaction: SelectionTransaction) -> Result<(), String> {
        let next = self
            .record
            .as_ref()
            .ok_or_else(|| error("switch_selection_missing"))?
            .begin(transaction)
            .map_err(state_error)?;
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.publish_locked(&lock, next)
    }
    pub(crate) fn advance(&mut self, phase: SelectionPhase) -> Result<(), String> {
        let next = self
            .record
            .as_ref()
            .ok_or_else(|| error("switch_selection_missing"))?
            .advance(phase)
            .map_err(state_error)?;
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.publish_locked(&lock, next)
    }
    /// Caller has revoked its native epoch and received the old actor's
    /// cleanup acknowledgement. No SDK calls or source reads run in this lane.
    pub(crate) fn commit(&mut self, settings: &SwitchSettings) -> Result<(), String> {
        let lock = WriteLock::acquire(&self.home).map_err(storage_error)?;
        self.check(&lock)?;
        let record = self
            .record
            .as_ref()
            .ok_or_else(|| error("switch_selection_missing"))?;
        let t = record
            .transaction
            .as_ref()
            .ok_or_else(|| error("switch_transaction_missing"))?;
        if t.phase != SelectionPhase::StopIntent
            || t.cancel_requested
            || !settings.matches(t)
            || settings.home() != self.home
        {
            return Err(error("switch_selection_conflict"));
        }
        settings.check_current()?;
        let intent = record
            .advance(SelectionPhase::CommitIntent)
            .map_err(state_error)?;
        self.publish_locked(&lock, intent)?;
        settings.publish(&lock)?;
        let committed = self
            .record
            .as_ref()
            .ok_or_else(|| error("switch_selection_missing"))?
            .advance(SelectionPhase::Committed)
            .map_err(state_error)?;
        self.publish_locked(&lock, committed)
    }
}

#[cfg(all(test, unix))]
#[path = "context_assistance_switch_store_tests.rs"]
mod tests;
