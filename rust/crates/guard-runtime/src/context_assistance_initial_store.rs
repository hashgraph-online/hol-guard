//! A separate authenticated first-selection intent cannot masquerade as a
//! previous SDK/data selection or supply activation authority.
use super::*;
use guard_cigar_release::{InitialPhase, InitialSelection};
const PAYLOAD_BYTES: usize = 32 * 1024;
#[path = "context_assistance_initial_empty.rs"]
mod empty;
pub(crate) use empty::EmptyDataProof;
#[path = "context_assistance_initial_journal.rs"]
mod journal;
#[path = "context_assistance_initial_recovery_target.rs"]
mod recovery_target;
pub(crate) use recovery_target::InitialTarget;

pub(super) struct State {
    raw: Option<Vec<u8>>,
    record: Option<InitialSelection>,
}
fn message(home: &Path, payload: &str) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&(
        "hol-guard-cigar-initial-selection.v1",
        format!("{:x}", Sha256::digest(home.as_os_str().as_encoded_bytes())),
        payload,
    ))
    .map_err(|_| error("initial_selection_invalid"))
}
fn decode(home: &Path, raw: &[u8], key: Option<&[u8; 32]>) -> Result<InitialSelection, String> {
    let envelope: Envelope = crate::strict_json_value(raw).and_then(|v| {
        crate::strict_json::from_value(v).map_err(|_| error("initial_selection_invalid"))
    })?;
    if envelope.schema != "guard-cigar-sealed-initial-selection.v1"
        || envelope.payload.len() > PAYLOAD_BYTES
        || !is_lower_hex(&envelope.mac, 64)
    {
        return Err(error("initial_selection_invalid"));
    }
    hmac::verify(
        &hmac::Key::new(
            hmac::HMAC_SHA256,
            key.ok_or_else(|| error("switch_key_missing"))?,
        ),
        &message(home, &envelope.payload)?,
        &hex::decode(envelope.mac).map_err(|_| error("initial_selection_invalid"))?,
    )
    .map_err(|_| error("initial_selection_unauthenticated"))?;
    let record: InitialSelection =
        crate::strict_json_value(envelope.payload.as_bytes()).and_then(|v| {
            crate::strict_json::from_value(v).map_err(|_| error("initial_selection_invalid"))
        })?;
    record.validate().map_err(state_error)?;
    Ok(record)
}
impl State {
    pub(super) fn load(
        home: &Path,
        lock: &WriteLock,
        key: Option<&[u8; 32]>,
    ) -> Result<Self, String> {
        let raw = lock
            .lifecycle_bytes(LifecycleFile::InitialSelection)
            .map_err(storage_error)?;
        let record = raw.as_ref().map(|raw| decode(home, raw, key)).transpose()?;
        Ok(Self { raw, record })
    }
    pub(super) fn check(&self, lock: &WriteLock) -> Result<(), String> {
        if lock
            .lifecycle_bytes(LifecycleFile::InitialSelection)
            .map_err(storage_error)?
            != self.raw
        {
            return Err(error("switch_selection_conflict"));
        }
        Ok(())
    }
}
impl Owner {
    pub(crate) fn initial_record(&self) -> Option<&InitialSelection> {
        self.initial.record.as_ref()
    }
    pub(crate) fn check_initial_clear(&self) -> Result<(), String> {
        match self.initial_record() {
            None => Ok(()),
            Some(r) if r.phase == InitialPhase::Cancelled => Ok(()),
            Some(r) if r.phase == InitialPhase::Completed && self.record.is_some() => Ok(()),
            _ => Err(error("initial_selection_recovery_required")),
        }
    }
}

#[cfg(all(test, unix))]
#[path = "context_assistance_initial_store_tests.rs"]
mod tests;
