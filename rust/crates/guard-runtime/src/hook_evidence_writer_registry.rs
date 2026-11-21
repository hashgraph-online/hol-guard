//! Per-home writer slots and the native receipt handoff.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, TryLockError};

use guard_command::hook_evidence_writer::{
    ComposioApi, EvidenceWriterDeps, NativeEvidenceJournal, NativeReceiptValidation,
    ReceiptValidationApi, RuntimeHookEvidenceWriter,
};
use guard_contracts::NativeHookDecisionReceiptV1;
use serde_json::Value;

use crate::hook_evidence_activity::NativeCorrelation;
use crate::hook_evidence_composio::NativeComposio;
use crate::hook_evidence_store::{NativeEvidenceStore, PolicyBarrierApi, StoreFatalSignal};
use crate::hook_evidence_store_timeout::NativeSqliteTimeout;

/// `RuntimeHookEvidenceWriter.__init__` defaults (:88-92).
const MAX_RECORDS: usize = 2_000;
const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_BATCH: usize = 50;
const BATCH_WAIT_SECONDS: f64 = 0.025;

/// The policy barrier the store seam closes after a discovery write. It
/// records the mutation for the caller instead of reaching into the Python
/// publisher registry this process has no handle on.
struct MutationCounter(Arc<AtomicU64>);

impl PolicyBarrierApi for MutationCounter {
    fn notify_policy_mutation(&self, _guard_home: &Path) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// One Guard home's writer, the mutations its store seam has recorded, and
/// the fatal store failure it is waiting to report.
pub(super) struct ResidentWriter {
    pub(super) writer: Arc<RuntimeHookEvidenceWriter>,
    pub(super) mutations: Arc<AtomicU64>,
    pub(super) fatal: StoreFatalSignal,
}

/// One Guard home's writer slot. Holding the slot's lock serializes every
/// request for that home: a submission cannot queue onto a writer a stop has
/// already begun draining, and a stop cannot drop a writer a later submission
/// built. Both matter because the writers for one home share one journal file.
pub(super) struct HomeSlot {
    pub(super) writer: Mutex<Option<ResidentWriter>>,
}

fn registry() -> &'static Mutex<HashMap<PathBuf, Arc<HomeSlot>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Arc<HomeSlot>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn build(guard_home: &Path, source: &str) -> Result<ResidentWriter, io::Error> {
    let mutations = Arc::new(AtomicU64::new(0));
    let store = NativeEvidenceStore::new(
        guard_home.to_path_buf(),
        source,
        Box::new(MutationCounter(Arc::clone(&mutations))),
    );
    let fatal = store.fatal();
    // The journal validates the records it rewrites with the same pair the
    // writer validates submissions with, so both share one instance each.
    let receipts: Arc<dyn ReceiptValidationApi + Send + Sync> = Arc::new(NativeReceiptValidation);
    let composio: Arc<dyn ComposioApi + Send + Sync> = Arc::new(NativeComposio);
    let deps = EvidenceWriterDeps {
        correlation: Box::new(NativeCorrelation::new(guard_home.to_path_buf())),
        journal: Box::new(NativeEvidenceJournal::new(
            Arc::clone(&receipts),
            Arc::clone(&composio),
        )),
        receipts,
        composio,
        sqlite_timeout: Box::new(NativeSqliteTimeout),
    };
    let writer = RuntimeHookEvidenceWriter::new(
        Arc::new(store),
        deps,
        MAX_RECORDS,
        MAX_BYTES,
        MAX_BATCH,
        BATCH_WAIT_SECONDS,
        None,
    )?;
    Ok(ResidentWriter {
        writer: Arc::new(writer),
        mutations,
        fatal,
    })
}

/// This Guard home's slot. Slots are never removed: an empty slot costs a
/// pointer, and keeping it is what lets a stop and a racing submission agree
/// on which writer they are talking about.
pub(super) fn slot(guard_home: &Path) -> Arc<HomeSlot> {
    let mut registry = registry().lock().unwrap_or_else(|e| e.into_inner());
    Arc::clone(registry.entry(guard_home.to_path_buf()).or_insert_with(|| {
        Arc::new(HomeSlot {
            writer: Mutex::new(None),
        })
    }))
}

/// The home as the filesystem names it.
///
/// One home can be spelled more than one way — through a symlink, with a
/// component that resolves away — and each spelling would otherwise take its
/// own slot and its own writer, two writers appending to the one journal that
/// home owns. A home that cannot be resolved keeps the spelling it arrived
/// with; the store seam refuses it the same way either way.
pub(super) fn canonical_home(guard_home: &Path) -> PathBuf {
    std::fs::canonicalize(guard_home).unwrap_or_else(|_| guard_home.to_path_buf())
}

/// Run `act` against this Guard home's writer, started on first use.
pub(super) fn with_writer<T>(
    guard_home: &Path,
    source: &str,
    act: impl FnOnce(&ResidentWriter) -> T,
) -> Result<T, io::Error> {
    let slot = slot(guard_home);
    let mut held = slot.writer.lock().unwrap_or_else(|e| e.into_inner());
    // A writer whose thread has exited drains nothing more, so anything
    // queued onto it would sit there. It is replaced — but what it still
    // holds is the two signals it exists to deliver, and dropping it would
    // drop them silently. The replacement carries them instead.
    let mut carried = None;
    if held
        .as_ref()
        .is_some_and(|resident| resident.writer.has_exited())
    {
        carried = held.take();
    }
    // A writer whose drain ran out of time has not left the journal yet. A
    // second writer for the same home would append to the file the first one
    // still owns, so this request is refused until that worker leaves.
    if held
        .as_ref()
        .is_some_and(|resident| resident.writer.is_stopping())
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "the hook evidence writer for this Guard home is still draining",
        ));
    }
    if held.is_none() {
        let fresh = match build(guard_home, source) {
            Ok(fresh) => fresh,
            Err(error) => {
                // The replacement failed, so the exited writer goes back into
                // the slot. It still holds the mutation count and the store
                // failure this request exists to report, and an empty slot
                // would answer `stats` with an idle home instead of the fault.
                *held = carried;
                return Err(error);
            }
        };
        if let Some(gone) = carried {
            fresh
                .mutations
                .fetch_add(gone.mutations.swap(0, Ordering::SeqCst), Ordering::SeqCst);
            fresh.fatal.adopt(&gone.fatal);
        }
        *held = Some(fresh);
    }
    Ok(act(held.as_ref().expect("the writer was just built")))
}

/// Run `act` against this Guard home's writer only if one is already running.
/// `stats` must not start a writer that no submission has asked for.
pub(super) fn with_running<T>(
    guard_home: &Path,
    act: impl FnOnce(&ResidentWriter) -> T,
) -> Option<T> {
    let slot = slot(guard_home);
    let held = slot.writer.lock().unwrap_or_else(|e| e.into_inner());
    held.as_ref().map(act)
}

/// Run `act` with the live writer for `guard_home` while its slot is held,
/// so the writer cannot exit or start draining in the meantime.
///
/// `None` means `act` did not run: no live writer runs for the home, or its
/// slot is busy starting one (a journal replay) or draining one. This never
/// waits on the slot and never starts a writer.
fn with_live<T>(guard_home: &Path, act: impl FnOnce(&ResidentWriter) -> T) -> Option<T> {
    let slot = slot(&canonical_home(guard_home));
    let held = match slot.writer.try_lock() {
        Ok(held) => held,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => return None,
    };
    let resident = held.as_ref()?;
    if resident.writer.has_exited() || resident.writer.is_stopping() {
        return None;
    }
    Some(act(resident))
}

/// Encode an edge answer that says its receipt was recorded, then queue
/// `receipt` with the live writer for `guard_home` and hand that writer to
/// `then` for the evidence that follows the receipt, holding the writer the
/// whole time so it cannot exit or start draining in between.
///
/// `None` means nothing was queued and the answer must say so: no live writer
/// runs for the home, its slot is busy starting one (a journal replay) or
/// draining one, or the writer refused the receipt. The edge never waits on
/// that slot and never starts a writer. An answer that fails to encode is
/// returned as is and queues nothing.
pub(crate) fn record_edge_receipt<E>(
    guard_home: &Path,
    receipt: &NativeHookDecisionReceiptV1,
    encode: impl FnOnce() -> Result<Vec<u8>, E>,
    then: impl FnOnce(&RuntimeHookEvidenceWriter),
) -> Option<Result<Vec<u8>, E>> {
    let Ok(Value::Object(receipt)) = serde_json::to_value(receipt) else {
        return None;
    };
    with_live(guard_home, |resident| {
        let encoded = match encode() {
            Ok(encoded) => encoded,
            Err(error) => return Some(Err(error)),
        };
        if !resident.writer.submit_native_decision_receipt(&receipt) {
            return None;
        }
        then(resident.writer.as_ref());
        Some(Ok(encoded))
    })
    .flatten()
}

/// Queue a direct answer's evidence with `queue`, which may first record its
/// receipt and command activity with the live writer for `guard_home` it is
/// handed, holding that writer the whole time.
///
/// The drain submits whatever a record leaves to this writer through the
/// same slot, so the activity cannot reach the writer before the receipt it
/// cites. `None` means `queue` did not run, because no live writer is free to
/// take the evidence, which then stays with the drain.
pub(crate) fn record_direct<T>(
    guard_home: &Path,
    queue: impl FnOnce(&RuntimeHookEvidenceWriter) -> T,
) -> Option<T> {
    with_live(guard_home, |resident| queue(resident.writer.as_ref()))
}

/// Run `record` with this Guard home's writer, started on first use as a
/// submission starts it, and hand back the store failure the writer holds.
///
/// The direct evidence drain records what a direct answer left behind this
/// way, with the source of the store the bound daemon publishes. `None`
/// means the writer could not run, and the evidence stays with the drain.
pub(crate) fn record_drained<T>(
    guard_home: &Path,
    source: &str,
    record: impl FnOnce(&RuntimeHookEvidenceWriter) -> T,
) -> Option<(T, Value)> {
    with_writer(&canonical_home(guard_home), source, |resident| {
        (record(resident.writer.as_ref()), resident.fatal.peek())
    })
    .ok()
}

/// The store failure the writer already running for `guard_home` holds, for
/// a drain page that gave it nothing to record. It reports the failure until
/// the client acknowledges it, so a recovery that failed is asked for again.
/// A slot busy starting or draining a writer is not waited on, and no writer
/// is started.
pub(crate) fn drained_fatal(guard_home: &Path) -> Option<Value> {
    let slot = slot(&canonical_home(guard_home));
    let held = match slot.writer.try_lock() {
        Ok(held) => held,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => return None,
    };
    held.as_ref().map(|resident| resident.fatal.peek())
}

/// Run `act` while this Guard home's writer slot is held, as starting a
/// writer or draining one holds it.
#[cfg(test)]
pub(crate) fn while_slot_busy<T>(guard_home: &Path, act: impl FnOnce() -> T) -> T {
    let slot = slot(&canonical_home(guard_home));
    let _held = slot.writer.lock().unwrap_or_else(|e| e.into_inner());
    act()
}
