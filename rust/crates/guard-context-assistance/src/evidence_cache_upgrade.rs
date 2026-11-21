//! Read-only, bounded storage inventory. Digests bind a later preparation;
//! neither this snapshot nor a preflight result carries CIGAR authority.
use super::*;

#[path = "evidence_upgrade_plan.rs"]
mod plan;
#[path = "evidence_upgrade_producer.rs"]
mod producer;
#[path = "evidence_producer_binding.rs"]
pub(crate) mod producer_binding;
pub use plan::{DataCompatibility, EvidenceUpgradePlan, EvidenceUpgradeStrategy};
pub use producer::EvidenceUpgradeProducer;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RecordState {
    Readable,
    Expired,
    PendingWrite,
    UnknownSchema,
    Invalid,
}
#[derive(Clone, Debug, Serialize)]
struct SlotInventory {
    key: String,
    manifest_schema: Option<u64>,
    state: RecordState,
    active: bool,
    bytes: u64,
    broker_bytes: u64,
    notes: usize,
    notes_version: Option<String>,
    expires_at_ms: Option<u64>,
}
/// Constructed only by native protected file inspection; no deserializer lets
/// a control-plane caller substitute its own storage or schema claims.
#[derive(Clone, Debug, Serialize)]
pub struct EvidenceUpgradeInventory {
    schema: &'static str,
    snapshot_sha256: String,
    observed_at_ms: u64,
    slots: Vec<SlotInventory>,
    bytes: u64,
    max_bytes: u64,
    authority_restored: bool,
}
impl EvidenceUpgradeInventory {
    pub fn empty(now: u64) -> Result<Self, RuntimeError> {
        if now == 0 {
            return Err(RuntimeError::RequestInvalid);
        }
        Ok(Self {
            schema: "guard-cigar-evidence-inventory.v1",
            snapshot_sha256: format!("{:x}", Sha256::digest(b"guard-cigar-empty-evidence.v1")),
            observed_at_ms: now,
            slots: Vec::new(),
            bytes: 0,
            max_bytes: MAX_CACHE_BYTES,
            authority_restored: false,
        })
    }
    pub(crate) fn slot_keys(&self) -> Vec<String> {
        self.slots.iter().map(|s| s.key.clone()).collect()
    }
    pub(crate) fn only_expired_unmapped(&self, keys: &BTreeSet<String>) -> bool {
        self.slots
            .iter()
            .all(|s| keys.contains(&s.key) || (!s.active && s.state == RecordState::Expired))
    }
    pub fn snapshot_sha256(&self) -> &str {
        &self.snapshot_sha256
    }
}
fn record(
    directory: &Directory,
    key: &str,
    active: bool,
    now: u64,
) -> Result<(SlotInventory, serde_json::Value), RuntimeError> {
    let names = directory.names(3)?;
    let bytes = slot_files(directory)?;
    let mut stamps = BTreeMap::new();
    let mut broker_bytes = 0;
    if names.iter().any(|n| n == "sdk") {
        let sdk = directory.child("sdk", false)?;
        for (name, size) in sdk_files(&sdk)? {
            let limit = if name == "broker.sqlite3" {
                DATABASE_BYTES
            } else {
                JOURNAL_BYTES
            };
            let file = sdk.open_file(&name, Access::Read, limit)?;
            let stamp = fs::file_stamp(&file)?;
            sdk.check_file(&name, &file, limit)?;
            stamps.insert(name, stamp);
            broker_bytes += size;
        }
    }
    let mut states = BTreeMap::new();
    for name in ["state.json", "state.next"] {
        if names.iter().any(|n| n == name) {
            states.insert(name, directory.read(name)?);
        }
    }
    let raw = states.get("state.json");
    let schema = raw
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
        .and_then(|v| v.get("schema").and_then(|s| s.as_u64()));
    let manifest = raw
        .and_then(|b| serde_json::from_slice::<Manifest>(b).ok())
        .filter(|m| m.validate(key).is_ok() && now >= m.last_seen_ms);
    let state = match &manifest {
        None if schema.is_some_and(|s| s != 1) => RecordState::UnknownSchema,
        None => RecordState::Invalid,
        Some(m) if m.intent.is_some() || states.contains_key("state.next") => {
            RecordState::PendingWrite
        }
        Some(m) if now >= m.expires_at_ms => RecordState::Expired,
        Some(_) => RecordState::Readable,
    };
    let entry = SlotInventory {
        key: key.into(),
        manifest_schema: schema,
        state,
        active,
        bytes,
        broker_bytes,
        notes: manifest
            .as_ref()
            .and_then(|m| m.notes.as_ref())
            .map_or(0, |n| n.documents.len()),
        notes_version: manifest.as_ref().map(|m| m.notes_version.clone()),
        expires_at_ms: manifest.as_ref().map(|m| m.expires_at_ms),
    };
    let state_hashes: BTreeMap<_, _> = states
        .iter()
        .map(|(name, raw)| (*name, format!("{:x}", Sha256::digest(raw))))
        .collect();
    Ok((
        entry,
        serde_json::json!({"key":key,"state_files":state_hashes,"sdk_file_metadata":stamps}),
    ))
}
impl EvidenceCache {
    /// Does not sweep, repair, copy a checkpoint, probe an SDK, read a project
    /// file or render saved text. Active stores require a fresh quiescent check
    /// before a prepared data generation may be committed.
    pub fn upgrade_inventory(&self, now: u64) -> Result<EvidenceUpgradeInventory, RuntimeError> {
        let _operation = self.root.operation()?;
        if now == 0 {
            return Err(RuntimeError::RequestInvalid);
        }
        let summary = self.summary_inner()?;
        let mut inventory = EvidenceUpgradeInventory::empty(now)?;
        let active = self.root.active()?.clone();
        let mut keys = self.keys()?;
        keys.sort();
        let mut snapshots = Vec::new();
        for key in keys {
            let directory = self.root.directory.child(&key, false)?;
            let (entry, snapshot) = record(&directory, &key, active.contains(&key), now)?;
            inventory.slots.push(entry);
            snapshots.push(snapshot);
        }
        self.root.check()?;
        if self.summary_inner()? != summary {
            return Err(RuntimeError::ContextStale);
        }
        let bytes = serde_json::to_vec(&("guard-cigar-evidence-snapshot.v1", snapshots))
            .map_err(|_| RuntimeError::RequestInvalid)?;
        inventory.snapshot_sha256 = format!("{:x}", Sha256::digest(bytes));
        inventory.bytes = summary.bytes;
        Ok(inventory)
    }
}
