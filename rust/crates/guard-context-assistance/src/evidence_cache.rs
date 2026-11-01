//! Bounded Guard-owned saved evidence. There are no saved file locators,
//! principals, grants, credentials, prepared contexts or execution approvals.
use crate::{BrokerStorage, ContextDocument, RuntimeError};
use nix::fcntl::{Flock, FlockArg, OFlag};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[path = "evidence_cold_export.rs"]
mod cold_export;
#[path = "evidence_cache_fs.rs"]
mod fs;
#[path = "evidence_cache_records.rs"]
pub(crate) mod records;
#[path = "evidence_cache_slot.rs"]
mod slot;
#[path = "evidence_note_transfer.rs"]
pub(crate) mod transfer;
use fs::Directory;
use records::Manifest;
pub use records::SavedNotes;
pub use transfer::{EvidenceScope, VerifiedNoteTransfer};
#[path = "evidence_generations.rs"]
mod generations;
pub use generations::{
    EvidenceCacheLocation, EvidenceErasureScope, EvidenceGenerationStore, EvidencePreparation,
    EvidenceScopeErasure, EvidenceScopeOwner, PreparedEvidenceGeneration,
};
#[path = "evidence_cache_upgrade.rs"]
mod upgrade;
pub use upgrade::{
    DataCompatibility, EvidenceUpgradeInventory, EvidenceUpgradePlan, EvidenceUpgradeProducer,
    EvidenceUpgradeStrategy,
};

const MAX_SLOTS: usize = 8;
const STATE_BYTES: u64 = 128 * 1024;
const MAX_CACHE_BYTES: u64 = 528 * 1024 * 1024;
const DATABASE_BYTES: u64 = 32 * 1024 * 1024;
const JOURNAL_BYTES: u64 = 33 * 1024 * 1024;

struct Root {
    directory: Directory,
    lock: Flock<File>,
    active: Mutex<BTreeSet<String>>,
    operation: Mutex<()>,
}
impl Root {
    fn operation(&self) -> Result<std::sync::MutexGuard<'_, ()>, RuntimeError> {
        self.operation
            .lock()
            .map_err(|_| RuntimeError::StorageRepairRequired)
    }
    fn check(&self) -> Result<(), RuntimeError> {
        self.directory.check_file("cache.lock", &self.lock, 0)
    }
    fn active(&self) -> Result<std::sync::MutexGuard<'_, BTreeSet<String>>, RuntimeError> {
        self.active
            .lock()
            .map_err(|_| RuntimeError::StorageRepairRequired)
    }
}
struct Lease {
    root: Arc<Root>,
    key: String,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut active) = self.root.active.lock() {
            active.remove(&self.key);
        }
    }
}

/// Clones share the same protected root lock, operation lane and slot leases.
#[derive(Clone)]
pub struct EvidenceCache {
    root: Arc<Root>,
}
pub struct EvidenceSlot {
    lease: Arc<Lease>,
    directory: Directory,
    state: Manifest,
    poisoned: bool,
}
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct EvidenceCacheSummary {
    pub slots: usize,
    pub active_slots: usize,
    pub bytes: u64,
    pub max_slots: usize,
    pub max_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct EvidenceCacheHealth {
    pub summary: EvidenceCacheSummary,
    pub unresolved_writes: usize,
    pub invalid_records: usize,
    pub expired_slots: usize,
}

fn valid_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn sdk_files(directory: &Directory) -> Result<BTreeMap<String, u64>, RuntimeError> {
    let mut files = BTreeMap::new();
    for name in directory.names(2)? {
        let limit = match name.as_str() {
            "broker.sqlite3" => DATABASE_BYTES,
            "broker.sqlite3-journal" => JOURNAL_BYTES,
            _ => return Err(RuntimeError::ScopeDenied),
        };
        let file = directory.open_file(&name, OFlag::O_RDONLY, limit)?;
        files.insert(
            name,
            file.metadata()
                .map_err(|_| RuntimeError::ArtifactUnreadable)?
                .len(),
        );
    }
    Ok(files)
}
fn slot_files(directory: &Directory) -> Result<u64, RuntimeError> {
    let mut total = 0;
    for name in directory.names(3)? {
        match name.as_str() {
            "sdk" => {
                total += sdk_files(&directory.child("sdk", false)?)?
                    .values()
                    .sum::<u64>();
            }
            "state.json" | "state.next" => {
                let file = directory.open_file(&name, OFlag::O_RDONLY, STATE_BYTES)?;
                total += file
                    .metadata()
                    .map_err(|_| RuntimeError::ArtifactUnreadable)?
                    .len();
            }
            _ => return Err(RuntimeError::ScopeDenied),
        }
    }
    Ok(total)
}
fn load(directory: &Directory, key: &str) -> Result<Manifest, RuntimeError> {
    let state: Manifest = serde_json::from_slice(&directory.read("state.json")?)
        .map_err(|_| RuntimeError::StorageRepairRequired)?;
    state.validate(key)?;
    Ok(state)
}

impl EvidenceCache {
    /// Synthetic-only qualification has a separate root and quota. It cannot
    /// consume or clear user saved-evidence slots, even if that cache is full.
    pub(crate) fn qualification(home: &Path) -> Result<Self, RuntimeError> {
        let home = Directory::inspect(home)?;
        let assistance = home.child("context-assistance", true)?;
        Self::from_directory(assistance.child("qualification", true)?)
    }
    /// Only call after explicit private-persistence consent. This creates no
    /// SDK process and does not read any project source.
    pub fn open(home: &Path) -> Result<Self, RuntimeError> {
        let home = Directory::inspect(home)?;
        let assistance = home.child("context-assistance", true)?;
        let directory = assistance.child("saved-evidence", true)?;
        Self::from_directory(directory)
    }
    /// Read/repair path for an already existing cache, including while off.
    /// Absence stays absent; no directory or SDK process is created.
    pub fn existing(home: &Path) -> Result<Option<Self>, RuntimeError> {
        match std::fs::symlink_metadata(home) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(RuntimeError::ArtifactUnreadable),
            Ok(_) => {}
        }
        let home = Directory::inspect(home)?;
        if !home.names(1024)?.iter().any(|n| n == "context-assistance") {
            return Ok(None);
        }
        let assistance = home.child("context-assistance", false)?;
        if !assistance.names(64)?.iter().any(|n| n == "saved-evidence") {
            return Ok(None);
        }
        Self::from_directory(assistance.child("saved-evidence", false)?).map(Some)
    }
    fn from_directory(directory: Directory) -> Result<Self, RuntimeError> {
        let file = directory.open_file("cache.lock", OFlag::O_RDWR | OFlag::O_CREAT, 0)?;
        let lock =
            Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|_| RuntimeError::Busy)?;
        let result = Self {
            root: Arc::new(Root {
                directory,
                lock,
                active: Mutex::default(),
                operation: Mutex::default(),
            }),
        };
        result.summary()?;
        Ok(result)
    }
    /// A digest is a storage namespace, never a permission or source locator.
    pub fn key(
        app: &str,
        workspace: &Path,
        worker_fingerprint: &str,
    ) -> Result<String, RuntimeError> {
        if app.is_empty()
            || app.len() > 128
            || !valid_key(worker_fingerprint)
            || !app
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !workspace.is_absolute()
        {
            return Err(RuntimeError::RequestInvalid);
        }
        let bytes = serde_json::to_vec(&(app, workspace, worker_fingerprint))
            .map_err(|_| RuntimeError::RequestInvalid)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    fn keys(&self) -> Result<Vec<String>, RuntimeError> {
        self.root.check()?;
        let mut keys = Vec::new();
        for name in self.root.directory.names(MAX_SLOTS + 1)? {
            if name == "cache.lock" {
                continue;
            }
            if !valid_key(&name) {
                return Err(RuntimeError::ScopeDenied);
            }
            keys.push(name);
        }
        Ok(keys)
    }
    pub fn summary(&self) -> Result<EvidenceCacheSummary, RuntimeError> {
        let _operation = self.root.operation()?;
        self.summary_inner()
    }
    pub fn empty_summary() -> EvidenceCacheSummary {
        EvidenceCacheSummary {
            slots: 0,
            active_slots: 0,
            bytes: 0,
            max_slots: MAX_SLOTS,
            max_bytes: MAX_CACHE_BYTES,
        }
    }
    /// Native metadata only. No SDK probing or project source read is needed
    /// to report incomplete writes, corrupt records or saved-data expiry.
    pub fn health(&self, now: u64) -> Result<EvidenceCacheHealth, RuntimeError> {
        let _operation = self.root.operation()?;
        let mut result = EvidenceCacheHealth {
            summary: self.summary_inner()?,
            unresolved_writes: 0,
            invalid_records: 0,
            expired_slots: 0,
        };
        for key in self.keys()? {
            match load(&self.root.directory.child(&key, false)?, &key) {
                Ok(state) => {
                    if now < state.last_seen_ms {
                        result.invalid_records += 1;
                    }
                    if now >= state.expires_at_ms {
                        result.expired_slots += 1;
                    }
                    if state.intent.is_some() {
                        result.unresolved_writes += 1;
                    }
                }
                Err(RuntimeError::StorageRepairRequired) => result.invalid_records += 1,
                Err(error) => return Err(error),
            }
        }
        Ok(result)
    }
    fn summary_inner(&self) -> Result<EvidenceCacheSummary, RuntimeError> {
        let keys = self.keys()?;
        let mut bytes = 0;
        for key in &keys {
            bytes += slot_files(&self.root.directory.child(key, false)?)?;
        }
        if bytes > MAX_CACHE_BYTES {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(EvidenceCacheSummary {
            slots: keys.len(),
            active_slots: self.root.active()?.len(),
            bytes,
            max_slots: MAX_SLOTS,
            max_bytes: MAX_CACHE_BYTES,
        })
    }
    pub fn open_slot(
        &self,
        key: &str,
        retention_hours: u32,
        now: u64,
    ) -> Result<EvidenceSlot, RuntimeError> {
        let _operation = self.root.operation()?;
        if !valid_key(key) || !(1..=720).contains(&retention_hours) || now == 0 {
            return Err(RuntimeError::RequestInvalid);
        }
        self.sweep_inner(retention_hours, now)?;
        let keys = self.keys()?;
        let existed = keys.iter().any(|k| k == key);
        if !existed && keys.len() >= MAX_SLOTS {
            return Err(RuntimeError::ResourceLimit);
        }
        if !self.root.active()?.insert(key.into()) {
            return Err(RuntimeError::Busy);
        }
        let lease = Arc::new(Lease {
            root: Arc::clone(&self.root),
            key: key.into(),
        });
        let directory = self.root.directory.child(key, !existed)?;
        let mut state = if existed {
            load(&directory, key)?
        } else {
            Manifest::new(key, retention_hours, now)
        };
        state.observe(retention_hours, now)?;
        directory
            .write_state(&serde_json::to_vec(&state).map_err(|_| RuntimeError::RequestInvalid)?)?;
        directory.child("sdk", true)?;
        self.summary_inner()?;
        Ok(EvidenceSlot {
            lease,
            directory,
            state,
            poisoned: false,
        })
    }
    /// Inactive stores expire without opening the SDK. Active owners must close
    /// their domains before removal; a storage capability retains that lease.
    pub fn sweep(&self, retention_hours: u32, now: u64) -> Result<usize, RuntimeError> {
        let _operation = self.root.operation()?;
        self.sweep_inner(retention_hours, now)
    }
    fn sweep_inner(&self, retention_hours: u32, now: u64) -> Result<usize, RuntimeError> {
        if !(1..=720).contains(&retention_hours) || now == 0 {
            return Err(RuntimeError::RequestInvalid);
        }
        let mut removed = 0;
        for key in self.keys()? {
            if self.root.active()?.contains(&key) {
                continue;
            }
            let directory = self.root.directory.child(&key, false)?;
            slot_files(&directory)?;
            let names = directory.names(3)?;
            if names.iter().any(|n| n == "state.json") {
                let state = load(&directory, &key)?;
                if now < state.last_seen_ms {
                    return Err(RuntimeError::StorageRepairRequired);
                }
                if now
                    < state.expires_at_ms.min(
                        state
                            .created_at_ms
                            .saturating_add(u64::from(retention_hours) * 3_600_000),
                    )
                {
                    continue;
                }
            } else if names.iter().any(|n| n == "sdk")
                && !sdk_files(&directory.child("sdk", false)?)?.is_empty()
            {
                return Err(RuntimeError::StorageRepairRequired);
            }
            self.forget_inner(&key)?;
            removed += 1;
        }
        Ok(removed)
    }
    pub fn forget(&self, key: &str) -> Result<(), RuntimeError> {
        let _operation = self.root.operation()?;
        self.forget_inner(key)
    }
    fn forget_inner(&self, key: &str) -> Result<(), RuntimeError> {
        if !valid_key(key) {
            return Err(RuntimeError::RequestInvalid);
        }
        self.root.check()?;
        if self.root.active()?.contains(key) {
            return Err(RuntimeError::Busy);
        }
        let directory = self.root.directory.child(key, false)?;
        slot_files(&directory)?; // Validate the complete bounded tree before any removal.
        if directory.names(3)?.iter().any(|n| n == "sdk") {
            let sdk = directory.child("sdk", false)?;
            let files = sdk_files(&sdk)?;
            let owner = if files.contains_key("broker.sqlite3") {
                let file = sdk.open_file("broker.sqlite3", OFlag::O_RDWR, DATABASE_BYTES)?;
                fs::storage_owner(&file)?;
                Some(file)
            } else {
                None
            };
            for (name, _) in files {
                sdk.remove_file(
                    &name,
                    if name == "broker.sqlite3" {
                        DATABASE_BYTES
                    } else {
                        JOURNAL_BYTES
                    },
                )?;
            }
            drop(owner);
            directory.remove_child("sdk", &sdk)?;
        }
        for name in directory.names(2)? {
            directory.remove_file(&name, STATE_BYTES)?;
        }
        self.root.directory.remove_child(key, &directory)
    }
    pub fn forget_all(&self) -> Result<usize, RuntimeError> {
        let _operation = self.root.operation()?;
        if !self.root.active()?.is_empty() {
            return Err(RuntimeError::Busy);
        }
        self.summary_inner()?;
        let keys = self.keys()?;
        for key in &keys {
            self.forget_inner(key)?;
        }
        Ok(keys.len())
    }
}

#[cfg(test)]
#[path = "evidence_cache_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "evidence_cache_actual_tests.rs"]
mod actual_tests;
