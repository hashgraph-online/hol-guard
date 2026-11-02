//! Durable, bounded evidence preparation. No selection or SDK authority lives
//! here. Current and prior caches are preserved while a replacement is built.
use super::upgrade::producer_binding::EvidenceProducerBinding;
use super::*;
use crate::{
    BrokerDomainHandle, EvidenceUpgradeInventory, EvidenceUpgradeProducer, VerifiedRuntime,
};
use transfer::{TransferData, VerifiedNoteTransfer};

#[path = "evidence_generation_cleanup.rs"]
mod cleanup;
#[path = "evidence_generation_crypto.rs"]
mod crypto;
#[path = "evidence_generation_lifecycle.rs"]
mod lifecycle;
#[path = "evidence_generation_scope_erasure.rs"]
mod scope_erasure;
pub use scope_erasure::{EvidenceErasureScope, EvidenceScopeErasure};
#[path = "evidence_scope_ownership.rs"]
mod ownership;
pub use ownership::{EvidenceCacheLocation, EvidenceScopeOwner};
const MAX_GENERATIONS: usize = 3; // current, retained last-good, pending
const PAYLOAD_BYTES: usize = 1024 * 1024;
const RECORD_BYTES: u64 = 2 * 1024 * 1024;

#[path = "evidence_generation_deferred.rs"]
mod deferred;
#[path = "evidence_generation_prepare.rs"]
mod preparation;
#[path = "evidence_generation_record.rs"]
mod record;
use record::{Entry, Phase, Record};

fn request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
struct StoreRoot {
    directory: Directory,
    authority: crypto::Authority,
    home: PathBuf,
}
impl StoreRoot {
    fn lock(&self) -> Result<Locked, RuntimeError> {
        let file = self.directory.open_file("store.lock", Access::Write, 0)?;
        let lock = access::lock(file)?;
        self.authority.check()?;
        Ok(lock)
    }
    fn ids(&self) -> Result<Vec<String>, RuntimeError> {
        let mut ids = Vec::new();
        for name in self.directory.names(MAX_GENERATIONS + 2)? {
            if matches!(name.as_str(), "store.lock" | "authority.key") {
                continue;
            }
            if !valid_key(&name) {
                return Err(RuntimeError::StorageRepairRequired);
            }
            self.directory.child(&name, false)?;
            ids.push(name);
        }
        ids.sort();
        Ok(ids)
    }
}
pub struct EvidenceGenerationStore {
    root: Arc<StoreRoot>,
}
pub struct PreparedEvidenceGeneration {
    root: Arc<StoreRoot>,
    directory: Directory,
    id: String,
}
pub struct EvidencePreparation<'a> {
    pub request_id: &'a str,
    pub source: &'a EvidenceCache,
    pub snapshot: &'a EvidenceUpgradeInventory,
    pub from: &'a EvidenceUpgradeProducer,
    pub to: &'a EvidenceUpgradeProducer,
    pub notes: &'a [VerifiedNoteTransfer],
}
impl EvidenceGenerationStore {
    pub fn existing(home: &Path) -> Result<Option<Self>, RuntimeError> {
        match std::fs::symlink_metadata(home) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(RuntimeError::ArtifactUnreadable),
            Ok(_) => {}
        }
        let home_dir = Directory::inspect(home)?;
        if !home_dir
            .names(1024)?
            .iter()
            .any(|n| n == "context-assistance")
        {
            return Ok(None);
        }
        let assistance = home_dir.child("context-assistance", false)?;
        if !assistance
            .names(64)?
            .iter()
            .any(|n| n == "evidence-generations")
        {
            return Ok(None);
        }
        let directory = assistance.child("evidence-generations", false)?;
        let names = directory.names(MAX_GENERATIONS + 2)?;
        if !names.iter().any(|n| n == "authority.key") && names.iter().all(|n| n == "store.lock") {
            return Ok(None); // explicit forget left only the stable lock inode
        }
        Self::from_directory(directory, home, false).map(Some)
    }
    pub fn open(home: &Path) -> Result<Self, RuntimeError> {
        let assistance = Directory::inspect(home)?.child("context-assistance", true)?;
        Self::from_directory(assistance.child("evidence-generations", true)?, home, true)
    }
    fn from_directory(
        directory: Directory,
        home: &Path,
        provision: bool,
    ) -> Result<Self, RuntimeError> {
        let mode = if provision {
            Access::WriteOrCreate
        } else {
            Access::Write
        };
        let file = directory.open_file("store.lock", mode, 0)?;
        let _lock = access::lock(file)?;
        let authority = crypto::Authority::open(&directory, home, provision)?;
        let result = Self {
            root: Arc::new(StoreRoot {
                directory,
                authority,
                home: home.into(),
            }),
        };
        result.root.ids()?;
        Ok(result)
    }
    pub fn list(&self) -> Result<Vec<serde_json::Value>, RuntimeError> {
        let _lock = self.root.lock()?;
        self.root
            .ids()?
            .iter()
            .map(|id| self.load_locked(id)?.describe_locked())
            .collect()
    }
    fn load_locked(&self, id: &str) -> Result<PreparedEvidenceGeneration, RuntimeError> {
        if !valid_key(id) {
            return Err(RuntimeError::RequestInvalid);
        }
        let directory = self.root.directory.child(id, false)?;
        self.root.authority.read(&directory, id)?;
        Ok(PreparedEvidenceGeneration {
            root: Arc::clone(&self.root),
            directory,
            id: id.into(),
        })
    }
    pub fn load(&self, id: &str) -> Result<PreparedEvidenceGeneration, RuntimeError> {
        let _lock = self.root.lock()?;
        self.load_locked(id)
    }
}
impl PreparedEvidenceGeneration {
    pub fn id(&self) -> &str {
        &self.id
    }
    fn read(&self) -> Result<Record, RuntimeError> {
        self.root.authority.read(&self.directory, &self.id)
    }
    fn describe_locked(&self) -> Result<serde_json::Value, RuntimeError> {
        let record = self.read()?;
        Ok(
            serde_json::json!({"schema":"guard-cigar-data-generation-summary.v1","generation_id":record.generation_id,
            "request_id":record.request_id,"phase":record.phase,"source_producer_sha256":record.source_producer_sha256,
            "target_producer_sha256":record.target_producer_sha256,"source_release":record.source_release,"target_release":record.target_release,
            "deferred_scopes":record.entries.iter().filter(|e|matches!(e,Entry::Deferred{..})).count(),
            "scopes":record.entries.len(),"pending_scopes":record.entries.iter().filter(|e|matches!(e, Entry::Pending{..})).count(),
            "preserved_unmapped_scopes":record.preserved_source_keys.len(),"authority_restored":false}),
        )
    }
    pub fn describe(&self) -> Result<serde_json::Value, RuntimeError> {
        let _lock = self.root.lock()?;
        self.describe_locked()
    }
    /// Complete authenticated staged data, returned only as a digest.
    pub fn semantic_sha256(&self) -> Result<String, RuntimeError> {
        let _lock = self.root.lock()?;
        let bytes = serde_json::to_vec(&("guard-cigar-generation-semantic.v1", self.read()?))
            .map_err(|_| RuntimeError::RequestInvalid)?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    pub fn transfer(
        &self,
        scope: &EvidenceScope,
        target: &EvidenceUpgradeProducer,
        now: u64,
    ) -> Result<VerifiedNoteTransfer, RuntimeError> {
        let _lock = self.root.lock()?;
        let record = self.read()?;
        if record.phase == Phase::Preparing
            || record.target_producer_sha256 != target.identity_sha256()
        {
            return Err(RuntimeError::ContextConflict);
        }
        let entry = record
            .entries
            .iter()
            .find(|e| e.scope() == scope.namespace_sha256())
            .ok_or(RuntimeError::ScopeDenied)?;
        match entry {
            Entry::Pending { transfer } | Entry::Deferred { transfer } => {
                transfer.validate(now)?;
                Ok(VerifiedNoteTransfer {
                    data: (**transfer).clone(),
                })
            }
            _ => Err(RuntimeError::ContextConflict),
        }
    }
    pub fn open_cache(&self) -> Result<EvidenceCache, RuntimeError> {
        let _lock = self.root.lock()?;
        if self.read()?.phase == Phase::Preparing {
            return Err(RuntimeError::ContextConflict);
        }
        EvidenceCache::from_directory(self.directory.child("cache", true)?)
    }
    pub fn finish_scope(
        &self,
        scope: &EvidenceScope,
        target: &EvidenceUpgradeProducer,
        slot: &EvidenceSlot,
        runtime: &mut VerifiedRuntime,
        domain: &BrokerDomainHandle,
        now: u64,
    ) -> Result<(), RuntimeError> {
        let proof = slot.export_reviewed_notes(scope, target, runtime, domain, now)?;
        let _lock = self.root.lock()?;
        let mut record = self.read()?;
        if slot.directory.path.parent() != Some(self.directory.path.join("cache").as_path())
            || record.target_producer_sha256 != target.identity_sha256()
            || record.phase == Phase::Preparing
        {
            return Err(RuntimeError::ScopeDenied);
        }
        let entry = record
            .entries
            .iter_mut()
            .find(|e| e.scope() == scope.namespace_sha256())
            .ok_or(RuntimeError::ScopeDenied)?;
        let actual = proof
            .data
            .notes
            .as_ref()
            .map_or(&[][..], |n| n.documents.as_slice());
        if let Entry::Imported {
            target_key,
            target_notes_version,
            notes_sha256,
            expires_at_ms,
            ..
        } = entry
        {
            return if target_key == &slot.lease.key
                && target_notes_version == slot.notes_version()
                && notes_sha256 == &records::documents_hash(actual)?
                && proof.data.expires_at_ms <= *expires_at_ms
            {
                Ok(())
            } else {
                Err(RuntimeError::ContextConflict)
            };
        }
        let deferred = entry.deferred();
        let (Entry::Pending { transfer } | Entry::Deferred { transfer }) = entry else {
            return Err(RuntimeError::ContextConflict);
        };
        let expected = transfer
            .notes
            .as_ref()
            .map_or(&[][..], |n| n.documents.as_slice());
        if records::documents_hash(expected)? != records::documents_hash(actual)?
            || transfer.basis_sha256 != proof.data.basis_sha256
            || proof.data.expires_at_ms > transfer.expires_at_ms
        {
            return Err(RuntimeError::ContextConflict);
        }
        *entry = Entry::Imported {
            original_producer: deferred.then(|| transfer.source_producer_sha256.clone()),
            original_release: deferred.then(|| transfer.source_release.clone()),
            scope_sha256: transfer.scope_sha256.clone(),
            source_key: transfer.source_key.clone(),
            source_manifest_sha256: transfer.source_manifest_sha256.clone(),
            source_notes_version: transfer.source_notes_version.clone(),
            target_key: slot.lease.key.clone(),
            target_notes_version: slot.notes_version().into(),
            notes_sha256: records::documents_hash(actual)?,
            notes: actual.len(),
            expires_at_ms: proof.data.expires_at_ms,
        };
        if !record
            .entries
            .iter()
            .any(|e| matches!(e, Entry::Pending { .. }))
        {
            record.phase = Phase::Ready;
        }
        self.directory
            .write_state_limit(&self.root.authority.seal(&record)?, RECORD_BYTES)
    }
}
