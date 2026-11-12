use super::*;

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Phase {
    Preparing,
    Prepared,
    Ready,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Entry {
    Pending {
        transfer: Box<TransferData>,
    },
    Deferred {
        transfer: Box<TransferData>,
    },
    Imported {
        scope_sha256: String,
        source_key: String,
        source_manifest_sha256: String,
        source_notes_version: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_producer: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        original_release: Option<EvidenceProducerBinding>,
        target_key: String,
        target_notes_version: String,
        notes_sha256: String,
        notes: usize,
        expires_at_ms: u64,
    },
    Expired {
        #[serde(default, skip_serializing_if = "is_false")]
        deferred: bool,
        scope_sha256: String,
        source_key: String,
        expires_at_ms: u64,
    },
}
fn is_false(value: &bool) -> bool {
    !*value
}
impl Entry {
    pub(super) fn deferred(&self) -> bool {
        match self {
            Self::Deferred { .. } => true,
            Self::Imported {
                original_producer, ..
            } => original_producer.is_some(),
            Self::Expired { deferred, .. } => *deferred,
            _ => false,
        }
    }
    pub(super) fn source_key(&self) -> &str {
        match self {
            Self::Pending { transfer } | Self::Deferred { transfer } => &transfer.source_key,
            Self::Imported { source_key, .. } | Self::Expired { source_key, .. } => source_key,
        }
    }
    pub(super) fn scope(&self) -> &str {
        match self {
            Self::Pending { transfer } | Self::Deferred { transfer } => &transfer.scope_sha256,
            Self::Imported { scope_sha256, .. } | Self::Expired { scope_sha256, .. } => {
                scope_sha256
            }
        }
    }
    pub(super) fn expires(&self) -> u64 {
        match self {
            Self::Pending { transfer } | Self::Deferred { transfer } => transfer.expires_at_ms,
            Self::Imported { expires_at_ms, .. } | Self::Expired { expires_at_ms, .. } => {
                *expires_at_ms
            }
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Record {
    pub(super) schema: String,
    pub(super) generation_id: String,
    pub(super) request_id: String,
    pub(super) source_generation: Option<String>,
    pub(super) source_snapshot_sha256: String,
    pub(super) source_producer_sha256: String,
    pub(super) target_producer_sha256: String,
    pub(super) source_release: EvidenceProducerBinding,
    pub(super) target_release: EvidenceProducerBinding,
    pub(super) created_at_ms: u64,
    pub(super) phase: Phase,
    pub(super) entries: Vec<Entry>,
    pub(super) preserved_source_keys: Vec<String>,
}
impl Record {
    pub(super) fn validate(&self) -> Result<(), RuntimeError> {
        if self.schema != "guard-cigar-prepared-evidence.v1"
            || !request_id(&self.request_id)
            || [
                &self.generation_id,
                &self.source_snapshot_sha256,
                &self.source_producer_sha256,
                &self.target_producer_sha256,
            ]
            .iter()
            .any(|s| !valid_key(s))
            || self
                .source_generation
                .as_ref()
                .is_some_and(|s| !valid_key(s))
            || self.created_at_ms == 0
            || self.source_release.validate().is_err()
            || self.target_release.validate().is_err()
            || (self.entries.is_empty() && self.phase == Phase::Prepared)
            || self.entries.len() > MAX_SLOTS
            || self.preserved_source_keys.len() > MAX_SLOTS
            || self.preserved_source_keys.iter().any(|s| !valid_key(s))
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        let mut scopes = BTreeSet::new();
        for entry in &self.entries {
            if !valid_key(entry.scope()) || !scopes.insert(entry.scope()) || entry.expires() == 0 {
                return Err(RuntimeError::StorageRepairRequired);
            }
            match entry {
                Entry::Pending { transfer } => {
                    transfer.validate(transfer.captured_at_ms)?;
                    if transfer.source_producer_sha256 != self.source_producer_sha256
                        || transfer.source_release != self.source_release
                        || self.phase == Phase::Ready
                    {
                        return Err(RuntimeError::StorageRepairRequired);
                    }
                }
                Entry::Deferred { transfer } => {
                    transfer.validate(transfer.captured_at_ms)?;
                }
                Entry::Imported {
                    original_producer,
                    original_release,
                    source_key,
                    source_manifest_sha256,
                    source_notes_version,
                    target_key,
                    target_notes_version,
                    notes_sha256,
                    notes,
                    ..
                } => {
                    if [source_key, source_manifest_sha256, target_key, notes_sha256]
                        .iter()
                        .any(|s| !valid_key(s))
                        || *notes > 32
                        || transfer::target_key(entry.scope(), &self.target_producer_sha256)?
                            != *target_key
                    {
                        return Err(RuntimeError::StorageRepairRequired);
                    }
                    if original_producer.is_some() != original_release.is_some()
                        || original_producer.as_deref().is_some_and(|s| !valid_key(s))
                        || original_release
                            .as_ref()
                            .is_some_and(|r| r.validate().is_err())
                    {
                        return Err(RuntimeError::StorageRepairRequired);
                    }
                    records::version(source_notes_version)?;
                    records::version(target_notes_version)?;
                }
                Entry::Expired { source_key, .. } if !valid_key(source_key) => {
                    return Err(RuntimeError::StorageRepairRequired)
                }
                _ => {}
            }
        }
        Ok(())
    }
}
