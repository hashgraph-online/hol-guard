//! SDK-proven or MAC-carried reviewed data; never stored source grants.
use super::*;
impl EvidenceGenerationStore {
    pub fn prepare(
        &self,
        request: EvidencePreparation<'_>,
        now: u64,
    ) -> Result<PreparedEvidenceGeneration, RuntimeError> {
        self.prepare_inner(request, now, false)
    }
    /// Cold selection seals data now. Target admission remains pending until
    /// a future explicit app/source grant proves the original basis again.
    pub fn prepare_cold(
        &self,
        request: EvidencePreparation<'_>,
        now: u64,
    ) -> Result<PreparedEvidenceGeneration, RuntimeError> {
        self.prepare_inner(request, now, true)
    }
    fn prepare_inner(
        &self,
        request: EvidencePreparation<'_>,
        now: u64,
        cold: bool,
    ) -> Result<PreparedEvidenceGeneration, RuntimeError> {
        if !request_id(request.request_id) || request.notes.len() > MAX_SLOTS || now == 0 {
            return Err(RuntimeError::RequestInvalid);
        }
        let metadata_only = request.notes.is_empty();
        if !request.from.metadata_preparation_qualified()
            || !request.to.metadata_preparation_qualified()
            || (!metadata_only
                && (!request.from.data_preparation_qualified()
                    || !request.to.data_preparation_qualified()))
        {
            return Err(RuntimeError::ReleaseUnqualified);
        }
        let _lock = self.root.lock()?;
        let mut inherited = Vec::new();
        let source_generation = if request.source.root.directory.path
            == self.root.home.join("context-assistance/saved-evidence")
        {
            None
        } else {
            let relative = request
                .source
                .root
                .directory
                .path
                .strip_prefix(&self.root.directory.path)
                .map_err(|_| RuntimeError::ScopeDenied)?;
            let components: Vec<_> = relative.components().collect();
            if components.len() != 2 || components[1].as_os_str() != "cache" {
                return Err(RuntimeError::ScopeDenied);
            }
            let id = components[0]
                .as_os_str()
                .to_str()
                .filter(|s| valid_key(s))
                .ok_or(RuntimeError::ScopeDenied)?;
            let source = self.load_locked(id)?;
            let record = self.root.authority.read(&source.directory, id)?;
            if record.phase != Phase::Ready
                || record.target_producer_sha256 != request.from.identity_sha256()
            {
                return Err(RuntimeError::ScopeDenied);
            }
            inherited = deferred::inherited(&source, &record, request.source, now)?;
            Some(id.into())
        };
        if request.source.upgrade_inventory(now)?.snapshot_sha256()
            != request.snapshot.snapshot_sha256()
        {
            return Err(RuntimeError::ContextStale);
        }
        if !inherited.is_empty()
            && (!request.from.data_preparation_qualified()
                || !request.to.data_preparation_qualified())
        {
            return Err(RuntimeError::ReleaseUnqualified);
        }
        let mut entries = Vec::new();
        let mut keys = BTreeSet::new();
        let mut scopes = BTreeSet::new();
        for note in request.notes {
            note.data.validate(now)?;
            if note.data.source_producer_sha256 != request.from.identity_sha256()
                || note.data.source_release != request.from.release_binding()?
                || !keys.insert(note.data.source_key.clone())
            {
                return Err(RuntimeError::ContextConflict);
            }
            let directory = request
                .source
                .root
                .directory
                .child(&note.data.source_key, false)?;
            if format!("{:x}", Sha256::digest(directory.read("state.json")?))
                != note.data.source_manifest_sha256
            {
                return Err(RuntimeError::ContextStale);
            }
            if inherited
                .iter()
                .any(|e| e.scope() == note.data.scope_sha256)
            {
                if note.data.notes.is_some()
                    || note.data.source_notes_version != "0"
                    || !note.data.basis_sha256.is_empty()
                {
                    return Err(RuntimeError::StorageRepairRequired);
                }
                continue;
            }
            if !scopes.insert(note.data.scope_sha256.clone()) {
                return Err(RuntimeError::ContextConflict);
            }
            entries.push(if cold {
                Entry::Deferred {
                    transfer: Box::new(note.data.clone()),
                }
            } else {
                Entry::Pending {
                    transfer: Box::new(note.data.clone()),
                }
            });
        }
        if cold && !request.snapshot.only_expired_unmapped(&keys) {
            return Err(RuntimeError::StorageRepairRequired);
        }
        for entry in inherited {
            if !scopes.insert(entry.scope().to_owned()) {
                return Err(RuntimeError::StorageRepairRequired);
            }
            entries.push(entry);
        }
        entries.sort_by(|a, b| a.scope().cmp(b.scope()));
        let deferred_binding = cold || entries.iter().any(|e| matches!(e, Entry::Deferred { .. }));
        let binding: Vec<_> = entries
            .iter()
            .map(|e| match e {
                Entry::Pending { transfer } | Entry::Deferred { transfer } => {
                    let mut parts = vec![
                        serde_json::json!(transfer.scope_sha256),
                        serde_json::json!(transfer.source_manifest_sha256),
                    ];
                    if deferred_binding {
                        parts.push(serde_json::json!(VerifiedNoteTransfer {
                            data: (**transfer).clone()
                        }
                        .semantic_sha256()?));
                    }
                    Ok(parts)
                }
                _ => unreachable!(),
            })
            .collect::<Result<Vec<_>, RuntimeError>>()?;
        let id = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(
                    if cold {
                        "guard-cigar-cold-data-generation.v2"
                    } else if deferred_binding {
                        "guard-cigar-deferred-data-generation.v1"
                    } else {
                        "guard-cigar-data-generation.v1"
                    },
                    request.request_id,
                    request.snapshot.snapshot_sha256(),
                    request.from.identity_sha256(),
                    request.to.identity_sha256(),
                    binding
                ))
                .map_err(|_| RuntimeError::RequestInvalid)?
            )
        );
        let ids = self.root.ids()?;
        for existing in &ids {
            let generation = self.load_locked(existing)?;
            let record = self.root.authority.read(&generation.directory, existing)?;
            if record.request_id == request.request_id {
                if existing != &id || record.phase == Phase::Preparing {
                    return Err(RuntimeError::ContextConflict);
                }
                return Ok(generation);
            }
        }
        if ids.len() >= MAX_GENERATIONS {
            return Err(RuntimeError::ResourceLimit);
        }
        let directory = self.root.directory.child(&id, true)?;
        if !directory.names(1)?.is_empty() {
            return Err(RuntimeError::StorageRepairRequired);
        }
        let mut record = Record {
            schema: "guard-cigar-prepared-evidence.v1".into(),
            generation_id: id.clone(),
            request_id: request.request_id.into(),
            source_generation,
            source_snapshot_sha256: request.snapshot.snapshot_sha256().into(),
            source_producer_sha256: request.from.identity_sha256().into(),
            target_producer_sha256: request.to.identity_sha256().into(),
            source_release: request.from.release_binding()?,
            target_release: request.to.release_binding()?,
            created_at_ms: now,
            phase: Phase::Preparing,
            entries,
            preserved_source_keys: if cold {
                Vec::new()
            } else {
                request
                    .snapshot
                    .slot_keys()
                    .into_iter()
                    .filter(|key| !keys.contains(key))
                    .collect()
            },
        };
        directory.write_state_limit(&self.root.authority.seal(&record)?, RECORD_BYTES)?;
        if request.source.upgrade_inventory(now)?.snapshot_sha256()
            != request.snapshot.snapshot_sha256()
        {
            return Err(RuntimeError::ContextStale);
        }
        record.phase = if !record
            .entries
            .iter()
            .any(|e| matches!(e, Entry::Pending { .. }))
        {
            Phase::Ready
        } else {
            Phase::Prepared
        };
        directory.write_state_limit(&self.root.authority.seal(&record)?, RECORD_BYTES)?;
        Ok(PreparedEvidenceGeneration {
            root: Arc::clone(&self.root),
            directory,
            id,
        })
    }
}
