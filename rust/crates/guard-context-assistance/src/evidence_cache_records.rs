use super::*;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SavedNotes {
    pub documents: Vec<ContextDocument>,
    pub basis: BTreeSet<String>,
    pub version: String,
    pub valid_until_ms: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    pub(super) expected_version: String,
    pub(super) documents_sha256: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    schema: u32,
    key: String,
    pub(super) created_at_ms: u64,
    pub(super) expires_at_ms: u64,
    pub(super) last_seen_ms: u64,
    pub(super) notes_version: String,
    pub(super) notes: Option<SavedNotes>,
    pub(super) intent: Option<Intent>,
}
pub(crate) fn version(value: &str) -> Result<u64, RuntimeError> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(RuntimeError::StorageRepairRequired);
    }
    value
        .parse()
        .map_err(|_| RuntimeError::StorageRepairRequired)
}
pub(crate) fn documents_hash(documents: &[ContextDocument]) -> Result<String, RuntimeError> {
    if documents.len() > 32 || documents.iter().any(|d| !d.id.starts_with("note:")) {
        return Err(RuntimeError::RequestInvalid);
    }
    let docs = crate::broker::documents(documents.to_vec(), 16 * 1024)?;
    let bytes = serde_json::to_vec(&docs.values().collect::<Vec<_>>())
        .map_err(|_| RuntimeError::RequestInvalid)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
pub(crate) fn source_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "guard:notes"
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_:-".contains(&b))
}
impl Manifest {
    pub(super) fn new(key: &str, retention: u32, now: u64) -> Self {
        Self {
            schema: 1,
            key: key.into(),
            created_at_ms: now,
            expires_at_ms: now.saturating_add(u64::from(retention) * 3_600_000),
            last_seen_ms: now,
            notes_version: "0".into(),
            notes: None,
            intent: None,
        }
    }
    pub(super) fn validate(&self, key: &str) -> Result<(), RuntimeError> {
        if self.schema != 1
            || self.key != key
            || !valid_key(key)
            || self.created_at_ms == 0
            || self.last_seen_ms < self.created_at_ms
            || self.last_seen_ms >= self.expires_at_ms
            || self.expires_at_ms <= self.created_at_ms
            || self.expires_at_ms > self.created_at_ms.saturating_add(720 * 3_600_000)
        {
            return Err(RuntimeError::StorageRepairRequired);
        }
        version(&self.notes_version)?;
        if let Some(notes) = &self.notes {
            documents_hash(&notes.documents).map_err(|_| RuntimeError::StorageRepairRequired)?;
            if notes.version != self.notes_version
                || notes.version == "0"
                || notes.documents.is_empty()
                || notes.basis.len() > 32
                || notes.basis.iter().any(|s| !source_id(s))
                || notes.valid_until_ms <= self.created_at_ms
                || notes.valid_until_ms > self.expires_at_ms
            {
                return Err(RuntimeError::StorageRepairRequired);
            }
        }
        if let Some(intent) = &self.intent {
            if intent.expected_version != self.notes_version || !valid_key(&intent.documents_sha256)
            {
                return Err(RuntimeError::StorageRepairRequired);
            }
        }
        Ok(())
    }
    pub(super) fn observe(&mut self, retention: u32, now: u64) -> Result<(), RuntimeError> {
        if now < self.last_seen_ms {
            return Err(RuntimeError::StorageRepairRequired);
        }
        self.expires_at_ms = self.expires_at_ms.min(
            self.created_at_ms
                .saturating_add(u64::from(retention) * 3_600_000),
        );
        if now >= self.expires_at_ms {
            return Err(RuntimeError::ContextStale);
        }
        if let Some(notes) = &mut self.notes {
            notes.valid_until_ms = notes.valid_until_ms.min(self.expires_at_ms);
        }
        self.last_seen_ms = now;
        Ok(())
    }
    pub(super) fn committed_hash(&self) -> Result<Option<String>, RuntimeError> {
        if self.notes_version == "0" {
            return Ok(None);
        }
        documents_hash(self.notes.as_ref().map_or(&[], |n| n.documents.as_slice())).map(Some)
    }
}
