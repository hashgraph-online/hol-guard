//! One private lock and durable append per bounded evidence batch.

use super::*;

impl NativeEvidenceJournal {
    pub(super) fn append_records(
        &self,
        path: &Path,
        records: &[&EvidenceRecord],
    ) -> Result<(), io::Error> {
        self.append_records_then(path, records, |file| file.sync_all())
    }

    pub(super) fn append_records_then(
        &self,
        path: &Path,
        records: &[&EvidenceRecord],
        sync_journal: impl FnOnce(&File) -> Result<(), io::Error>,
    ) -> Result<(), io::Error> {
        if records.is_empty() {
            return Ok(());
        }
        let _lock = JournalLock::acquire(path)?;
        let mut body = Vec::new();
        let mut previews = Vec::new();
        for record in records {
            body.extend_from_slice(&record.serialized());
            if let EvidenceRecord::CommandActivity(activity) = record {
                if let Some(preview) =
                    validated_sidecar_preview(activity.invocation_preview.as_deref())
                {
                    previews.extend_from_slice(&sidecar_line(&activity.record_id, &preview));
                }
            }
        }
        let mut file = open_journal_append(path)?;
        let original_size = file.metadata()?.len();
        // Open and verify both destinations before changing either. The same
        // lock covers previews, rollback and the journal's final fsync.
        let mut sidecar = if previews.is_empty() {
            None
        } else {
            let file = open_journal_append(&preview_sidecar_path(path))?;
            let original = file.metadata()?.len();
            Some((file, original))
        };
        let appended = (|| {
            file.write_all(&body)?;
            if let Some((preview_file, _)) = sidecar.as_mut() {
                preview_file.write_all(&previews)?;
                preview_file.sync_all()?;
            }
            sync_journal(&file)
        })();
        if let Err(error) = appended {
            // A failed append has the same fate for every record. Preserve
            // any earlier journal/preview prefix and make rollback durable.
            let preview_rollback = sidecar
                .as_mut()
                .map(|(file, original)| file.set_len(*original).and_then(|()| file.sync_all()));
            let journal_rollback = file.set_len(original_size).and_then(|()| file.sync_all());
            journal_rollback?;
            if let Some(result) = preview_rollback {
                result?;
            }
            return Err(error);
        }
        Ok(())
    }
}
