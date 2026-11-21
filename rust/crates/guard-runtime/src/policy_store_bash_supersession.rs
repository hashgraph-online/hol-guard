//! Retire only authenticated, never-reserved pending versions. No grant is
//! rewritten, no completed call advances, and Keep blocked remains sticky.
use super::BashOperationJournal;

impl BashOperationJournal<'_> {
    pub(crate) fn retire_unstarted_review(
        &self,
        operation_id: &str,
        artifact_hash: &str,
        harness: &str,
        project: &str,
    ) -> rusqlite::Result<bool> {
        let invalid = || rusqlite::Error::InvalidQuery;
        if self.connection.is_autocommit()
            || Self::read_authenticated(&self.connection, self.store, operation_id)?.is_some()
        {
            return Err(invalid());
        }
        let mut record =
            Self::read_review_in(&self.connection, self.store, operation_id, artifact_hash)?
                .ok_or_else(invalid)?;
        if record.harness != harness || record.project != project {
            return Err(invalid());
        }
        let resolution = self.refresh_review(&mut record)?;
        if record.blocked {
            return Ok(false);
        }
        if let Some((request_id, action)) = resolution {
            if action == "pending" {
                let changed = self.connection.execute(
                    "UPDATE approval_requests SET status='expired',
                     resolved_at=strftime('%Y-%m-%dT%H:%M:%f+00:00','now'),
                     resolution_action=NULL,resolution_scope=NULL,
                     reason='Expired because the reviewed invocation changed before execution.'
                     WHERE request_id=?1 AND status='pending'",
                    [request_id],
                )?;
                if changed != 1 {
                    return Err(invalid());
                }
            }
        }
        // Retain signed retirement authority: restoring an old lifetime row
        // or losing another journal row must not reactivate an old review.
        // No existing consent is transplanted into the new generation.
        record.superseded = true;
        self.write_review(&record)?;
        Ok(true)
    }
}
