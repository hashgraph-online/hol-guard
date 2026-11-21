//! Native-issued review lineage in the existing store, never an allow token.

use guard_contracts::{ClaimApprovalReuseDecisionsRequestV1, NativeBashReviewLineageV1};
use guard_policy_snapshot::local_authority_integrity::verify_local_authority_payload;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};

use super::BashOperationJournal;

#[path = "policy_store_bash_supersession.rs"]
mod supersession;

const PURPOSE: &str = "guard-native-bash-review-lineage-v1";
const SCHEMA: &str = "guard-native-bash-review-lineage.v1";
const LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    lineage: NativeBashReviewLineageV1,
    harness: String,
    project: String,
    request_id: Option<String>,
    blocked: bool,
    #[serde(default)]
    superseded: bool,
}

impl BashOperationJournal<'_> {
    pub(crate) fn verify_pending_request(
        &self,
        request_id: &str,
        harness: &str,
        command: &str,
        descriptor: &guard_contracts::NativeBashReviewDescriptorV1,
    ) -> rusqlite::Result<()> {
        self.review_transaction(|| {
            let Some(mut record) = self.read_review()? else {
                return Err(rusqlite::Error::InvalidQuery);
            };
            if record.blocked
                || record.lineage != descriptor.review_lineage
                || record.harness != harness
                || record.project != descriptor.subject.context.project
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let row: Option<(String, String, String)> = self
                .connection
                .query_row(
                    "SELECT artifact_type,raw_command_text,
                 CASE WHEN length(action_envelope_json)<=1048576 THEN action_envelope_json END
                 FROM approval_requests WHERE request_id=?1 AND status='pending'",
                    [request_id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            let Some((kind, stored_command, envelope)) = row else {
                return Err(rusqlite::Error::InvalidQuery);
            };
            let envelope: serde_json::Value =
                serde_json::from_str(&envelope).map_err(|_| rusqlite::Error::InvalidQuery)?;
            let stored: guard_contracts::NativeBashReviewDescriptorV1 = serde_json::from_value(
                envelope
                    .get("native_bash")
                    .cloned()
                    .ok_or(rusqlite::Error::InvalidQuery)?,
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
            if kind != guard_contracts::NATIVE_BASH_REVIEW_ARTIFACT_TYPE
                || stored_command != command
                || stored != *descriptor
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            if self.refresh_review(&mut record)? != Some((request_id.into(), "pending".into())) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(())
        })
    }

    fn read_review(&self) -> rusqlite::Result<Option<Record>> {
        Self::read_review_in(
            &self.connection,
            self.store,
            self.operation_id,
            self.artifact_hash,
        )
    }

    fn read_review_in(
        connection: &rusqlite::Connection,
        store: &crate::policy_store::PolicySnapshotStore,
        operation_id: &str,
        artifact_hash: &str,
    ) -> rusqlite::Result<Option<Record>> {
        Self::require_authority_for(store)?;
        let row: Option<(Option<String>, Option<String>)> = connection
            .query_row(
                "SELECT CASE WHEN length(payload)<=16384 THEN payload END,
             CASE WHEN length(integrity)<=4096 THEN integrity END
             FROM guard_bash_reviews WHERE operation_id=?1",
                [operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((Some(payload), Some(integrity))) = row else {
            return if row.is_none() {
                Ok(None)
            } else {
                Err(rusqlite::Error::InvalidQuery)
            };
        };
        let invalid = |_| rusqlite::Error::InvalidQuery;
        let payload = serde_json::from_str(&payload).map_err(invalid)?;
        let integrity = serde_json::from_str(&integrity).map_err(invalid)?;
        let key_id = guard_policy_snapshot::verifier_key_id(&store.verifier_key);
        if verify_local_authority_payload(
            &payload,
            &integrity,
            Some(&store.verifier_key),
            Some(&key_id),
            PURPOSE,
        )
        .status
            != "valid"
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let record: Record = serde_json::from_value(payload).map_err(invalid)?;
        let now = crate::policy_store::now_ms().map_err(|_| rusqlite::Error::InvalidQuery)?;
        let lineage = &record.lineage;
        if record.superseded
            || lineage.schema != SCHEMA
            || lineage.operation_id != operation_id
            || lineage.artifact_hash != artifact_hash
            || lineage.lineage_id.len() != 64
            || !lineage
                .lineage_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || lineage.created_at_ms > now
            || lineage.expires_at_ms < now
            || lineage.created_at_ms.checked_add(LIFETIME_MS) != Some(lineage.expires_at_ms)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(Some(record))
    }

    pub(crate) fn descriptor_is_backed(
        connection: &rusqlite::Connection,
        store: &crate::policy_store::PolicySnapshotStore,
        request_id: &str,
        harness: &str,
        command: &str,
        descriptor: &guard_contracts::NativeBashReviewDescriptorV1,
    ) -> rusqlite::Result<bool> {
        let Some(record) = Self::read_review_in(
            connection,
            store,
            &descriptor.review_lineage.operation_id,
            &descriptor.artifact_hash,
        )?
        else {
            return Ok(false);
        };
        if record.blocked
            || record.lineage != descriptor.review_lineage
            || record.harness != harness
            || record.project != descriptor.subject.context.project
            || record
                .request_id
                .as_deref()
                .is_some_and(|id| id != request_id)
        {
            return Ok(false);
        }
        let matches: i64 = connection.query_row(
            "SELECT count(*) FROM (SELECT 1 FROM approval_requests WHERE harness=?1 AND artifact_id=?2
             AND artifact_hash=?3 AND workspace IS ?4
             AND json_extract(action_envelope_json,'$.native_bash.review_lineage.lineage_id')=?5 LIMIT 2)",
            params![harness,guard_contracts::NATIVE_BASH_ARTIFACT_ID,descriptor.artifact_hash,record.project,
                descriptor.review_lineage.lineage_id], |row| row.get(0),
        )?;
        if matches != 1 {
            return Ok(false);
        }
        // Scope projection also presents a resolved allow. This read grants
        // nothing: pending-request verification and authenticated consent
        // consumption remain separate execution checks.
        let row: Option<(String, String, String)> = connection
            .query_row(
                "SELECT artifact_type,raw_command_text,
             CASE WHEN length(action_envelope_json)<=1048576 THEN action_envelope_json END
             FROM approval_requests WHERE request_id=?1
             AND (status='pending' OR (status='resolved' AND resolution_action='allow')) AND harness=?2
             AND artifact_id=?3 AND artifact_hash=?4 AND workspace IS ?5",
                params![
                    request_id,
                    harness,
                    guard_contracts::NATIVE_BASH_ARTIFACT_ID,
                    descriptor.artifact_hash,
                    record.project
                ],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((kind, stored_command, envelope)) = row else {
            return Ok(false);
        };
        let envelope: serde_json::Value =
            serde_json::from_str(&envelope).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let stored: guard_contracts::NativeBashReviewDescriptorV1 = serde_json::from_value(
            envelope
                .get("native_bash")
                .cloned()
                .ok_or(rusqlite::Error::InvalidQuery)?,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
        Ok(kind == guard_contracts::NATIVE_BASH_REVIEW_ARTIFACT_TYPE
            && stored_command == command
            && stored == *descriptor)
    }

    fn write_review(&self, record: &Record) -> rusqlite::Result<()> {
        if self.connection.is_autocommit() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let (payload, integrity) = self.seal(record, PURPOSE)?;
        self.connection.execute(
            "INSERT INTO guard_bash_reviews(operation_id,payload,integrity) VALUES(?1,?2,?3)
             ON CONFLICT(operation_id) DO UPDATE SET payload=excluded.payload,integrity=excluded.integrity",
            params![record.lineage.operation_id, payload, integrity],
        )?;
        Ok(())
    }

    fn review_transaction<T>(
        &self,
        action: impl FnOnce() -> rusqlite::Result<T>,
    ) -> rusqlite::Result<T> {
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        match action() {
            Ok(value) => {
                self.connection.execute_batch("COMMIT")?;
                Ok(value)
            }
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    pub(crate) fn pending_review(
        &self,
        harness: &str,
        project: &str,
    ) -> rusqlite::Result<NativeBashReviewLineageV1> {
        self.review_transaction(|| {
            if let Some(record) = self.read_review()? {
                if record.harness != harness || record.project != project || record.blocked {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                return Ok(record.lineage);
            }
            let mut nonce = [0u8; 32];
            getrandom::fill(&mut nonce).map_err(|_| rusqlite::Error::InvalidQuery)?;
            let now = crate::policy_store::now_ms().map_err(|_| rusqlite::Error::InvalidQuery)?;
            let record = Record {
                lineage: NativeBashReviewLineageV1 {
                    schema: SCHEMA.into(),
                    lineage_id: hex::encode(nonce),
                    operation_id: self.operation_id.into(),
                    artifact_hash: self.artifact_hash.into(),
                    created_at_ms: now,
                    expires_at_ms: now
                        .checked_add(LIFETIME_MS)
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                },
                harness: harness.into(),
                project: project.into(),
                request_id: None,
                blocked: false,
                superseded: false,
            };
            self.write_review(&record)?;
            Ok(record.lineage)
        })
    }

    /// Only denial is learned from a resolved inbox row. Permission still
    /// requires the existing MAC grant claim and the current native policy.
    fn refresh_review(&self, record: &mut Record) -> rusqlite::Result<Option<(String, String)>> {
        if record.blocked {
            return Ok(None);
        }
        let mut statement = self.connection.prepare(
            "SELECT request_id,status,resolution_action,
             CASE WHEN length(action_envelope_json)<=1048576 THEN action_envelope_json END
             FROM approval_requests WHERE harness=?1 AND artifact_id=?2 AND artifact_hash=?3
             AND workspace IS ?4 AND json_extract(action_envelope_json,'$.native_bash.review_lineage.lineage_id')=?5
             LIMIT 2",
        )?;
        let rows = statement
            .query_map(
                params![
                    record.harness,
                    guard_contracts::NATIVE_BASH_ARTIFACT_ID,
                    record.lineage.artifact_hash,
                    record.project,
                    record.lineage.lineage_id
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if rows.is_empty() && record.request_id.is_none() {
            return Ok(None);
        }
        let [(id, status, action, Some(envelope))] = rows.as_slice() else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        if record
            .request_id
            .as_ref()
            .is_some_and(|expected| expected != id)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let envelope: serde_json::Value =
            serde_json::from_str(envelope).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let lineage: NativeBashReviewLineageV1 = serde_json::from_value(
            envelope
                .pointer("/native_bash/review_lineage")
                .cloned()
                .ok_or(rusqlite::Error::InvalidQuery)?,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if lineage != record.lineage
            || envelope
                .pointer("/native_bash/artifact_hash")
                .and_then(serde_json::Value::as_str)
                != Some(record.lineage.artifact_hash.as_str())
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let action = match (status.as_str(), action.as_deref()) {
            ("pending", None) => "pending",
            ("resolved", Some("allow")) => "allow",
            ("resolved", Some("block")) => "block",
            _ => return Err(rusqlite::Error::InvalidQuery),
        };
        record.request_id = Some(id.clone());
        record.blocked = action == "block";
        self.write_review(record)?;
        Ok(Some((id.clone(), action.into())))
    }

    pub(crate) fn review_kept_blocked(&self) -> rusqlite::Result<bool> {
        self.review_transaction(|| {
            let Some(mut record) = self.read_review()? else {
                return Ok(false);
            };
            self.refresh_review(&mut record)?;
            Ok(record.blocked)
        })
    }

    pub(super) fn require_review_authority(
        &self,
        claim: Option<&ClaimApprovalReuseDecisionsRequestV1>,
    ) -> rusqlite::Result<()> {
        if self.connection.is_autocommit() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let Some(mut record) = self.read_review()? else {
            if claim.is_some_and(|claim| {
                claim.decisions.iter().any(|decision| {
                    decision
                        .get("approval_id")
                        .is_some_and(serde_json::Value::is_string)
                })
            }) {
                // No legacy-row, missing-schema or synthetic-claim fallback.
                // Every once grant belongs to a native pending operation.
                return Err(rusqlite::Error::InvalidQuery);
            }
            return Ok(());
        };
        let resolution = self.refresh_review(&mut record)?;
        if record.blocked {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let Some((request_id, action)) = resolution else {
            return Err(rusqlite::Error::InvalidQuery);
        };
        if action != "allow" {
            return Err(rusqlite::Error::InvalidQuery);
        }
        if let Some(claim) = claim {
            for decision in &claim.decisions {
                if decision
                    .get("approval_id")
                    .is_some_and(serde_json::Value::is_string)
                    && decision
                        .get("request_id")
                        .and_then(serde_json::Value::as_str)
                        != Some(request_id.as_str())
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "policy_store_bash_review_tests.rs"]
mod tests;
