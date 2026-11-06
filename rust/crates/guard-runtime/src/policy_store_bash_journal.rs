//! Authoritative execution deduplication in guard.db, not an allowlist.
//! A reservation and its authenticated consent claim share one transaction.

use guard_contained_process::CapturedOutput;
use guard_contracts::{
    ClaimApprovalReuseDecisionsRequestV1, NativeBashAuthorizationKindV1 as Authorization,
    NativeBashCompletionSummaryV1, NativeBashOperationStateV1 as State, NativeBashOperationV1,
};
use guard_policy_snapshot::local_authority_integrity::{
    sign_local_authority_payload, verify_local_authority_payload,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use super::policy_store_authority;
use super::PolicySnapshotStore;

#[path = "policy_store_bash_admission.rs"]
mod admission;
#[path = "policy_store_bash_invocation.rs"]
pub(crate) mod invocation;
#[path = "policy_store_bash_review.rs"]
mod review;

const PURPOSE: &str = "guard-native-bash-operation-v1";
const MAX_RECORD_BYTES: usize = 16 * 1024;
const SCHEMA: &str = include_str!(
    "../../../../src/codex_plugin_scanner/guard/schemas/native_bash_operations_v1.sql"
);

pub(crate) struct BashOperationJournal<'store> {
    pub(super) connection: Connection,
    pub(super) store: &'store PolicySnapshotStore,
    operation_id: &'store str,
    artifact_hash: &'store str,
    invocation: Option<invocation::Invocation>,
}

impl<'store> BashOperationJournal<'store> {
    /// Observe an existing signed delivery record without creating or changing
    /// execution, consent, or acknowledgement state.
    pub(crate) fn open_for_delivery(
        store: &'store PolicySnapshotStore,
        store_path: &str,
        operation_id: &'store str,
    ) -> Result<Self, String> {
        if !guard_contracts::native_bash_operation_id_is_valid(operation_id) {
            return Err("native_bash_operation_id_invalid".into());
        }
        store.require_store_path(store_path)?;
        let connection =
            Connection::open_with_flags(store_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|_| "native_bash_operation_store_unavailable")?;
        connection
            .busy_timeout(std::time::Duration::from_millis(100))
            .map_err(|_| "native_bash_operation_store_unavailable")?;
        connection
            .execute_batch("BEGIN DEFERRED")
            .map_err(|_| "native_bash_operation_store_unavailable")?;
        let journal = Self {
            connection,
            store,
            operation_id,
            artifact_hash: "",
            invocation: None,
        };
        journal
            .require_authority()
            .map_err(|_| "native_bash_operation_authority_changed")?;
        Ok(journal)
    }

    pub(crate) fn open(
        store: &'store PolicySnapshotStore,
        store_path: &str,
        operation_id: &'store str,
        artifact_hash: &'store str,
    ) -> Result<Self, String> {
        if !guard_contracts::native_bash_operation_id_is_valid(operation_id) {
            return Err("native_bash_operation_id_invalid".into());
        }
        store.require_store_path(store_path)?;
        let connection =
            Connection::open_with_flags(store_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(|_| "native_bash_operation_store_unavailable")?;
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| "native_bash_operation_store_unavailable")?;
        // A committed reservation must reach durable storage before effects.
        connection
            .execute_batch("PRAGMA synchronous=FULL;")
            .map_err(|_| "native_bash_operation_store_unavailable")?;
        connection
            .execute_batch(SCHEMA)
            .map_err(|_| "native_bash_operation_store_unavailable")?;
        connection
            .execute_batch(include_str!(
                "../../../../src/codex_plugin_scanner/guard/schemas/native_bash_reviews_v1.sql"
            ))
            .map_err(|_| "native_bash_operation_store_unavailable")?;
        connection
            .execute_batch(include_str!(
                "../../../../src/codex_plugin_scanner/guard/schemas/native_bash_invocations_v1.sql"
            ))
            .map_err(|_| "native_bash_operation_store_unavailable")?;
        let journal = Self {
            connection,
            store,
            operation_id,
            artifact_hash,
            invocation: None,
        };
        journal
            .require_authority()
            .map_err(|_| "native_bash_operation_authority_changed")?;
        Ok(journal)
    }

    fn require_authority(&self) -> rusqlite::Result<()> {
        Self::require_authority_for(self.store)
    }

    pub(super) fn require_authority_for(store: &PolicySnapshotStore) -> rusqlite::Result<()> {
        if store
            .authority_changed
            .load(std::sync::atomic::Ordering::SeqCst)
            || !policy_store_authority::authority_unchanged_fenced(store)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(())
    }

    pub(crate) fn read(&self) -> rusqlite::Result<Option<NativeBashOperationV1>> {
        let record = Self::read_authenticated(&self.connection, self.store, self.operation_id)?;
        if record
            .as_ref()
            .is_some_and(|record| record.artifact_hash != self.artifact_hash)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(record)
    }

    pub(super) fn read_authenticated(
        connection: &Connection,
        store: &PolicySnapshotStore,
        operation_id: &str,
    ) -> rusqlite::Result<Option<NativeBashOperationV1>> {
        Self::require_authority_for(store)?;
        // Bound allocations even when the database has been modified externally.
        let row: Option<(Option<String>, Option<String>)> = connection
            .query_row(
                "SELECT CASE WHEN length(payload)<=16384 THEN payload END,
                    CASE WHEN length(integrity)<=4096 THEN integrity END
               FROM guard_bash_operations WHERE operation_id=?1",
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
        let payload: Value =
            serde_json::from_str(&payload).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let integrity: Value =
            serde_json::from_str(&integrity).map_err(|_| rusqlite::Error::InvalidQuery)?;
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
        let record: NativeBashOperationV1 =
            serde_json::from_value(payload).map_err(|_| rusqlite::Error::InvalidQuery)?;
        if record.operation_id != operation_id
            || (record.state == State::Completed) != record.completion.is_some()
            || (matches!(record.state, State::Dispatched | State::Completed)
                && !record.dispatch_acknowledged)
            || (record.state == State::Claimed && record.dispatch_acknowledged)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(Some(record))
    }

    fn encode(&self, record: &NativeBashOperationV1) -> rusqlite::Result<(String, String)> {
        self.seal(record, PURPOSE)
    }

    pub(super) fn seal<T: serde::Serialize>(
        &self,
        record: &T,
        purpose: &str,
    ) -> rusqlite::Result<(String, String)> {
        self.require_authority()?;
        let payload = serde_json::to_value(record).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let timestamp: String = self.connection.query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%f+00:00','now')",
            [],
            |row| row.get(0),
        )?;
        let signed = sign_local_authority_payload(
            &payload,
            &self.store.verifier_key,
            &guard_policy_snapshot::verifier_key_id(&self.store.verifier_key),
            purpose,
            &timestamp,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
        let integrity = json!({
            "integrity_version":signed.integrity_version, "payload_hash":signed.payload_hash,
            "payload_mac":signed.payload_mac, "integrity_key_id":signed.integrity_key_id,
            "signed_at":signed.signed_at,
        });
        let payload = serde_json::to_string(&payload).map_err(|_| rusqlite::Error::InvalidQuery)?;
        if payload.len() > MAX_RECORD_BYTES {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok((payload, integrity.to_string()))
    }

    pub(crate) fn reserve(
        &self,
        claim: &ClaimApprovalReuseDecisionsRequestV1,
    ) -> Result<bool, String> {
        crate::claim_approval_reuse_op::claim_now_then(claim, &self.connection, &mut |_| {
            self.require_review_authority(Some(claim))?;
            self.insert(Authorization::SavedGrant)
        })
        .map(|record| record.is_some())
    }

    /// The fenced launch owner has established that every current decision
    /// permits this action. Re-read saved authority under the same write lock
    /// as reservation; no approval row is created or consumed here.
    pub(crate) fn reserve_allowed(&self, harness: &str, project: &str) -> rusqlite::Result<bool> {
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        let result = admission::require_no_saved_decision(
            &self.connection,
            self.artifact_hash,
            harness,
            project,
        )
        .and_then(|()| self.require_review_authority(None))
        .and_then(|()| self.insert(Authorization::CurrentPolicy));
        match result {
            Ok(Some(())) => {
                self.connection.execute_batch("COMMIT")?;
                Ok(true)
            }
            Ok(None) => {
                self.connection.execute_batch("ROLLBACK")?;
                Ok(false)
            }
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn insert(&self, authorization: Authorization) -> rusqlite::Result<Option<()>> {
        // Always inside BEGIN IMMEDIATE, including the saved-grant claim.
        if let Some(invocation) = &self.invocation {
            invocation.reserve(self)?;
        }
        if self.read()?.is_some() {
            return Ok(None);
        }
        let record = NativeBashOperationV1 {
            operation_id: self.operation_id.into(),
            artifact_hash: self.artifact_hash.into(),
            authorization,
            state: State::Claimed,
            dispatch_acknowledged: false,
            completion: None,
        };
        let (payload, integrity) = self.encode(&record)?;
        self.connection.execute(
            "INSERT INTO guard_bash_operations(operation_id,payload,integrity) VALUES(?1,?2,?3)",
            params![self.operation_id, payload, integrity],
        )?;
        Ok(Some(()))
    }

    pub(crate) fn dispatched(&self) -> rusqlite::Result<NativeBashOperationV1> {
        self.transition(State::Dispatched, true, None)
    }

    pub(crate) fn uncertain(&self, dispatched: bool) -> rusqlite::Result<NativeBashOperationV1> {
        self.transition(State::Uncertain, dispatched, None)
    }

    pub(crate) fn completed(
        &self,
        output: &CapturedOutput,
    ) -> rusqlite::Result<NativeBashOperationV1> {
        self.transition(
            State::Completed,
            true,
            Some(NativeBashCompletionSummaryV1 {
                exit_code: output.exit_code,
                output_limited: output.output_limited,
                timed_out: output.timed_out,
                cancelled: output.cancelled,
                stdout_sha256: guard_policy_snapshot::digest_bytes(&output.stdout),
                stderr_sha256: guard_policy_snapshot::digest_bytes(&output.stderr),
            }),
        )
    }

    fn transition(
        &self,
        state: State,
        dispatched: bool,
        completion: Option<NativeBashCompletionSummaryV1>,
    ) -> rusqlite::Result<NativeBashOperationV1> {
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        let result =
            (|| {
                let mut record = self.read()?.ok_or(rusqlite::Error::InvalidQuery)?;
                let valid = match state {
                    State::Dispatched => record.state == State::Claimed,
                    State::Completed => record.state == State::Dispatched,
                    State::Uncertain => matches!(record.state, State::Claimed | State::Dispatched),
                    State::Claimed => false,
                };
                if !valid || (record.dispatch_acknowledged && !dispatched) {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                record.state = state;
                record.dispatch_acknowledged = dispatched;
                record.completion = completion;
                if state == State::Completed {
                    if let Some(invocation) = &self.invocation {
                        invocation.complete(self)?;
                    }
                }
                let (payload, integrity) = self.encode(&record)?;
                if self.connection.execute(
                "UPDATE guard_bash_operations SET payload=?1,integrity=?2 WHERE operation_id=?3",
                params![payload, integrity, self.operation_id],
            )? != 1 { return Err(rusqlite::Error::InvalidQuery); }
                Ok(record)
            })();
        match result {
            Ok(record) => {
                self.connection.execute_batch("COMMIT")?;
                Ok(record)
            }
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }
}
