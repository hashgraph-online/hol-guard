//! Durable SDK delivery acknowledgement is metadata, never execution consent.
//! Unknown calls share the pending operation until a clean native completion
//! has reached the SDK. Known call IDs remain pinned to their original run.

use std::collections::BTreeMap;

use guard_contracts::NativeBashOperationStateV1;
use guard_policy_snapshot::local_authority_integrity::verify_local_authority_payload;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::BashOperationJournal;

const PURPOSE: &str = "guard-native-bash-invocation-lifetime-v1";
const MAX_CALLS: usize = 128;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    base_id: String,
    harness: String,
    project: String,
    generation: u64,
    operation_id: String,
    artifact_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reserved: Option<bool>,
    completed: bool,
    acknowledged: bool,
    calls: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    busy_calls: BTreeMap<String, u64>,
}

impl Record {
    fn new(journal: &BashOperationJournal<'_>, harness: &str, project: &str) -> Self {
        Self {
            schema: PURPOSE.into(),
            base_id: journal.operation_id.into(),
            harness: harness.into(),
            project: project.into(),
            generation: 0,
            operation_id: operation_id(journal.operation_id, 0),
            artifact_hash: journal.artifact_hash.into(),
            reserved: Some(false),
            completed: false,
            acknowledged: false,
            calls: BTreeMap::new(),
            busy_calls: BTreeMap::new(),
        }
    }
}

pub(crate) struct Invocation {
    base_id: String,
    call_digest: String,
    generation: u64,
}

fn invalid() -> rusqlite::Error {
    rusqlite::Error::InvalidQuery
}

fn operation_id(base_id: &str, generation: u64) -> String {
    format!(
        "bash-invocation:{}",
        guard_policy_snapshot::digest_bytes(
            &serde_json::to_vec(&(PURPOSE, base_id, generation)).expect("primitive tuple")
        )
    )
}

fn call_digest(call_id: &str) -> rusqlite::Result<String> {
    if call_id.is_empty() || call_id.len() > 256 || call_id.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(guard_policy_snapshot::digest_bytes(call_id.as_bytes()))
}

fn read(journal: &BashOperationJournal<'_>, base_id: &str) -> rusqlite::Result<Option<Record>> {
    BashOperationJournal::require_authority_for(journal.store)?;
    let row: Option<(Option<String>, Option<String>)> = journal
        .connection
        .query_row(
            "SELECT CASE WHEN length(payload)<=16384 THEN payload END,
                CASE WHEN length(integrity)<=4096 THEN integrity END
         FROM guard_bash_invocations WHERE base_id=?1",
            [base_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((Some(payload), Some(integrity))) = row else {
        return if row.is_none() {
            Ok(None)
        } else {
            Err(invalid())
        };
    };
    let payload: Value = serde_json::from_str(&payload).map_err(|_| invalid())?;
    let integrity: Value = serde_json::from_str(&integrity).map_err(|_| invalid())?;
    let key_id = guard_policy_snapshot::verifier_key_id(&journal.store.verifier_key);
    if verify_local_authority_payload(
        &payload,
        &integrity,
        Some(&journal.store.verifier_key),
        Some(&key_id),
        PURPOSE,
    )
    .status
        != "valid"
    {
        return Err(invalid());
    }
    let record: Record = serde_json::from_value(payload).map_err(|_| invalid())?;
    if record.schema != PURPOSE
        || record.base_id != base_id
        || record.operation_id != operation_id(base_id, record.generation)
        || record.calls.len() + record.busy_calls.len() > MAX_CALLS
        || (record.calls.is_empty() && record.busy_calls.is_empty())
        || record
            .calls
            .iter()
            .chain(&record.busy_calls)
            .any(|(key, generation)| {
                key.len() != 64
                    || !key.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || *generation > record.generation
            })
        || record
            .busy_calls
            .keys()
            .any(|key| record.calls.contains_key(key))
        || record.acknowledged && !record.completed
        || record.completed && record.reserved == Some(false)
    {
        return Err(invalid());
    }
    Ok(Some(record))
}

fn write(journal: &BashOperationJournal<'_>, record: &Record) -> rusqlite::Result<()> {
    let (payload, integrity) = journal.seal(record, PURPOSE)?;
    journal.connection.execute(
        "INSERT INTO guard_bash_invocations(base_id,payload,integrity) VALUES(?1,?2,?3)
         ON CONFLICT(base_id) DO UPDATE SET payload=excluded.payload,integrity=excluded.integrity",
        params![record.base_id, payload, integrity],
    )?;
    Ok(())
}

fn transaction<T>(
    journal: &BashOperationJournal<'_>,
    body: impl FnOnce() -> rusqlite::Result<T>,
) -> rusqlite::Result<T> {
    journal.connection.execute_batch("BEGIN IMMEDIATE")?;
    match body() {
        Ok(value) => {
            journal.connection.execute_batch("COMMIT")?;
            Ok(value)
        }
        Err(error) => {
            let _ = journal.connection.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}

impl BashOperationJournal<'_> {
    /// Authenticate a rejected concurrent SDK call without allocating a run,
    /// claiming consent, completing an operation, or acknowledging delivery.
    #[cfg(target_os = "macos")]
    pub(crate) fn record_busy_call(
        &self,
        harness: &str,
        project: &str,
        call_id: &str,
    ) -> rusqlite::Result<()> {
        let digest = call_digest(call_id)?;
        transaction(self, || {
            let mut record = read(self, self.operation_id)?
                .unwrap_or_else(|| Record::new(self, harness, project));
            if record.harness != harness
                || record.project != project
                || record.artifact_hash != self.artifact_hash
                || record.calls.contains_key(&digest)
                || (record.calls.len() + record.busy_calls.len() >= MAX_CALLS
                    && !record.busy_calls.contains_key(&digest))
            {
                return Err(invalid());
            }
            record.busy_calls.insert(digest.clone(), record.generation);
            write(self, &record)
        })
    }

    /// Bind a reply to the authenticated allocation for this base and SDK call.
    /// Reading an allocation never reserves, completes or acknowledges it.
    pub(crate) fn reply_invocation_matches(
        &self,
        harness: &str,
        project: &str,
        call_id: &str,
        returned_id: &str,
        artifact_hash: &str,
    ) -> rusqlite::Result<bool> {
        let Some(record) = read(self, self.operation_id)? else {
            return Ok(false);
        };
        let Some(generation) = record.calls.get(&call_digest(call_id)?) else {
            return Ok(false);
        };
        Ok(record.harness == harness
            && record.project == project
            && record.artifact_hash == artifact_hash
            && returned_id == operation_id(self.operation_id, *generation))
    }

    /// A signed invocation may explain its own control/result delivery, never
    /// authorize another execution. The bool identifies a clean current result
    /// eligible for a later SDK acknowledgement.
    pub(crate) fn confirm_delivery_call(
        &self,
        harness: &str,
        project: &str,
        call_id: &str,
        observed_exit: i32,
    ) -> rusqlite::Result<Option<bool>> {
        let Some(record) = read(self, self.operation_id)? else {
            return Ok(None);
        };
        if record.harness != harness || record.project != project {
            return Err(invalid());
        }
        let digest = call_digest(call_id)?;
        if record.busy_calls.get(&digest) == Some(&record.generation) {
            return Ok((observed_exit == 125).then_some(false));
        }
        let Some(generation) = record.calls.get(&digest) else {
            return Ok(None);
        };
        let current = *generation == record.generation;
        if current && !record.completed && record.reserved.is_some() && observed_exit == 125 {
            return Ok(Some(false));
        }
        let Some(operation) = Self::read_authenticated(
            &self.connection,
            self.store,
            &operation_id(self.operation_id, *generation),
        )?
        else {
            return Ok(None);
        };
        if operation.state != NativeBashOperationStateV1::Completed
            || current && operation.artifact_hash != record.artifact_hash
        {
            return Ok(None);
        }
        let Some(completion) = operation.completion else {
            return Ok(None);
        };
        let exit = if completion.timed_out {
            124
        } else if completion.cancelled || completion.output_limited {
            125
        } else {
            completion
                .exit_code
                .filter(|code| (0..=255).contains(code))
                .unwrap_or(125)
        };
        if observed_exit != exit {
            return Ok(None);
        }
        Ok(Some(
            current
                && record.completed
                && operation.dispatch_acknowledged
                && !completion.timed_out
                && !completion.cancelled
                && !completion.output_limited
                && completion.exit_code == Some(observed_exit),
        ))
    }

    pub(crate) fn allocate_invocation(
        &self,
        harness: &str,
        project: &str,
        call_id: Option<&str>,
    ) -> rusqlite::Result<(String, Option<Invocation>)> {
        let Some(call_id) = call_id else {
            return if self.operation_id.starts_with("bash-invocation:") {
                Err(invalid())
            } else {
                Ok((self.operation_id.into(), None))
            };
        };
        let base_id = self.operation_id;
        let Some(digest) = base_id.strip_prefix("bash-operation:") else {
            return Err(invalid());
        };
        if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid());
        }
        let call_digest = call_digest(call_id)?;
        let allocated = transaction(self, || {
            let mut record =
                read(self, base_id)?.unwrap_or_else(|| Record::new(self, harness, project));
            if record.harness != harness || record.project != project {
                return Err(invalid());
            }
            if record.busy_calls.contains_key(&call_digest) {
                return Err(invalid());
            }
            if record.artifact_hash != self.artifact_hash
                && record.reserved == Some(false)
                && !record.completed
                && !record.acknowledged
            {
                if record
                    .calls
                    .get(&call_digest)
                    .is_some_and(|generation| *generation != record.generation)
                {
                    return Err(invalid());
                }
                if !self.retire_unstarted_review(
                    &record.operation_id,
                    &record.artifact_hash,
                    harness,
                    project,
                )? {
                    // Keep the authenticated denial learned from the inbox,
                    // even though this attempt cannot receive a new version.
                    return Ok(None);
                }
                let previous = record.generation;
                record.generation = previous.checked_add(1).ok_or_else(invalid)?;
                record.operation_id = operation_id(base_id, record.generation);
                record.artifact_hash = self.artifact_hash.into();
                for generation in record.calls.values_mut() {
                    if *generation == previous {
                        *generation = record.generation;
                    }
                }
            }
            let generation = if let Some(generation) = record.calls.get(&call_digest) {
                *generation
            } else {
                if record.calls.len() + record.busy_calls.len() >= MAX_CALLS {
                    return Err(invalid());
                }
                if record.acknowledged {
                    // A signed completion bit alone does not replace the signed
                    // journal. Losing either record cannot enable a new run.
                    require_clean_completion(self, &record, None)?;
                    record.generation = record.generation.checked_add(1).ok_or_else(invalid)?;
                    record.operation_id = operation_id(base_id, record.generation);
                    record.artifact_hash = self.artifact_hash.into();
                    record.reserved = Some(false);
                    record.completed = false;
                    record.acknowledged = false;
                }
                if record.artifact_hash != self.artifact_hash {
                    return Err(invalid());
                }
                record.calls.insert(call_digest.clone(), record.generation);
                record.generation
            };
            write(self, &record)?;
            Ok(Some((
                operation_id(base_id, generation),
                Some(Invocation {
                    base_id: base_id.into(),
                    call_digest,
                    generation,
                }),
            )))
        })?;
        allocated.ok_or_else(invalid)
    }

    pub(crate) fn attach_invocation(&mut self, invocation: Option<Invocation>) {
        self.invocation = invocation;
    }

    pub(crate) fn acknowledge_invocation(
        &self,
        harness: &str,
        project: &str,
        call_id: &str,
        exit_code: i32,
    ) -> rusqlite::Result<bool> {
        let call_digest = call_digest(call_id)?;
        transaction(self, || {
            let mut record = read(self, self.operation_id)?.ok_or_else(invalid)?;
            if record.harness != harness || record.project != project {
                return Err(invalid());
            }
            let generation = record.calls.get(&call_digest).ok_or_else(invalid)?;
            if *generation != record.generation {
                return Ok(false);
            }
            require_clean_completion(self, &record, Some(exit_code))?;
            record.acknowledged = true;
            write(self, &record)?;
            Ok(true)
        })
    }
}

fn require_clean_completion(
    journal: &BashOperationJournal<'_>,
    record: &Record,
    observed_exit: Option<i32>,
) -> rusqlite::Result<()> {
    let operation = BashOperationJournal::read_authenticated(
        &journal.connection,
        journal.store,
        &record.operation_id,
    )?
    .ok_or_else(invalid)?;
    let completion = operation.completion.ok_or_else(invalid)?;
    if !record.completed
        || operation.state != NativeBashOperationStateV1::Completed
        || operation.artifact_hash != record.artifact_hash
        || !operation.dispatch_acknowledged
        || completion.timed_out
        || completion.cancelled
        || completion.output_limited
        || !completion
            .exit_code
            .is_some_and(|code| (0..=255).contains(&code))
        || observed_exit.is_some_and(|code| completion.exit_code != Some(code))
    {
        return Err(invalid());
    }
    Ok(())
}

impl Invocation {
    fn current(&self, journal: &BashOperationJournal<'_>) -> rusqlite::Result<Record> {
        let record = read(journal, &self.base_id)?.ok_or_else(invalid)?;
        if record.generation != self.generation
            || record.operation_id != journal.operation_id
            || record.artifact_hash != journal.artifact_hash
            || record.calls.get(&self.call_digest) != Some(&self.generation)
        {
            return Err(invalid());
        }
        Ok(record)
    }

    pub(super) fn reserve(&self, journal: &BashOperationJournal<'_>) -> rusqlite::Result<()> {
        let mut record = self.current(journal)?;
        if record.reserved != Some(false) || record.completed || record.acknowledged {
            return Err(invalid());
        }
        // Sealed in the SAME transaction as reservation and any once claim.
        // A missing operation row can never be mistaken for an unstarted run.
        record.reserved = Some(true);
        write(journal, &record)
    }

    pub(super) fn complete(&self, journal: &BashOperationJournal<'_>) -> rusqlite::Result<()> {
        let mut record = self.current(journal)?;
        if record.completed || record.acknowledged {
            return Err(invalid());
        }
        record.completed = true;
        write(journal, &record)
    }
}
