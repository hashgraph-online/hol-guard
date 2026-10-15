//! Private durable progress, never an execution grant or restart retry token.

use super::super::super::PolicySnapshotStore;
use guard_policy_snapshot::canonical_json_bytes;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DIRECTORY: &str = "workspace-review-business-attempts";
const LIMIT: u64 = 2048;
const CAPACITY: usize = 128;
const INVALID: &str = "native_business_attempt_invalid";

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Claimed,
    AttemptStarted,
    ApiAccepted,
    Unconfirmed,
    NotAttempted,
}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    version: u16,
    request_id: String,
    input_binding: String,
    status: Status,
    acknowledgement_binding: Option<String>,
}

// The in-memory expected bytes detect changes between transitions. Durable
// records only describe progress; reading one cannot restore this owned handle.
#[allow(dead_code)]
pub(super) struct Journal {
    path: PathBuf,
    root: PathBuf,
    record: Record,
    expected: Vec<u8>,
}

#[allow(dead_code)]
impl Journal {
    pub(super) fn claimed(
        store: &PolicySnapshotStore,
        request_id: &str,
        input_binding: &str,
    ) -> Result<Self, String> {
        super::super::super::approval_enrollment::with_transition_lock(store.state_base(), || {
            Self::claimed_unlocked(store, request_id, input_binding)
        })
    }

    pub(super) fn claimed_unlocked(
        store: &PolicySnapshotStore,
        request_id: &str,
        input_binding: &str,
    ) -> Result<Self, String> {
        if !super::super::super::workspace_review_request::valid_request_id(request_id)
            || !super::super::super::workspace_review_claim_index::valid_digest(input_binding)
        {
            return Err(INVALID.into());
        }
        let root = crate::resident_state::private_root_for_state_base(store.state_base())?;
        let directory = store.state_base().join(DIRECTORY);
        crate::resident_state::ensure_private_directory_under(&directory, &root, true)?;
        // No automatic pruning: retained attempts must not disappear and
        // masquerade as permission to resend. Capacity refuses new work.
        let count = retained_count(&directory, &root)?;
        if count >= CAPACITY {
            return Err("native_business_attempt_capacity".into());
        }
        let path = directory.join(format!("{request_id}.json"));
        if read(&path, &root)?.is_some() {
            return Err("native_business_attempt_exists".into());
        }
        let record = Record {
            schema: "guard.private-business-attempt.v1".into(),
            version: 1,
            request_id: request_id.into(),
            input_binding: input_binding.into(),
            status: Status::Claimed,
            acknowledgement_binding: None,
        };
        let expected = encode(&record)?;
        persist(&path, &root, &expected)?;
        Ok(Self {
            path,
            root,
            record,
            expected,
        })
    }

    // Must be called only after current floors and budgets pass, and before I/O.
    // No production caller enables this transition yet.
    pub(super) fn start(mut self, store: &PolicySnapshotStore) -> Result<Self, String> {
        if self.record.status != Status::Claimed {
            return Err(INVALID.into());
        }
        self.transition(store, Status::AttemptStarted, None)?;
        Ok(self)
    }

    pub(super) fn start_unlocked(mut self, store: &PolicySnapshotStore) -> Result<Self, String> {
        if self.record.status != Status::Claimed {
            return Err(INVALID.into());
        }
        self.transition_unlocked(store, Status::AttemptStarted, None)?;
        Ok(self)
    }

    pub(super) fn finish_unlocked(
        mut self,
        store: &PolicySnapshotStore,
        acknowledgement: Option<String>,
    ) -> Result<(), String> {
        if self.record.status != Status::AttemptStarted
            || acknowledgement.as_deref().is_some_and(|v| {
                !super::super::super::workspace_review_claim_index::valid_digest(v)
            })
        {
            return Err(INVALID.into());
        }
        let status = if acknowledgement.is_some() {
            Status::ApiAccepted
        } else {
            Status::Unconfirmed
        };
        self.transition_unlocked(store, status, acknowledgement)
    }

    pub(super) fn finish(
        mut self,
        store: &PolicySnapshotStore,
        acknowledgement: Option<String>,
    ) -> Result<(), String> {
        if self.record.status != Status::AttemptStarted
            || acknowledgement.as_deref().is_some_and(|binding| {
                !super::super::super::workspace_review_claim_index::valid_digest(binding)
            })
        {
            return Err(INVALID.into());
        }
        let status = if acknowledgement.is_some() {
            Status::ApiAccepted
        } else {
            Status::Unconfirmed
        };
        self.transition(store, status, acknowledgement)
    }

    pub(super) fn refuse_unlocked(mut self, store: &PolicySnapshotStore) -> Result<(), String> {
        if self.record.status != Status::AttemptStarted {
            return Err(INVALID.into());
        }
        self.transition_unlocked(store, Status::NotAttempted, None)
    }

    fn transition(
        &mut self,
        store: &PolicySnapshotStore,
        status: Status,
        acknowledgement: Option<String>,
    ) -> Result<(), String> {
        super::super::super::approval_enrollment::with_transition_lock(store.state_base(), || {
            self.transition_unlocked(store, status, acknowledgement)
        })
    }

    fn transition_unlocked(
        &mut self,
        store: &PolicySnapshotStore,
        status: Status,
        acknowledgement: Option<String>,
    ) -> Result<(), String> {
        if store
            .state_base()
            .join(DIRECTORY)
            .join(format!("{}.json", self.record.request_id))
            != self.path
        {
            return Err(INVALID.into());
        }
        if read(&self.path, &self.root)?.as_deref() != Some(self.expected.as_slice()) {
            return Err("native_business_attempt_changed".into());
        }
        self.record.status = status;
        self.record.acknowledgement_binding = acknowledgement;
        let bytes = encode(&self.record)?;
        persist(&self.path, &self.root, &bytes)?;
        self.expected = bytes;
        Ok(())
    }
}

fn retained_count(directory: &Path, root: &Path) -> Result<usize, String> {
    let mut count = 0;
    for (index, entry) in std::fs::read_dir(directory)
        .map_err(|_| INVALID.to_owned())?
        .enumerate()
    {
        // Bound scanning independently of retained capacity. Crash leftovers
        // are preserved; too many unexpected/temporary entries refuse safely.
        if index >= CAPACITY * 4 {
            return Err("native_business_attempt_scan_limit".into());
        }
        let entry = entry.map_err(|_| INVALID.to_owned())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| INVALID.to_owned())?;
        if persistence_temporary(&name) {
            if !entry.file_type().map_err(|_| INVALID.to_owned())?.is_file() {
                return Err(INVALID.into());
            }
            continue;
        }
        let id = name
            .strip_suffix(".json")
            .ok_or_else(|| INVALID.to_owned())?;
        if !super::super::super::workspace_review_request::valid_request_id(id) {
            return Err(INVALID.into());
        }
        let bytes = read(&entry.path(), root)?.ok_or_else(|| INVALID.to_owned())?;
        let record: Record = serde_json::from_slice(&bytes).map_err(|_| INVALID.to_owned())?;
        if record.schema != "guard.private-business-attempt.v1"
            || record.version != 1
            || record.request_id != id
            || !super::super::super::workspace_review_claim_index::valid_digest(
                &record.input_binding,
            )
            || (record.status == Status::ApiAccepted) != record.acknowledgement_binding.is_some()
            || record.acknowledgement_binding.as_deref().is_some_and(|v| {
                !super::super::super::workspace_review_claim_index::valid_digest(v)
            })
            || encode(&record)? != bytes
        {
            return Err(INVALID.into());
        }
        count += 1;
        if count >= CAPACITY {
            return Ok(count);
        }
    }
    Ok(count)
}

fn persistence_temporary(name: &str) -> bool {
    let Some(value) = name.strip_prefix('.').and_then(|v| v.strip_suffix(".tmp")) else {
        return false;
    };
    let mut parts = value.rsplitn(3, '.');
    let (Some(stamp), Some(pid), Some(file)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let Some(id) = file.strip_suffix(".json") else {
        return false;
    };
    super::super::super::workspace_review_request::valid_request_id(id)
        && !stamp.is_empty()
        && stamp.bytes().all(|b| b.is_ascii_digit())
        && stamp.parse::<u128>().is_ok()
        && !pid.is_empty()
        && pid.bytes().all(|b| b.is_ascii_digit())
        && pid.parse::<u32>().is_ok()
}

fn encode(record: &Record) -> Result<Vec<u8>, String> {
    canonical_json_bytes(&serde_json::to_value(record).map_err(|_| INVALID.to_owned())?)
        .map_err(|_| INVALID.to_owned())
}

fn read(path: &Path, root: &Path) -> Result<Option<Vec<u8>>, String> {
    super::super::super::policy_store_persistence::read_private_json(
        path,
        LIMIT,
        "business_attempt",
        root,
    )
    .map(|value| value.map(|(_, bytes)| bytes))
}

fn persist(path: &Path, root: &Path, bytes: &[u8]) -> Result<(), String> {
    super::super::super::policy_store_persistence::persist_private_bytes(
        path,
        bytes,
        LIMIT,
        "business_attempt",
        root,
    )
}

#[cfg(test)]
#[path = "workspace_review_business_journal_tests.rs"]
mod tests;
