#![forbid(unsafe_code)]
//! Producer-owned discovery hints, never decisions, grants or frozen input.
//! SQL/Cloud staging cannot populate this index. Every hint is revalidated
//! against the existing authenticated private request before presentation.

use super::{workspace_review_request::TrustedWorkspaceReviewRequest, PolicySnapshotStore};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DIRECTORY: &str = "workspace-review-business-queue";
const MAX_ENTRIES: usize = 4096;
const MAX_BYTES: u64 = 1024;
const UNAVAILABLE: &str = "native_local_business_queue_unavailable";

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selector {
    schema: String,
    version: u16,
    pub(crate) request_id: String,
    request_snapshot_digest: String,
    prepared_input_binding: String,
}

pub(crate) struct Registration {
    pub(crate) path: PathBuf,
    pub(crate) bytes: Vec<u8>,
}

impl Registration {
    /// Caller holds the existing transition lock. This is only discovery
    /// metadata; the private snapshot and native origin retain all authority.
    pub(crate) fn new(
        store: &PolicySnapshotStore,
        id: &str,
        bytes: &[u8],
        input_binding: &str,
    ) -> Result<Self, String> {
        if !super::workspace_review_request::valid_request_id(id)
            || !super::workspace_review_claim_index::valid_digest(input_binding)
        {
            return Err(UNAVAILABLE.into());
        }
        let root = crate::resident_state::private_root_for_state_base(store.state_base())?;
        let directory = crate::resident_state::ensure_private_directory_under(
            &store.state_base().join(DIRECTORY),
            &root,
            true,
        )?;
        let path = directory.join(format!("{id}.json"));
        if super::policy_store_persistence::read_private_json(
            &path,
            MAX_BYTES,
            "business_queue_selector",
            &root,
        )?
        .is_some()
        {
            return Err("native_business_request_exists".into());
        }
        let selector = Selector {
            schema: "guard.private-business-queue-selector.v1".into(),
            version: 1,
            request_id: id.into(),
            request_snapshot_digest: digest_bytes(bytes),
            prepared_input_binding: input_binding.into(),
        };
        let bytes = canonical_json_bytes(
            &serde_json::to_value(selector).map_err(|_| UNAVAILABLE.to_owned())?,
        )
        .map_err(|_| UNAVAILABLE.to_owned())?;
        Ok(Self { path, bytes })
    }

    pub(crate) fn publish(&self, store: &PolicySnapshotStore) -> Result<(), String> {
        let root = crate::resident_state::private_root_for_state_base(store.state_base())?;
        super::policy_store_persistence::persist_private_bytes(
            &self.path,
            &self.bytes,
            MAX_BYTES,
            "business_queue_selector",
            &root,
        )
    }
}

pub(crate) fn selectors(store: &PolicySnapshotStore) -> Result<Vec<Selector>, String> {
    let root = crate::resident_state::private_root_for_state_base(store.state_base())?;
    let directory = store.state_base().join(DIRECTORY);
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(UNAVAILABLE.into()),
        Ok(_) => super::validate_private_directory(&directory)?,
    }
    let mut found = Vec::new();
    for (index, entry) in std::fs::read_dir(&directory)
        .map_err(|_| UNAVAILABLE.to_owned())?
        .enumerate()
    {
        if index >= MAX_ENTRIES {
            return Err(UNAVAILABLE.into());
        }
        let entry = entry.map_err(|_| UNAVAILABLE.to_owned())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| UNAVAILABLE.to_owned())?;
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        if !super::workspace_review_request::valid_request_id(id) {
            return Err(UNAVAILABLE.into());
        }
        let (value, bytes) = super::policy_store_persistence::read_private_json(
            &entry.path(),
            MAX_BYTES,
            "business_queue_selector",
            &root,
        )?
        .ok_or_else(|| UNAVAILABLE.to_owned())?;
        if canonical_json_bytes(&value).map_err(|_| UNAVAILABLE.to_owned())? != bytes {
            return Err(UNAVAILABLE.into());
        }
        let selector: Selector =
            serde_json::from_value(value).map_err(|_| UNAVAILABLE.to_owned())?;
        if selector.schema != "guard.private-business-queue-selector.v1"
            || selector.version != 1
            || selector.request_id != id
            || !super::workspace_review_claim_index::valid_digest(&selector.request_snapshot_digest)
            || !super::workspace_review_claim_index::valid_digest(&selector.prepared_input_binding)
        {
            return Err(UNAVAILABLE.into());
        }
        found.push(selector);
    }
    super::validate_private_directory(&directory)?;
    found.sort_by(|a, b| a.request_id.cmp(&b.request_id));
    Ok(found)
}

pub(crate) fn load(
    store: &PolicySnapshotStore,
    selector: &Selector,
) -> Result<TrustedWorkspaceReviewRequest, String> {
    let request = super::workspace_review_request::load(store, &selector.request_id)?;
    if request.request_snapshot_digest != selector.request_snapshot_digest
        || request
            .business_input
            .as_ref()
            .is_none_or(|input| input.binding() != selector.prepared_input_binding)
    {
        return Err(UNAVAILABLE.into());
    }
    Ok(request)
}

pub(crate) fn consumed(
    store: &PolicySnapshotStore,
    request: &TrustedWorkspaceReviewRequest,
) -> Result<bool, String> {
    // Do not call authority loading here: its reconciliation can write state.
    // Only read the platform-secure anchor and immutable replay index.
    let state = super::workspace_review_secure_state::load(store.state_base())?;
    consumed_with_state(store, request, state.as_ref())
}

pub(crate) fn consumed_with_state(
    store: &PolicySnapshotStore,
    request: &TrustedWorkspaceReviewRequest,
    state: Option<&super::workspace_review_secure_state::WorkspaceReviewSecureStateV1>,
) -> Result<bool, String> {
    let Some(state) = state else {
        return Ok(false);
    };
    let digest = super::workspace_review_decision::owned_request_digest(request, state)?;
    if state
        .consumed_claims
        .iter()
        .any(|claim| claim.semantic_decision_digest.as_deref() == Some(digest.as_str()))
    {
        return Ok(true);
    }
    match state.claim_index.as_ref() {
        Some(anchor) => Ok(super::workspace_review_claim_index::find_semantic(
            store.state_base(),
            anchor,
            &digest,
        )?
        .is_some()),
        None => Ok(false),
    }
}
