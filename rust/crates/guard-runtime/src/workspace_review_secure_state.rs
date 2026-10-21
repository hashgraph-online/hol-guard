#![forbid(unsafe_code)]
//! Secure resident state for the root-enrolled workspace-review authority.
//!
//! The record is public metadata, but its accepted digest and one-shot claim
//! set are resident-owned state. Production uses the platform secret store;
//! the private file exists only in tests, matching the existing V4 pattern.

use guard_contracts::{
    NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES, NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES,
    NATIVE_WORKSPACE_REVIEW_MAX_SCOPE_VERSION_BYTES, NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1,
};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::path::Path;

use super::workspace_review_authority::VerifiedWorkspaceReviewAuthority;

#[cfg(not(test))]
use super::approval_enrollment::{
    read_platform_secret_for_workspace_review, write_platform_secret_for_workspace_review,
};

pub(crate) const SECURE_STATE_SCHEMA: &str = "guard-native-workspace-review-secure-state.v1";
pub(crate) const SECURE_STATE_VERSION: u16 = 1;
// Covers the canonical JSON representation of one claim, including the
// optional semantic digest, while keeping the platform-secret budget bounded.
const MAX_CLAIM_TEXT_BYTES: usize = 512;
const MAX_SECRET_TEXT_BYTES: usize = NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES
    + (NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES * MAX_CLAIM_TEXT_BYTES);
#[cfg(test)]
const SECURE_STATE_FILE_NAME: &str = "workspace-review-authority-v1-state.test.json";
#[cfg(not(test))]
const SECURE_STATE_ACCOUNT_SUFFIX: &str = ":workspace-review-authority-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceReviewClaimV1 {
    pub(crate) claim_id: String,
    pub(crate) envelope_digest: String,
    /// Derived from the stable decision semantics, excluding short-lived
    /// transport timestamps/signature and authority signer identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) semantic_decision_digest: Option<String>,
    /// Set only when an exact legacy envelope was replayed and its semantic
    /// digest was safely derived under the current authority.
    #[serde(default)]
    pub(crate) legacy_semantic_recovered: bool,
    /// The original transport expiry is retained for audit only. Consumed
    /// claims are never pruned after expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkspaceReviewSecureStateV1 {
    pub(crate) schema: String,
    pub(crate) version: u16,
    pub(crate) authority_record_digest: String,
    pub(crate) enrollment_generation: u64,
    pub(crate) key_id: String,
    pub(crate) workspace_binding: String,
    pub(crate) device_binding: String,
    pub(crate) installation_binding: String,
    pub(crate) scope_contract_version: String,
    pub(crate) scope_binding: String,
    pub(crate) status: String,
    pub(crate) consumed_claims: Vec<WorkspaceReviewClaimV1>,
    /// New claims live in an immutable index. The bounded inline vector is
    /// retained only while pre-index installation history migrates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) claim_index: Option<super::workspace_review_claim_index::ClaimIndexAnchor>,
    /// Highest wall-clock value observed by the resident. A rollback fails
    /// closed so expired claims cannot become replayable again.
    #[serde(default)]
    pub(crate) last_observed_time_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) pending_authority_record: Option<String>,
}

impl WorkspaceReviewSecureStateV1 {
    pub(crate) fn for_authority(
        authority: &VerifiedWorkspaceReviewAuthority,
    ) -> WorkspaceReviewSecureStateV1 {
        Self {
            schema: SECURE_STATE_SCHEMA.to_owned(),
            version: SECURE_STATE_VERSION,
            authority_record_digest: authority.record_digest.clone(),
            enrollment_generation: authority.enrollment_generation,
            key_id: authority.key_id.clone(),
            workspace_binding: authority.workspace_binding.clone(),
            device_binding: authority.device_binding.clone(),
            installation_binding: authority.installation_binding.clone(),
            scope_contract_version: authority.scope_contract_version.clone(),
            scope_binding: authority.scope_binding.clone(),
            status: authority.status.clone(),
            consumed_claims: Vec::new(),
            claim_index: None,
            last_observed_time_ms: 0,
            pending_authority_record: None,
        }
    }

    pub(crate) fn with_pending_authority_record(
        mut self,
        record_bytes: &[u8],
    ) -> Result<Self, String> {
        self.pending_authority_record = Some(
            String::from_utf8(record_bytes.to_vec())
                .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?,
        );
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn clear_pending_authority_record(&mut self) {
        self.pending_authority_record = None;
    }

    pub(crate) fn can_transition_to(&self, candidate: &VerifiedWorkspaceReviewAuthority) -> bool {
        if self.status == "revoked"
            || candidate.enrollment_generation <= self.enrollment_generation
            || self.workspace_binding != candidate.workspace_binding
            || self.device_binding != candidate.device_binding
            || self.installation_binding != candidate.installation_binding
            || self.scope_contract_version != candidate.scope_contract_version
            || self.scope_binding != candidate.scope_binding
        {
            return false;
        }
        match candidate.status.as_str() {
            "active" => {
                candidate.previous_key_id.as_deref() == Some(self.key_id.as_str())
                    && candidate.key_id != self.key_id
            }
            "revoked" => candidate.key_id == self.key_id && candidate.previous_key_id.is_none(),
            _ => false,
        }
    }

    pub(crate) fn matches_authority(&self, authority: &VerifiedWorkspaceReviewAuthority) -> bool {
        self.schema == SECURE_STATE_SCHEMA
            && self.version == SECURE_STATE_VERSION
            && self.authority_record_digest == authority.record_digest
            && self.enrollment_generation == authority.enrollment_generation
            && self.key_id == authority.key_id
            && self.workspace_binding == authority.workspace_binding
            && self.device_binding == authority.device_binding
            && self.installation_binding == authority.installation_binding
            && self.scope_contract_version == authority.scope_contract_version
            && self.scope_binding == authority.scope_binding
            && self.status == authority.status
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema != SECURE_STATE_SCHEMA
            || self.version != SECURE_STATE_VERSION
            || self.enrollment_generation == 0
            || !matches!(self.status.as_str(), "active" | "revoked")
            || !is_lower_hex(&self.authority_record_digest, 64)
            || !is_lower_hex(&self.key_id, 64)
            || !is_lower_hex(&self.workspace_binding, 64)
            || !is_lower_hex(&self.device_binding, 64)
            || !is_lower_hex(&self.installation_binding, 64)
            || self.device_binding == self.installation_binding
            || self.scope_contract_version != NATIVE_WORKSPACE_REVIEW_SCOPE_CONTRACT_V1
            || self.scope_contract_version.len() > NATIVE_WORKSPACE_REVIEW_MAX_SCOPE_VERSION_BYTES
            || !is_lower_hex(&self.scope_binding, 64)
            || self.consumed_claims.len() > NATIVE_WORKSPACE_REVIEW_MAX_REPLAY_ENTRIES
            || self
                .claim_index
                .as_ref()
                .is_some_and(|index| !index.validate())
        {
            return Err("native_workspace_review_secure_state_invalid".to_owned());
        }
        if let Some(record) = self.pending_authority_record.as_ref() {
            let bytes = record.as_bytes();
            if bytes.is_empty()
                || bytes.len() > NATIVE_WORKSPACE_REVIEW_MAX_AUTHORITY_BYTES
                || digest_bytes(bytes) != self.authority_record_digest
            {
                return Err("native_workspace_review_secure_state_invalid".to_owned());
            }
            let value = crate::strict_json_value(bytes)
                .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?;
            let canonical = canonical_json_bytes(&value)
                .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?;
            if canonical != bytes {
                return Err("native_workspace_review_secure_state_invalid".to_owned());
            }
        }
        let mut claim_ids = HashSet::with_capacity(self.consumed_claims.len());
        let mut semantics = HashSet::with_capacity(self.consumed_claims.len());
        for claim in &self.consumed_claims {
            if !is_lower_hex(&claim.claim_id, 64)
                || !is_lower_hex(&claim.envelope_digest, 64)
                || claim
                    .semantic_decision_digest
                    .as_ref()
                    .is_some_and(|digest| !is_lower_hex(digest, 64))
                || claim.expires_at_ms == Some(0)
                || !claim_ids.insert(&claim.claim_id)
                || claim
                    .semantic_decision_digest
                    .as_ref()
                    .is_some_and(|digest| !semantics.insert(digest))
            {
                return Err("native_workspace_review_secure_state_invalid".to_owned());
            }
        }
        Ok(())
    }
}

pub(crate) fn record_claim(
    state_base: &Path,
    state: &mut WorkspaceReviewSecureStateV1,
    claim: WorkspaceReviewClaimV1,
) -> Result<(), String> {
    let mut root = state.claim_index.as_ref().map(|index| index.root.clone());
    let mut count = state
        .claim_index
        .as_ref()
        .map_or(0, |index| index.claim_count);
    let mut candidate = state.clone();
    // Move one legacy record per decision, not the entire history while the
    // resident lock is held. Both representations commit in one secure record.
    // A claim still missing its semantic digest cannot enter the dual-key
    // index; leave it inline where its claim_id tombstone still applies until
    // an exact legacy replay backfills the digest, then migrate it later.
    let migrated = candidate
        .consumed_claims
        .iter()
        .rposition(|claim| claim.semantic_decision_digest.is_some())
        .map(|index| candidate.consumed_claims.remove(index));
    for previous in migrated.iter().chain(std::iter::once(&claim)) {
        root = Some(super::workspace_review_claim_index::insert_claim(
            state_base,
            root.as_deref(),
            previous,
        )?);
        count = count
            .checked_add(1)
            .ok_or_else(|| "native_workspace_review_claim_index_invalid".to_owned())?;
    }
    super::workspace_review_claim_index::sync_directories_before_commit(state_base)?;
    // Files precede the secure commit. Orphans cannot grant authority; an
    // uncertain platform-write outcome is reconciled by reloading the anchor.
    candidate.claim_index = Some(super::workspace_review_claim_index::ClaimIndexAnchor {
        root: root.ok_or_else(|| "native_workspace_review_claim_index_invalid".to_owned())?,
        claim_count: count,
    });
    store(state_base, &candidate)?;
    *state = candidate;
    Ok(())
}

fn is_lower_hex(value: &str, encoded_bytes: usize) -> bool {
    value.len() == encoded_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn load(state_base: &Path) -> Result<Option<WorkspaceReviewSecureStateV1>, String> {
    #[cfg(test)]
    let encoded = {
        let path = state_base.join(SECURE_STATE_FILE_NAME);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("native_workspace_review_secure_state_unavailable".to_owned()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("native_workspace_review_secure_state_invalid".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("native_workspace_review_secure_state_invalid".to_owned());
            }
        }
        let value = std::fs::read_to_string(path)
            .map_err(|_| "native_workspace_review_secure_state_unavailable".to_owned())?;
        if value.len() > MAX_SECRET_TEXT_BYTES {
            return Err("native_workspace_review_secure_state_invalid".to_owned());
        }
        Some(value)
    };
    #[cfg(not(test))]
    let encoded = {
        let account = format!(
            "{}{}",
            super::approval_enrollment::account_for_state_base(state_base)?,
            SECURE_STATE_ACCOUNT_SUFFIX
        );
        read_platform_secret_for_workspace_review(state_base, &account, MAX_SECRET_TEXT_BYTES)
            .map_err(map_platform_error)?
    };
    decode_secure_state(encoded)
}

fn decode_secure_state(
    encoded: Option<String>,
) -> Result<Option<WorkspaceReviewSecureStateV1>, String> {
    let Some(encoded) = encoded else {
        return Ok(None);
    };
    let value: Value = crate::strict_json_value(encoded.as_bytes())
        .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?;
    let canonical = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?;
    if canonical != encoded.as_bytes() {
        return Err("native_workspace_review_secure_state_invalid".to_owned());
    }
    let state: WorkspaceReviewSecureStateV1 = serde_json::from_value(value)
        .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?;
    state.validate()?;
    Ok(Some(state))
}

pub(crate) fn store(state_base: &Path, state: &WorkspaceReviewSecureStateV1) -> Result<(), String> {
    state.validate()?;
    let value = serde_json::to_value(state)
        .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?;
    if bytes.is_empty() || bytes.len() > MAX_SECRET_TEXT_BYTES {
        return Err("native_workspace_review_secure_state_invalid".to_owned());
    }
    #[cfg(test)]
    {
        let path = state_base.join(SECURE_STATE_FILE_NAME);
        let private_root = crate::resident_state::private_root_for_state_base(state_base)
            .map_err(|_| "native_workspace_review_secure_state_unavailable".to_owned())?;
        super::policy_store_persistence::persist_private_bytes(
            &path,
            &bytes,
            MAX_SECRET_TEXT_BYTES as u64,
            "workspace_review_secure_state",
            &private_root,
        )
        .map_err(|_| "native_workspace_review_secure_state_unavailable".to_owned())?;
        Ok(())
    }
    #[cfg(not(test))]
    {
        let account = format!(
            "{}{}",
            super::approval_enrollment::account_for_state_base(state_base)?,
            SECURE_STATE_ACCOUNT_SUFFIX
        );
        let encoded = String::from_utf8(bytes)
            .map_err(|_| "native_workspace_review_secure_state_invalid".to_owned())?;
        write_platform_secret_for_workspace_review(
            state_base,
            &account,
            &encoded,
            MAX_SECRET_TEXT_BYTES,
        )
        .map_err(map_platform_error)
    }
}

#[cfg(not(test))]
fn map_platform_error(error: String) -> String {
    match error.as_str() {
        "native_approval_secure_state_invalid" => {
            "native_workspace_review_secure_state_invalid".to_owned()
        }
        "native_approval_secure_state_unavailable" => {
            "native_workspace_review_secure_state_unavailable".to_owned()
        }
        _ => error,
    }
}

#[cfg(test)]
mod tests {
    use super::decode_secure_state;

    #[test]
    fn absent_secure_secret_allows_first_enrollment() {
        assert_eq!(decode_secure_state(None), Ok(None));
    }

    #[test]
    fn present_invalid_secure_secret_is_not_absence() {
        for encoded in ["", "{}", "not-json"] {
            assert_eq!(
                decode_secure_state(Some(encoded.to_owned())),
                Err("native_workspace_review_secure_state_invalid".to_owned())
            );
        }
    }
}
