//! Read-only continuity evidence; resident authentication and evaluation stay authoritative.
use super::*;
use guard_policy_snapshot::canonical_json_bytes;
use std::fs;

const MISMATCH: &str = "native_policy_snapshot_context_mismatch";

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ClientAuthorityObservation {
    policy: String,
    approval: Option<String>,
    approval_v4: Option<String>,
}

fn fingerprint(path: &Path) -> Result<Option<String>, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(MISMATCH.to_owned()),
        Ok(_) => authority_fingerprint(path)
            .map(Some)
            .ok_or_else(|| MISMATCH.to_owned()),
    }
}

fn fingerprint_set(state_base: &Path) -> Result<ClientAuthorityObservation, String> {
    Ok(ClientAuthorityObservation {
        policy: fingerprint(&state_base.join(SNAPSHOT_FILE_NAME))?
            .ok_or_else(|| MISMATCH.to_owned())?,
        approval: fingerprint(&state_base.join(approval_authority::APPROVAL_AUTHORITY_FILE_NAME))?,
        approval_v4: fingerprint(&state_base.join(approval_v4_authority::AUTHORITY_FILE_NAME))?,
    })
}

impl ClientAuthorityObservation {
    pub(crate) fn capture(state_base: &Path) -> Result<Self, String> {
        Self::capture_checked(state_base).map_err(|_| MISMATCH.to_owned())
    }

    fn capture_checked(state_base: &Path) -> Result<Self, String> {
        validate_private_directory(state_base)?;
        let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
        validate_private_directory(&private_root)?;
        let before = fingerprint_set(state_base)?;
        let (value, bytes) = read_private_json(
            &state_base.join(SNAPSHOT_FILE_NAME),
            AUTHORITY_RECORD_MAX_BYTES,
            "authority",
            &private_root,
        )?
        .ok_or_else(|| MISMATCH.to_owned())?;
        if canonical_json_bytes(&value).map_err(snapshot_error)? != bytes {
            return Err(MISMATCH.to_owned());
        }
        let record: PolicyAuthorityRecord =
            serde_json::from_value(value).map_err(|_| MISMATCH.to_owned())?;
        let snapshot = record.snapshot.ok_or_else(|| MISMATCH.to_owned())?;
        if !matches!(
            record.schema.as_str(),
            AUTHORITY_RECORD_SCHEMA | AUTHORITY_RECORD_V4_SCHEMA
        ) || record.generation_floor == 0
            || !is_lower_hex(&record.policy_digest, 64)
            || !is_lower_hex(&record.floor_mac, 64)
            || *snapshot.generation() != record.generation_floor
            || snapshot.policy_digest() != &record.policy_digest
            || (record.schema == AUTHORITY_RECORD_V4_SCHEMA)
                != snapshot.source_input_digest().is_some()
        {
            return Err(MISMATCH.to_owned());
        }
        let approval = approval_authority::public_record_fingerprint(state_base)?;
        let approval_v4 = approval_v4_authority::public_record_fingerprint(state_base)?;
        let after = fingerprint_set(state_base)?;
        if before != after
            || approval != after.approval
            || approval_v4 != after.approval_v4
            || *snapshot.expires_at_ms() <= now_ms()?
        {
            return Err(MISMATCH.to_owned());
        }
        Ok(after)
    }
}
