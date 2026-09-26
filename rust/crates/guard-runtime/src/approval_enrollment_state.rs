#![forbid(unsafe_code)]

#[cfg(not(test))]
use super::account_for_state_base;
use super::{valid_digest, MAX_SECRET_TEXT_BYTES, STATE_VERSION};
use guard_policy_snapshot::canonical_json_bytes;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::fs;
use std::path::Path;

#[cfg(test)]
const TEST_ENROLLMENT_STATE_FILE_NAME: &str = "approval-enrollment-state.test.json";

#[derive(Debug, Clone)]
pub(crate) struct SecureApprovalState {
    pub(crate) generation: u64,
    pub(crate) device_binding: String,
    pub(crate) installation_binding: String,
    pub(crate) key_id: String,
    pub(crate) status: String,
    pub(crate) pending: bool,
    /// Digest of the exact canonical, root-signed authority record awaiting installation.
    /// It makes interrupted transitions retryable only for the same authenticated candidate.
    pub(crate) pending_record_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecureApprovalStateRecord {
    version: u16,
    generation: u64,
    device_binding: String,
    installation_binding: String,
    key_id: String,
    status: String,
    pending: bool,
    pending_record_digest: String,
}

pub(super) fn encode_state(state: &SecureApprovalState) -> Result<String, String> {
    let record = SecureApprovalStateRecord {
        version: STATE_VERSION,
        generation: state.generation,
        device_binding: state.device_binding.clone(),
        installation_binding: state.installation_binding.clone(),
        key_id: state.key_id.clone(),
        status: state.status.clone(),
        pending: state.pending,
        pending_record_digest: state.pending_record_digest.clone(),
    };
    let value = serde_json::to_value(record)
        .map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    let bytes = canonical_json_bytes(&value)
        .map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    Ok(hex::encode(bytes))
}

fn decode_state(value: &str) -> Result<SecureApprovalState, String> {
    if value.is_empty() || value.len() > MAX_SECRET_TEXT_BYTES || value.len() % 2 != 0 {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    let bytes =
        hex::decode(value).map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    let record: SecureApprovalStateRecord = serde_json::from_slice(&bytes)
        .map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    if record.version != STATE_VERSION
        || (record.generation == 0 && !record.pending)
        || (record.generation > 0 && record.pending && record.key_id.is_empty())
        || !valid_digest(&record.device_binding)
        || !valid_digest(&record.installation_binding)
        || record.device_binding == record.installation_binding
    {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    if record.generation == 0 {
        if !record.key_id.is_empty() || record.status != "pending" {
            return Err("native_approval_secure_state_invalid".to_owned());
        }
        if !record.pending_record_digest.is_empty() {
            return Err("native_approval_secure_state_invalid".to_owned());
        }
    } else if !valid_digest(&record.key_id)
        || !matches!(record.status.as_str(), "active" | "revoked")
    {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    if record.pending && record.generation > 0 && !valid_digest(&record.pending_record_digest) {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    if !record.pending && !record.pending_record_digest.is_empty() {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    Ok(SecureApprovalState {
        generation: record.generation,
        device_binding: record.device_binding,
        installation_binding: record.installation_binding,
        key_id: record.key_id,
        status: record.status,
        pending: record.pending,
        pending_record_digest: record.pending_record_digest,
    })
}

pub(crate) fn load_unlocked(state_base: &Path) -> Result<Option<SecureApprovalState>, String> {
    #[cfg(test)]
    {
        let path = state_base.join(TEST_ENROLLMENT_STATE_FILE_NAME);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("native_approval_secure_state_unavailable".to_owned()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("native_approval_secure_state_invalid".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err("native_approval_secure_state_invalid".to_owned());
            }
        }
        let encoded = fs::read_to_string(path)
            .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
        Ok(Some(decode_state(encoded.trim())?))
    }
    #[cfg(not(test))]
    {
        let account = account_for_state_base(state_base)?;
        let Some(value) = super::read_platform_secret(&account)? else {
            return Ok(None);
        };
        Ok(Some(decode_state(&value)?))
    }
}

#[cfg(test)]
pub(crate) fn write_test_enrollment_bindings(
    state_base: &Path,
    device_binding: &str,
    installation_binding: &str,
) -> Result<(), String> {
    super::super::validate_private_directory(state_base)?;
    if !valid_digest(device_binding)
        || !valid_digest(installation_binding)
        || device_binding == installation_binding
    {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    let state = SecureApprovalState {
        generation: 0,
        device_binding: device_binding.to_owned(),
        installation_binding: installation_binding.to_owned(),
        key_id: String::new(),
        status: "pending".to_owned(),
        pending: true,
        pending_record_digest: String::new(),
    };
    let encoded = encode_state(&state)?;
    let path = state_base.join(TEST_ENROLLMENT_STATE_FILE_NAME);
    let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
    super::super::policy_store_persistence::persist_private_bytes(
        &path,
        encoded.as_bytes(),
        MAX_SECRET_TEXT_BYTES as u64,
        "approval_enrollment_test_state",
        &private_root,
    )
    .map_err(|_| "native_approval_secure_state_unavailable".to_owned())
}
