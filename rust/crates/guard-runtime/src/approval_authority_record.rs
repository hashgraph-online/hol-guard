//! Decode and authenticate a public enrollment record without a lifecycle transition.

use super::{verify_enrollment, ApprovalAuthorityRecordV1, APPROVAL_AUTHORITY_MAX_BYTES};
use guard_policy_snapshot::canonical_json_bytes;
use std::path::Path;

pub(super) fn read_authority_record(
    path: &Path,
    private_root: &Path,
) -> Result<Option<(ApprovalAuthorityRecordV1, Vec<u8>, String)>, String> {
    let Some((value, bytes)) = super::super::read_private_json(
        path,
        APPROVAL_AUTHORITY_MAX_BYTES,
        "approval_authority",
        private_root,
    )?
    else {
        return Ok(None);
    };
    let canonical =
        canonical_json_bytes(&value).map_err(|_| "native_approval_authority_invalid".to_owned())?;
    if canonical != bytes {
        return Err("native_approval_authority_noncanonical".to_owned());
    }
    let record: ApprovalAuthorityRecordV1 = serde_json::from_value(value)
        .map_err(|_| "native_approval_authority_invalid".to_owned())?;
    let _ = verify_enrollment(&record)?;
    let fingerprint = super::super::authority_fingerprint(path)
        .ok_or_else(|| "native_approval_authority_invalid".to_owned())?;
    Ok(Some((record, bytes, fingerprint)))
}
