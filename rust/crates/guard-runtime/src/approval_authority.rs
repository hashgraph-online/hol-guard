//! External approval-authority enrollment and authenticated lifecycle.
//!
//! Approval signatures are verified against an authority independent from the
//! policy-integrity key. Python may publish policy snapshots, but it cannot
//! create or rotate this authority. A trusted installer supplies a record
//! signed by the release/device enrollment root; the resident pins the
//! accepted generation and provenance in the OS secure store.

use guard_policy_snapshot::canonical_json_bytes;
use ring::signature;
#[cfg(test)]
use ring::signature::KeyPair;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};

pub(super) const APPROVAL_AUTHORITY_FILE_NAME: &str = "approval-authority.v1.json";
const APPROVAL_AUTHORITY_SCHEMA: &str = "guard-native-approval-authority.v1";
const APPROVAL_AUTHORITY_VERSION: u16 = 1;
const APPROVAL_AUTHORITY_ALGORITHM: &str = "ed25519";
const APPROVAL_AUTHORITY_MAX_BYTES: u64 = 16 * 1024;
const APPROVAL_ENROLLMENT_DOMAIN: &[u8] = b"guard-native-approval-enrollment-v1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalAuthorityRecordV1 {
    schema: String,
    version: u16,
    algorithm: String,
    key_id: String,
    public_key: String,
    device_binding: String,
    installation_binding: String,
    enrollment_generation: u64,
    previous_key_id: Option<String>,
    status: String,
    enrollment_signature: String,
}

#[derive(Debug, Clone)]
pub(super) struct ApprovalAuthority {
    pub(super) public_key: [u8; 32],
    pub(super) key_id: String,
    pub(super) device_binding: String,
    pub(super) installation_binding: String,
    pub(super) path: PathBuf,
    pub(super) fingerprint: String,
}

const ENROLLMENT_REQUEST_SCHEMA: &str = "guard-native-approval-enrollment-request.v1";

#[cfg(test)]
fn enrollment_root_public_key() -> [u8; 32] {
    let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[42u8; 32]).unwrap();
    key_pair.public_key().as_ref().try_into().unwrap()
}

#[cfg(not(test))]
fn enrollment_root_public_key() -> Result<[u8; 32], String> {
    let encoded = option_env!("HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_HEX")
        .ok_or_else(|| "native_approval_authority_root_unconfigured".to_owned())?;
    let expected_fingerprint = option_env!("HOL_GUARD_APPROVAL_ENROLLMENT_ROOT_FINGERPRINT_HEX")
        .ok_or_else(|| "native_approval_authority_root_provenance_unconfigured".to_owned())?;
    let bytes =
        hex::decode(encoded).map_err(|_| "native_approval_authority_root_invalid".to_owned())?;
    let root: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "native_approval_authority_root_invalid".to_owned())?;
    if !super::is_lower_hex(expected_fingerprint, 64)
        || guard_policy_snapshot::digest_bytes(&root) != expected_fingerprint
    {
        return Err("native_approval_authority_root_provenance_invalid".to_owned());
    }
    Ok(root)
}

fn enrollment_signing_value(record: &ApprovalAuthorityRecordV1) -> Result<Value, String> {
    let mut value =
        serde_json::to_value(record).map_err(|_| "native_approval_authority_invalid".to_owned())?;
    value
        .as_object_mut()
        .ok_or_else(|| "native_approval_authority_invalid".to_owned())?
        .remove("enrollment_signature");
    Ok(value)
}

fn enrollment_signing_bytes(record: &ApprovalAuthorityRecordV1) -> Result<Vec<u8>, String> {
    canonical_json_bytes(&enrollment_signing_value(record)?)
        .map_err(|_| "native_approval_authority_invalid".to_owned())
}

fn verify_enrollment(record: &ApprovalAuthorityRecordV1) -> Result<[u8; 32], String> {
    if record.schema != APPROVAL_AUTHORITY_SCHEMA
        || record.version != APPROVAL_AUTHORITY_VERSION
        || record.algorithm != APPROVAL_AUTHORITY_ALGORITHM
        || record.enrollment_generation == 0
        || !matches!(record.status.as_str(), "active" | "revoked")
        || !super::is_lower_hex(&record.key_id, 64)
        || !super::is_lower_hex(&record.public_key, 64)
        || !super::is_lower_hex(&record.device_binding, 64)
        || !super::is_lower_hex(&record.installation_binding, 64)
        || record.device_binding == record.installation_binding
        || !super::is_lower_hex(&record.enrollment_signature, 128)
        || (record.enrollment_generation == 1 && record.previous_key_id.is_some())
    {
        return Err("native_approval_authority_invalid".to_owned());
    }
    if let Some(previous_key_id) = record.previous_key_id.as_ref() {
        if !super::is_lower_hex(previous_key_id, 64) || previous_key_id == &record.key_id {
            return Err("native_approval_authority_invalid".to_owned());
        }
    }
    let public_key_bytes = hex::decode(&record.public_key)
        .map_err(|_| "native_approval_authority_invalid".to_owned())?;
    let public_key: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| "native_approval_authority_invalid".to_owned())?;
    if record.key_id != guard_policy_snapshot::digest_bytes(&public_key) {
        return Err("native_approval_authority_key_id_mismatch".to_owned());
    }
    let signature_bytes = hex::decode(&record.enrollment_signature)
        .map_err(|_| "native_approval_authority_invalid".to_owned())?;
    let signing_bytes = enrollment_signing_bytes(record)?;
    let mut message = Vec::with_capacity(APPROVAL_ENROLLMENT_DOMAIN.len() + signing_bytes.len());
    message.extend_from_slice(APPROVAL_ENROLLMENT_DOMAIN);
    message.extend_from_slice(&signing_bytes);
    #[cfg(test)]
    let root = enrollment_root_public_key();
    #[cfg(not(test))]
    let root = enrollment_root_public_key()?;
    signature::UnparsedPublicKey::new(&signature::ED25519, root)
        .verify(&message, &signature_bytes)
        .map_err(|_| "native_approval_authority_enrollment_invalid".to_owned())?;
    Ok(public_key)
}

fn read_authority_record(
    path: &Path,
) -> Result<Option<(ApprovalAuthorityRecordV1, Vec<u8>, String)>, String> {
    let Some((value, bytes)) =
        super::read_private_json(path, APPROVAL_AUTHORITY_MAX_BYTES, "approval_authority")?
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
    let fingerprint = super::authority_fingerprint(path)
        .ok_or_else(|| "native_approval_authority_invalid".to_owned())?;
    Ok(Some((record, bytes, fingerprint)))
}

fn authority_record_digest(bytes: &[u8]) -> String {
    guard_policy_snapshot::digest_bytes(bytes)
}

pub(super) fn load(state_base: &Path) -> Result<Option<ApprovalAuthority>, String> {
    super::approval_enrollment::with_transition_lock(state_base, || load_locked(state_base))
}

fn load_locked(state_base: &Path) -> Result<Option<ApprovalAuthority>, String> {
    let path = state_base.join(APPROVAL_AUTHORITY_FILE_NAME);
    let Some((record, bytes, fingerprint)) = read_authority_record(&path)? else {
        // An unenrolled installation must not probe or mutate the platform
        // secure store during ordinary resident startup. Enrollment state is
        // consulted only after a signed public authority record exists; this
        // keeps fresh developer/CI homes usable without weakening the
        // fail-closed approval path (approval operations have no authority).
        return Ok(None);
    };
    #[cfg(test)]
    let _ = &bytes;
    let public_key = verify_enrollment(&record)?;
    #[cfg(not(test))]
    {
        let secure = super::approval_enrollment::load_unlocked(state_base)?
            .ok_or_else(|| "native_approval_secure_state_unavailable".to_owned())?;
        if secure.pending {
            if secure.generation != record.enrollment_generation
                || secure.key_id != record.key_id
                || secure.status != record.status
                || secure.device_binding != record.device_binding
                || secure.installation_binding != record.installation_binding
                || secure.pending_record_digest != authority_record_digest(&bytes)
            {
                return Err("native_approval_authority_provenance_mismatch".to_owned());
            }
            // A signed record is the only input allowed to complete a
            // previously-started secure-store transition. This makes a crash
            // between the secure-store and file phases recoverable without
            // accepting an unsigned or rolled-back record.
            super::approval_enrollment::complete_transition_unlocked(
                state_base,
                &authority_record_digest(&bytes),
                record.enrollment_generation,
                &record.key_id,
                &record.status,
                &record.device_binding,
                &record.installation_binding,
            )?;
        }
        let secure = super::approval_enrollment::load_unlocked(state_base)?
            .ok_or_else(|| "native_approval_secure_state_unavailable".to_owned())?;
        if !super::approval_enrollment::matches_authority(
            &secure,
            record.enrollment_generation,
            &record.key_id,
            &record.status,
            &record.device_binding,
            &record.installation_binding,
        ) {
            return Err("native_approval_authority_provenance_mismatch".to_owned());
        }
    }
    if record.status == "revoked" {
        return Err("native_approval_authority_revoked".to_owned());
    }
    Ok(Some(ApprovalAuthority {
        public_key,
        key_id: record.key_id,
        device_binding: record.device_binding,
        installation_binding: record.installation_binding,
        path,
        fingerprint,
    }))
}

/// Create the public half of the enrollment ceremony. The secure store
/// generates and retains the device/install identities; an external root-held
/// authority must include these digests in the signed authority record.
pub(crate) fn prepare_enrollment(state_base: &Path) -> Result<Vec<u8>, String> {
    super::validate_private_directory(state_base)?;
    let (device_binding, installation_binding) =
        super::approval_enrollment::prepare_enrollment(state_base)?;
    let value = serde_json::json!({
        "schema": ENROLLMENT_REQUEST_SCHEMA,
        "version": 1,
        "algorithm": APPROVAL_AUTHORITY_ALGORITHM,
        "enrollment_generation": 1,
        "status": "active",
        "device_binding": device_binding,
        "installation_binding": installation_binding,
    });
    canonical_json_bytes(&value)
        .map_err(|_| "native_approval_enrollment_request_invalid".to_owned())
}

fn candidate_matches_record(
    candidate: &ApprovalAuthorityRecordV1,
    current: &ApprovalAuthorityRecordV1,
) -> bool {
    candidate.schema == current.schema
        && candidate.version == current.version
        && candidate.algorithm == current.algorithm
        && candidate.key_id == current.key_id
        && candidate.public_key == current.public_key
        && candidate.device_binding == current.device_binding
        && candidate.installation_binding == current.installation_binding
        && candidate.enrollment_generation == current.enrollment_generation
        && candidate.previous_key_id == current.previous_key_id
        && candidate.status == current.status
        && candidate.enrollment_signature == current.enrollment_signature
}

/// Install or rotate an authority record supplied by the trusted enrollment
/// ceremony. The candidate is root-authenticated before any state changes;
/// rotations must name the currently pinned key and strictly advance the OS
/// secure generation. Revocation is represented by a signed `status` record.
pub(crate) fn install_record(state_base: &Path, record_path: &Path) -> Result<(), String> {
    super::approval_enrollment::with_transition_lock(state_base, || {
        install_record_locked(state_base, record_path)
    })
}

fn install_record_locked(state_base: &Path, record_path: &Path) -> Result<(), String> {
    super::validate_private_directory(state_base)?;
    let Some((candidate, bytes, _)) = read_authority_record(record_path)? else {
        return Err("native_approval_authority_missing".to_owned());
    };
    let target = state_base.join(APPROVAL_AUTHORITY_FILE_NAME);
    let existing = read_authority_record(&target)?;
    let secure = super::approval_enrollment::load_unlocked(state_base)?;
    let Some(secure) = secure else {
        return Err("native_approval_enrollment_required".to_owned());
    };
    if let Some((current, current_bytes, _)) = existing.as_ref() {
        if candidate_matches_record(&candidate, current) {
            if !secure.pending
                && secure.generation == candidate.enrollment_generation
                && secure.key_id == candidate.key_id
                && secure.status == candidate.status
            {
                return Ok(());
            }
            if secure.pending && secure.pending_record_digest != authority_record_digest(&bytes) {
                return Err("native_approval_authority_provenance_mismatch".to_owned());
            }
        } else if candidate.status == "revoked" {
            if candidate.key_id != current.key_id
                || candidate.previous_key_id.is_some()
                || candidate.enrollment_generation <= current.enrollment_generation
            {
                return Err("native_approval_authority_generation_rollback".to_owned());
            }
        } else if candidate.enrollment_generation <= current.enrollment_generation
            || candidate.previous_key_id.as_deref() != Some(current.key_id.as_str())
        {
            return Err("native_approval_authority_generation_rollback".to_owned());
        }
        if secure.pending
            && (secure.generation != candidate.enrollment_generation
                || secure.key_id != candidate.key_id
                || secure.status != candidate.status
                || secure.device_binding != candidate.device_binding
                || secure.installation_binding != candidate.installation_binding
                || secure.pending_record_digest != authority_record_digest(&bytes))
        {
            return Err("native_approval_authority_provenance_mismatch".to_owned());
        }
        if candidate.device_binding != secure.device_binding
            || candidate.installation_binding != secure.installation_binding
        {
            return Err("native_approval_authority_provenance_mismatch".to_owned());
        }
        let _ = current_bytes;
    } else {
        let is_prepared_initial = secure.pending
            && secure.generation == 0
            && candidate.enrollment_generation == 1
            && candidate.previous_key_id.is_none()
            && candidate.status == "active";
        let is_recoverable_initial = secure.pending
            && secure.generation == candidate.enrollment_generation
            && secure.generation > 0
            && secure.key_id == candidate.key_id
            && secure.status == candidate.status
            && secure.pending_record_digest == authority_record_digest(&bytes);
        if (!is_prepared_initial && !is_recoverable_initial)
            || candidate.enrollment_generation == 0
            || candidate.device_binding != secure.device_binding
            || candidate.installation_binding != secure.installation_binding
        {
            return Err("native_approval_authority_generation_invalid".to_owned());
        }
    }
    // The secure store first records a pending, monotonic transition. If the
    // process crashes before the file is installed, startup remains fail
    // closed and this command can safely retry the same signed record.
    super::approval_enrollment::begin_transition_unlocked(
        state_base,
        &authority_record_digest(&bytes),
        candidate.enrollment_generation,
        &candidate.key_id,
        &candidate.status,
        &candidate.device_binding,
        &candidate.installation_binding,
    )?;
    super::policy_store_persistence::persist_private_bytes(
        &target,
        &bytes,
        APPROVAL_AUTHORITY_MAX_BYTES,
        "approval_authority",
    )?;
    super::approval_enrollment::complete_transition_unlocked(
        state_base,
        &authority_record_digest(&bytes),
        candidate.enrollment_generation,
        &candidate.key_id,
        &candidate.status,
        &candidate.device_binding,
        &candidate.installation_binding,
    )?;
    Ok(())
}

#[cfg(test)]
fn test_bindings() -> (String, String) {
    (
        guard_policy_snapshot::digest_bytes(b"test-device-binding-v1"),
        guard_policy_snapshot::digest_bytes(b"test-installation-binding-v1"),
    )
}

#[cfg(test)]
fn test_record(
    public_key: &[u8; 32],
    enrollment_generation: u64,
    previous_key_id: Option<String>,
    status: &str,
    enrollment_signature: String,
) -> ApprovalAuthorityRecordV1 {
    let (device_binding, installation_binding) = test_bindings();
    ApprovalAuthorityRecordV1 {
        schema: APPROVAL_AUTHORITY_SCHEMA.to_owned(),
        version: APPROVAL_AUTHORITY_VERSION,
        algorithm: APPROVAL_AUTHORITY_ALGORITHM.to_owned(),
        key_id: guard_policy_snapshot::digest_bytes(public_key),
        public_key: hex::encode(public_key),
        device_binding,
        installation_binding,
        enrollment_generation,
        previous_key_id,
        status: status.to_owned(),
        enrollment_signature,
    }
}

#[cfg(test)]
pub(super) fn canonical_record_for_enrollment(
    public_key: &[u8; 32],
    enrollment_generation: u64,
    enrollment_signature: &str,
) -> Result<Vec<u8>, String> {
    let record = test_record(
        public_key,
        enrollment_generation,
        None,
        "active",
        enrollment_signature.to_owned(),
    );
    let value =
        serde_json::to_value(record).map_err(|_| "native_approval_authority_invalid".to_owned())?;
    canonical_json_bytes(&value).map_err(|_| "native_approval_authority_invalid".to_owned())
}

#[cfg(test)]
pub(super) fn enrollment_signature_for_tests(
    public_key: &[u8; 32],
    enrollment_generation: u64,
    signing_seed: &[u8; 32],
) -> Result<String, String> {
    let record = test_record(
        public_key,
        enrollment_generation,
        None,
        "active",
        String::new(),
    );
    let signing_bytes = enrollment_signing_bytes(&record)?;
    let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(signing_seed)
        .map_err(|_| "native_approval_authority_invalid".to_owned())?;
    let mut message = Vec::with_capacity(APPROVAL_ENROLLMENT_DOMAIN.len() + signing_bytes.len());
    message.extend_from_slice(APPROVAL_ENROLLMENT_DOMAIN);
    message.extend_from_slice(&signing_bytes);
    Ok(hex::encode(key_pair.sign(&message).as_ref()))
}

#[cfg(test)]
pub(super) fn test_enrollment_root_seed() -> [u8; 32] {
    [42u8; 32]
}

#[cfg(test)]
pub(crate) fn write_test_record(state_base: &Path, public_key: &[u8; 32], generation: u64) {
    let signature =
        enrollment_signature_for_tests(public_key, generation, &test_enrollment_root_seed())
            .unwrap();
    let bytes = canonical_record_for_enrollment(public_key, generation, &signature).unwrap();
    fs::write(state_base.join(APPROVAL_AUTHORITY_FILE_NAME), bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            state_base.join(APPROVAL_AUTHORITY_FILE_NAME),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
}

#[cfg(test)]
pub(super) fn verify_test_root_matches_compiled_key() {
    let expected: [u8; 32] = {
        let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[42u8; 32]).unwrap();
        key_pair.public_key().as_ref().try_into().unwrap()
    };
    assert_eq!(enrollment_root_public_key(), expected);
}

#[cfg(test)]
#[path = "approval_authority_tests.rs"]
mod tests;
