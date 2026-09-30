//! A decision holds the control mutation lease through evaluation or approval
//! finalization. Its authenticated marker is independent of daemon liveness.

use super::policy_store_persistence::read_private_json;
use super::PolicySnapshotStore;
use guard_contracts::{NativeCommandControlAuthorityV1, NativeCommandControlRecoveryV1};
use guard_policy_snapshot::{canonical_json_bytes, PolicySnapshotV3};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;

const MARKER_FILE: &str = "command-control-authority.v1.json";
const MARKER_SCHEMA: &str = "guard.native-command-control-authority.v1";
const MARKER_DOMAIN: &[u8] = b"hol-guard.native-command-control-authority.v1\0";
const MAX_MARKER_BYTES: u64 = 4_096;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandAuthorityMarker {
    schema: String,
    epoch: u64,
    mutation_revision: u64,
    authority_key_id: String,
    phase: String,
    effective_digest: Option<String>,
    recovery: Option<NativeCommandControlRecoveryV1>,
    mac: String,
}

pub(crate) struct CommandAuthorityLease {
    _file: File,
}

impl PolicySnapshotStore {
    pub(crate) fn command_authority_lease(
        &self,
        snapshot: &PolicySnapshotV3,
    ) -> Result<Option<CommandAuthorityLease>, String> {
        let Some(binding) = &snapshot.command_extensions else {
            return Ok(None);
        };
        let expected = binding
            .authority
            .as_ref()
            .ok_or_else(|| "native_command_control_authority_missing".to_owned())?;
        let state_base = self
            .authority_path
            .parent()
            .ok_or_else(|| "native_command_control_authority_path_invalid".to_owned())?;
        let private_root = crate::resident_state::private_root_for_state_base(state_base)?;
        let file = open_mutation_lock(
            &private_root.join("extension-control-authority.lock"),
            &private_root,
        )?;
        fs2::FileExt::try_lock_shared(&file)
            .map_err(|_| "native_command_control_mutation_in_progress".to_owned())?;
        let marker_path = state_base.join(MARKER_FILE);
        let (mut value, bytes) = read_private_json(
            &marker_path,
            MAX_MARKER_BYTES,
            "command_authority",
            &private_root,
        )?
        .ok_or_else(|| "native_command_control_authority_missing".to_owned())?;
        let canonical = canonical_json_bytes(&value)
            .map_err(|_| "native_command_control_authority_invalid".to_owned())?;
        if bytes != canonical && bytes.strip_suffix(b"\n") != Some(canonical.as_slice()) {
            return Err("native_command_control_authority_noncanonical".to_owned());
        }
        let object = value
            .as_object()
            .ok_or_else(|| "native_command_control_authority_invalid".to_owned())?;
        if object.len() != 8
            || [
                "schema",
                "epoch",
                "mutation_revision",
                "authority_key_id",
                "phase",
                "effective_digest",
                "recovery",
                "mac",
            ]
            .iter()
            .any(|key| !object.contains_key(*key))
        {
            return Err("native_command_control_authority_invalid".to_owned());
        }
        let marker: CommandAuthorityMarker = serde_json::from_value(value.clone())
            .map_err(|_| "native_command_control_authority_invalid".to_owned())?;
        let authority = NativeCommandControlAuthorityV1 {
            epoch: marker.epoch,
            mutation_revision: marker.mutation_revision,
            authority_key_id: marker.authority_key_id,
            recovery: marker.recovery,
        };
        authority.validate().map_err(str::to_owned)?;
        if marker.schema != MARKER_SCHEMA
            || marker.phase != "committed"
            || marker.effective_digest.as_deref() != Some(binding.effective_digest.as_str())
            || &authority != expected
        {
            return Err("native_command_control_authority_not_current".to_owned());
        }
        value
            .as_object_mut()
            .ok_or_else(|| "native_command_control_authority_invalid".to_owned())?
            .remove("mac");
        let body = canonical_json_bytes(&value)
            .map_err(|_| "native_command_control_authority_invalid".to_owned())?;
        let mut authenticated = Vec::with_capacity(MARKER_DOMAIN.len() + body.len());
        authenticated.extend_from_slice(MARKER_DOMAIN);
        authenticated.extend_from_slice(&body);
        if marker.mac.len() != 64
            || !marker
                .mac
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("native_command_control_authority_mac_invalid".to_owned());
        }
        let tag = hex::decode(marker.mac)
            .map_err(|_| "native_command_control_authority_mac_invalid".to_owned())?;
        if tag.len() != 32 {
            return Err("native_command_control_authority_mac_invalid".to_owned());
        }
        ring::hmac::verify(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.verifier_key),
            &authenticated,
            &tag,
        )
        .map_err(|_| "native_command_control_authority_mac_invalid".to_owned())?;
        Ok(Some(CommandAuthorityLease { _file: file }))
    }
}

fn open_mutation_lock(path: &Path, private_root: &Path) -> Result<File, String> {
    super::policy_store_validation::validate_private_directory(private_root)?;
    #[cfg(windows)]
    {
        crate::resident_state::open_private_read(
            path,
            MAX_MARKER_BYTES,
            "command_mutation_lock",
            private_root,
        )?
        .ok_or_else(|| "native_command_control_mutation_lock_missing".to_owned())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "native_command_control_mutation_lock_missing".to_owned())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
            return Err("native_command_control_mutation_lock_invalid".to_owned());
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| "native_command_control_mutation_lock_invalid".to_owned())?;
        let opened = file
            .metadata()
            .map_err(|_| "native_command_control_mutation_lock_invalid".to_owned())?;
        let root = std::fs::symlink_metadata(private_root)
            .map_err(|_| "native_command_control_mutation_lock_invalid".to_owned())?;
        if !opened.is_file()
            || opened.nlink() != 1
            || opened.dev() != metadata.dev()
            || opened.ino() != metadata.ino()
            || opened.uid() != root.uid()
            || opened.permissions().mode() & 0o077 != 0
        {
            return Err("native_command_control_mutation_lock_invalid".to_owned());
        }
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err("native_command_control_mutation_lock_unsupported".to_owned())
    }
}
