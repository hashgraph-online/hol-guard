//! Exclusive creation of a new Python v1 quota lifetime in private storage.

use crate::crypto::is_sha256;
use crate::io::open_absolute_directory;
use crate::provider_quota::{digest, invalid, root_owned_by_reader};
use crate::provider_quota_writer::{random_id, ProviderQuotaWriter};
use crate::{canonical_value, EvidenceError, Result};
use rustix::fs::{fstat, fsync, mkdirat, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::path::Path;

fn io(error: impl std::fmt::Display) -> EvidenceError {
    EvidenceError::Io(error.to_string())
}

fn authorization_id_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

fn create_file(root: &OwnedFd, name: &str, bytes: &[u8]) -> Result<()> {
    let descriptor = openat(
        root,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(io)?;
    let created = fstat(&descriptor).map_err(io)?;
    if FileType::from_raw_mode(created.st_mode) != FileType::RegularFile
        || created.st_uid != geteuid().as_raw()
        || created.st_mode & 0o7777 != 0o600
        || created.st_nlink != 1
    {
        return Err(invalid("new quota file is not private"));
    }
    let mut file = File::from(descriptor);
    file.write_all(bytes).map_err(io)?;
    file.sync_all().map_err(io)?;
    let after = fstat(&file).map_err(io)?;
    let named = statat(root, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io)?;
    if after.st_size != bytes.len() as i64
        || after.st_dev != created.st_dev
        || after.st_ino != created.st_ino
        || named.st_dev != created.st_dev
        || named.st_ino != created.st_ino
    {
        return Err(invalid("new quota file changed while creating"));
    }
    Ok(())
}

impl ProviderQuotaWriter {
    /// Create one new lifetime in an owner-only parent directory. The caller
    /// must independently retain the authorization and model identity pins.
    /// Any interrupted creation leaves its exact path unusable, never reset.
    pub fn create_new(
        root: &Path,
        authorization_id: &str,
        total_tokens: u64,
        maximum_requests: u64,
        model_identity_digest: &str,
    ) -> Result<Self> {
        if !authorization_id_valid(authorization_id)
            || !(1..=1_000_000_000).contains(&total_tokens)
            || !(1..=10_000).contains(&maximum_requests)
            || !is_sha256(model_identity_digest)
        {
            return Err(invalid("invalid new provider quota authorization"));
        }
        let parent = root
            .parent()
            .ok_or(invalid("new canonical absolute quota directory required"))?;
        let name = root
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty() && *name != "." && *name != "..")
            .ok_or(invalid("new canonical absolute quota directory required"))?;
        let parent_descriptor = open_absolute_directory(parent)?;
        root_owned_by_reader(parent, &parent_descriptor)?;
        mkdirat(&parent_descriptor, name, Mode::from_bits_truncate(0o700)).map_err(io)?;
        fsync(&parent_descriptor).map_err(io)?;
        let directory = openat(
            &parent_descriptor,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io)?;
        root_owned_by_reader(root, &directory)?;
        let config = json!({
            "schema":"gauntlet-provider-quota.v1",
            "authorization_id":authorization_id,
            "quota_id":random_id()?,
            "total_tokens":total_tokens,
            "maximum_requests":maximum_requests,
            "model_identity_digest":model_identity_digest,
            "maximum_inflight":1,
        });
        let config_digest = digest(&config)?;
        let mut bytes = canonical_value(&config)?;
        bytes.push(b'\n');
        create_file(&directory, "config.json", &bytes)?;
        create_file(&directory, "events.jsonl", b"")?;
        create_file(&directory, "quota.lock", b"")?;
        fsync(&directory).map_err(io)?;
        fsync(&parent_descriptor).map_err(io)?;
        Self::open_existing(root, &config_digest, None)
    }
}

#[cfg(test)]
mod tests {
    use super::ProviderQuotaWriter;
    use crate::read_provider_quota_snapshot;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn new_quota_is_private_python_v1_and_cannot_be_reset() {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = parent.join("quota");
        let writer = ProviderQuotaWriter::create_new(
            &root,
            "external-authorization",
            100,
            3,
            &"a".repeat(64),
        )
        .unwrap();
        let config: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("config.json")).unwrap()).unwrap();
        let digest = crate::provider_quota::digest(&config).unwrap();
        assert_eq!(writer.config_digest(), digest);
        assert_eq!(writer.allowance_digest(), None);
        let snapshot = read_provider_quota_snapshot(&root, &digest, None).unwrap();
        assert_eq!(snapshot["token_cap"], 100);
        assert_eq!(snapshot["requests"], 0);
        assert_eq!(snapshot["journal_hash"], "0".repeat(64));
        assert!(ProviderQuotaWriter::create_new(
            &root,
            "external-authorization",
            100,
            3,
            &"a".repeat(64)
        )
        .is_err());
        assert!(ProviderQuotaWriter::create_new(
            &parent.join("invalid"),
            "../bad",
            100,
            3,
            &"a".repeat(64)
        )
        .is_err());
    }
}
