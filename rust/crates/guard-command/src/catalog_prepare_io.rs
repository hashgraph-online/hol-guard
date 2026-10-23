//! Private immutable metadata CAS. No policy programs are admitted here.
use crate::native_command_program::source::PackObjectRef;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

pub(super) const OBJECT_BYTES: usize = 65_536;
pub(super) const BLOB_BYTES: usize = 8 * 1024 * 1024;
pub(super) type Result<T> = std::result::Result<T, &'static str>;

pub(super) fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn nonce() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| "catalog_prepare_entropy_failed")?;
    Ok(hex::encode(bytes))
}

/// One sparse, disposable hash table, not one filesystem inode per permission.
/// 33 bytes per slot (occupied flag + SHA256), at most 2^27 slots, load <= 1/2.
/// The bound derives from the unchanged 100,000 extensions x 512 permissions.
/// No payloads are retained; a claim uses one 33-byte stack buffer. Colliding
/// digests fail closed as duplicates. This scratch state is never authority.
struct ScratchPath(std::path::PathBuf);
impl Drop for ScratchPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
pub(super) struct Ownership {
    file: fs::File,
    _path: ScratchPath,
    slots: u64,
}
impl Ownership {
    pub fn new(path: std::path::PathBuf, extensions: usize) -> Result<Self> {
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // DELETE access + FILE_FLAG_DELETE_ON_CLOSE also reclaim scratch
            // after process termination, without a startup directory sweep.
            options.access_mode(0xc0010000).custom_flags(0x04000000);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|_| "catalog_prepare_permission_ownership")?;
        let slots = (extensions as u64 * 512 * 2).next_power_of_two();
        let result = Self {
            file,
            _path: ScratchPath(path.clone()),
            slots,
        };
        result
            .file
            .set_len(slots * 33)
            .map_err(|_| "catalog_prepare_permission_ownership")?;
        // POSIX reclaims even after a killed/crashed resident. On Windows the
        // fields drop in declaration order: close the file, then remove it.
        #[cfg(unix)]
        fs::remove_file(path).map_err(|_| "catalog_prepare_permission_ownership")?;
        Ok(result)
    }
    pub fn claim(&mut self, identity: &str) -> Result<()> {
        let digest = Sha256::digest(identity.as_bytes());
        let first = u64::from_le_bytes(digest[..8].try_into().unwrap()) & (self.slots - 1);
        let mut operation = || -> std::io::Result<bool> {
            let mut slot = [0u8; 33];
            for step in 0..self.slots {
                let offset = ((first + step) & (self.slots - 1)) * 33;
                self.file.seek(SeekFrom::Start(offset))?;
                self.file.read_exact(&mut slot)?;
                if slot[0] == 0 {
                    slot[0] = 1;
                    slot[1..].copy_from_slice(&digest);
                    self.file.seek(SeekFrom::Start(offset))?;
                    self.file.write_all(&slot)?;
                    return Ok(true);
                }
                if slot[1..] == digest[..] {
                    return Ok(false);
                }
            }
            Ok(false)
        };
        if operation().map_err(|_| "catalog_prepare_permission_ownership")? {
            Ok(())
        } else {
            Err("catalog_prepare_permission_ownership")
        }
    }
}

pub(super) fn json(bytes: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| "catalog_prepare_json_invalid")?;
    if serde_json::to_vec(&value).map_err(|_| "catalog_prepare_json_invalid")? != bytes {
        return Err("catalog_prepare_json_noncanonical");
    }
    Ok(value)
}

pub(super) fn private_directory(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("catalog_prepare_home_invalid");
    }
    for parent in path.ancestors() {
        if fs::symlink_metadata(parent).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("catalog_prepare_symlink");
        }
    }
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|_| "catalog_prepare_directory_failed")?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "catalog_prepare_directory_failed")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("catalog_prepare_directory_invalid");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != nix::unistd::getuid().as_raw()
        {
            return Err("catalog_prepare_directory_not_private");
        }
    }
    Ok(())
}

pub(super) fn read(directory: &Path, digest: &str) -> Result<Vec<u8>> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("catalog_prepare_digest_invalid");
    }
    // Check cache directories and leaf on every read, including registered
    // handles. secure-fs additionally pins identities and rejects symlinks.
    let leaf = directory.join(format!("{digest}.json"));
    for path in directory
        .ancestors()
        .take(3)
        .chain(std::iter::once(leaf.as_path()))
    {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| "catalog_prepare_object_unavailable")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.permissions().mode() & 0o077 != 0
                || metadata.uid() != nix::unistd::getuid().as_raw()
            {
                return Err("catalog_prepare_directory_not_private");
            }
        }
        if metadata.file_type().is_symlink() {
            return Err("catalog_prepare_symlink");
        }
    }
    let result =
        guard_secure_fs::read_bounded(&directory.join(format!("{digest}.json")), OBJECT_BYTES)
            .map_err(|_| "catalog_prepare_object_unavailable")?;
    if hash(&result.bytes) != digest {
        return Err("catalog_prepare_object_corrupt");
    }
    Ok(result.bytes)
}

pub(super) fn put(
    directory: &Path,
    bytes: &[u8],
    kind: &str,
    expanded: usize,
) -> Result<PackObjectRef> {
    if bytes.is_empty() || bytes.len() > OBJECT_BYTES || expanded == 0 || expanded > BLOB_BYTES {
        return Err("catalog_prepare_object_budget");
    }
    private_directory(directory)?;
    let digest = hash(bytes);
    let destination = directory.join(format!("{digest}.json"));
    let replace = if fs::symlink_metadata(&destination).is_ok() {
        match read(directory, &digest) {
            Ok(saved) if saved == bytes => false,
            Err("catalog_prepare_object_corrupt") => true,
            Err(error) => return Err(error),
            _ => return Err("catalog_prepare_object_corrupt"),
        }
    } else {
        false
    };
    if replace || !destination.exists() {
        let temporary = directory.join(format!(".{}", nonce()?));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let publish = (|| {
            let mut file = options
                .open(&temporary)
                .map_err(|_| "catalog_prepare_write_failed")?;
            file.write_all(bytes)
                .map_err(|_| "catalog_prepare_write_failed")?;
            // Discovery is rebuildable metadata, never durable security state.
            // Publish atomically, but do not fsync each cache object. A crash
            // may lose objects; all reads still verify bounds, SHA and proofs,
            // and a restarted resident has no trusted registered handle.
            if replace {
                return fs::rename(&temporary, &destination)
                    .map_err(|_| "catalog_prepare_publish_failed");
            }
            match fs::hard_link(&temporary, &destination) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if read(directory, &digest)? == bytes {
                        Ok(())
                    } else {
                        Err("catalog_prepare_object_corrupt")
                    }
                }
                Err(_) => Err("catalog_prepare_publish_failed"),
            }
        })();
        let _ = fs::remove_file(temporary);
        publish?;
    }
    Ok(PackObjectRef {
        sha256: digest,
        length: bytes.len(),
        expanded_length: expanded,
        kind: kind.into(),
    })
}

pub(super) fn put_json_with(
    value: &Value,
    mut put: impl FnMut(&[u8], &str, usize) -> Result<PackObjectRef>,
) -> Result<PackObjectRef> {
    let bytes = serde_json::to_vec(value).map_err(|_| "catalog_prepare_json_invalid")?;
    if bytes.is_empty() || bytes.len() > BLOB_BYTES {
        return Err("catalog_prepare_blob_budget");
    }
    let mut refs = bytes
        .chunks(OBJECT_BYTES)
        .map(|part| put(part, "data", part.len()))
        .collect::<Result<Vec<_>>>()?;
    while refs.len() > 1 {
        refs = refs
            .chunks(64)
            .map(|parts| {
                // A reader admits a concatenation only when its bytes are the
                // canonical encoding of what they parse to, so sort the keys here
                // instead of relying on serde_json's selected Map implementation.
                let bytes = crate::native_command_program::canonical_json_bytes(
                    &json!({"schema":"guard.pack-concat.v1","parts":parts}),
                )
                .map_err(|_| "catalog_prepare_json_invalid")?;
                put(
                    &bytes,
                    "concat",
                    parts.iter().map(|p| p.expanded_length).sum(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
    }
    Ok(refs.remove(0))
}
