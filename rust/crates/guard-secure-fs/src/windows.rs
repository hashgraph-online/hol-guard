use std::io::{self, Read};
use std::path::Path;

use guard_rules::MAX_SCAN_BYTES;
use guard_runtime_windows_process::SourceFile;
use sha2::{Digest, Sha256};

use super::{FileIdentity, SecureRead, SecureReadError};

pub fn read_bounded(path: &Path, max_bytes: usize) -> Result<SecureRead, SecureReadError> {
    let max_bytes = max_bytes.min(MAX_SCAN_BYTES);
    let mut file = SourceFile::open(path).map_err(map_open_error)?;
    let before = file.identity().map_err(map_open_error)?;
    if before.links != 1 {
        return Err(SecureReadError::HardLinkedFile);
    }
    if before.size > max_bytes as u64 {
        return Err(SecureReadError::TooLarge);
    }
    file.validate_path()
        .map_err(|_| SecureReadError::PathChanged)?;
    let mut bytes = Vec::with_capacity(before.size as usize);
    file.by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SecureReadError::ReadFailed)?;
    if bytes.len() > max_bytes {
        return Err(SecureReadError::TooLarge);
    }
    let after = file.identity().map_err(map_open_error)?;
    if before != after || bytes.len() as u64 != before.size {
        return Err(SecureReadError::Changed);
    }
    file.validate_path()
        .map_err(|_| SecureReadError::PathChanged)?;
    // FILETIME counts 100 ns intervals from 1601; the public identity uses
    // nanoseconds from 1970, matching the existing Unix representation.
    let mtime_ns = u128::from(after.modified_100ns.saturating_sub(116_444_736_000_000_000)) * 100;
    let identity = FileIdentity {
        dev: Some(after.volume),
        ino: Some(after.index),
        size: after.size,
        mtime_ns,
        mode: after.attributes,
        nlink: after.links,
    };
    let sha256 = hex::encode(Sha256::digest(&bytes));
    Ok(SecureRead {
        bytes,
        identity,
        sha256,
    })
}

fn map_open_error(error: io::Error) -> SecureReadError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => SecureReadError::PermissionDenied,
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => SecureReadError::PathChanged,
        _ => SecureReadError::ReadFailed,
    }
}
