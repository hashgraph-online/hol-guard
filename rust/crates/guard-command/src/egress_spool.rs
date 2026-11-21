//! Response bodies the caller hands over by file because they are too big to
//! inline in the request. The file must be a plain name inside the spool
//! directory the request designated, opened without following symlinks.

use std::io::Read;
use std::path::Path;

use guard_contracts::EGRESS_MAX_INLINE_BODY_BYTES;

use crate::guard_sync_transport::SyncHttpError;

const MAX_SPOOL_FILE_NAME_BYTES: usize = 128;

pub(crate) fn response_body(
    inline: Option<&str>,
    file: Option<&str>,
    spool: Option<&Path>,
    max_response_bytes: u64,
) -> Result<Vec<u8>, SyncHttpError> {
    let other = |message: &str| SyncHttpError::Other(message.to_owned());
    match (inline, file) {
        (None, None) => Ok(Vec::new()),
        (Some(_), Some(_)) => Err(other("egress response carries two bodies")),
        (Some(text), None) => {
            if text.len() > EGRESS_MAX_INLINE_BODY_BYTES || text.len() as u64 > max_response_bytes {
                return Err(other("egress response body too large"));
            }
            Ok(text.as_bytes().to_vec())
        }
        (None, Some(name)) => {
            let plain = !name.is_empty()
                && name.len() <= MAX_SPOOL_FILE_NAME_BYTES
                && !name.starts_with('.')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            let (true, Some(dir)) = (plain, spool) else {
                return Err(other("egress response file is not in the spool directory"));
            };
            read_spool_file(&dir.join(name), max_response_bytes)
        }
    }
}

fn read_spool_file(path: &Path, max_response_bytes: u64) -> Result<Vec<u8>, SyncHttpError> {
    let other = |message: &str| SyncHttpError::Other(message.to_owned());
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| other("egress response file unreadable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| other("egress response file unreadable"))?;
    if !metadata.is_file() {
        return Err(other("egress response file is not a regular file"));
    }
    if metadata.len() > max_response_bytes {
        return Err(other("egress response body too large"));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(max_response_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| other("egress response file unreadable"))?;
    if bytes.len() as u64 > max_response_bytes {
        return Err(other("egress response body too large"));
    }
    Ok(bytes)
}
