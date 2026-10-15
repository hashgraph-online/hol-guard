//! Bounded response headers, streaming digest, and immutable temporary blob.

use super::restricted_archive::{
    require_remaining, ReadableResponse, RestrictedArchiveDownload, RestrictedDownloadError,
};
use super::restricted_archive_destination::urlsplit;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Instant;

const READ_CHUNK_BYTES: u64 = 64 * 1024;
const MAX_RESPONSE_HEADERS: usize = 64;
const MAX_RESPONSE_HEADER_BYTES: u64 = 32 * 1024;

static HTTP_FIELD_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$").unwrap());

/// `_response_header` (restricted_archive_stream.py).
pub(super) fn response_header(response: &dyn ReadableResponse, name: &str) -> Option<String> {
    response.get_header(name)
}

/// `_validate_response_headers` (restricted_archive_stream.py).
pub(super) fn validate_response_headers(
    response: &dyn ReadableResponse,
) -> Result<(), RestrictedDownloadError> {
    let invalid = || {
        RestrictedDownloadError::new(
            "external_archive_response_headers_invalid",
            "External archive response headers were malformed or exceeded Guard's limit.",
        )
    };
    let headers = response.header_items();
    if headers.len() > MAX_RESPONSE_HEADERS {
        return Err(invalid());
    }
    let mut total_bytes: u64 = 0;
    for (name, value) in &headers {
        let name_valid = HTTP_FIELD_NAME_RE.is_match(name);
        let value_valid = !value.chars().any(|ch| {
            let code = ch as u32;
            (code < 0x20 && ch != '\t') || code == 0x7f
        });
        if !name_valid || !value_valid {
            return Err(invalid());
        }
        total_bytes += name.len() as u64 + value.len() as u64 + 4;
        if total_bytes > MAX_RESPONSE_HEADER_BYTES {
            return Err(invalid());
        }
    }
    Ok(())
}

/// `_content_length` (restricted_archive_stream.py).
fn content_length(
    response: &dyn ReadableResponse,
    max_bytes: u64,
) -> Result<Option<u64>, RestrictedDownloadError> {
    let invalid = || {
        RestrictedDownloadError::new(
            "external_archive_incomplete_response",
            "External archive response declared an invalid content length.",
        )
    };
    let raw_length = match response_header(response, "Content-Length") {
        Some(value) => value,
        None => return Ok(None),
    };
    let parsed = match raw_length.trim().parse::<i64>() {
        Ok(value) => value,
        Err(_) => return Err(invalid()),
    };
    if parsed < 0 {
        return Err(invalid());
    }
    if parsed as u64 > max_bytes {
        return Err(RestrictedDownloadError::new(
            "external_archive_download_size_limit",
            "External archive exceeded Guard's download size limit.",
        ));
    }
    Ok(Some(parsed as u64))
}

/// `_write_chunk_with_deadline` (restricted_archive_stream.py) — write the
/// full chunk or fail; the deadline budget is enforced by the caller.
/// `_write_bounded_response` (restricted_archive_stream.py).
pub(super) fn write_bounded_response(
    response: &mut dyn ReadableResponse,
    source_url: &str,
    final_url: &str,
    deadline: Instant,
    max_bytes: u64,
    temp_dir: Option<&Path>,
) -> Result<RestrictedArchiveDownload, RestrictedDownloadError> {
    let content_encoding = response_header(response, "Content-Encoding")
        .unwrap_or_else(|| "identity".to_string())
        .trim()
        .to_ascii_lowercase();
    if !content_encoding.is_empty() && content_encoding != "identity" {
        return Err(RestrictedDownloadError::new(
            "external_archive_content_encoding_rejected",
            "External archive response used an unsupported content encoding.",
        ));
    }
    let expected_size = content_length(response, max_bytes)?;
    let directory = match temp_dir {
        Some(dir) => dir.to_path_buf(),
        None => std::env::temp_dir(),
    }
    .canonicalize()
    .map_err(|_| {
        RestrictedDownloadError::new(
            "external_archive_connection_failed",
            "External archive temporary blob could not be created.",
        )
    })?;
    let (_, _, source_path, _) = urlsplit(source_url);
    let source_path = source_path.to_ascii_lowercase();
    let suffix = [".tar.gz", ".tgz", ".tar"]
        .into_iter()
        .find(|suffix| source_path.ends_with(suffix))
        .unwrap_or(".archive");
    // `tempfile.mkstemp(prefix="hol-guard-archive-", suffix=".archive")`.
    let mut path = PathBuf::new();
    let mut file = None;
    for _ in 0..128 {
        let mut random_bytes = [0u8; 8];
        if getrandom::fill(&mut random_bytes).is_err() {
            return Err(RestrictedDownloadError::new(
                "external_archive_connection_failed",
                "External archive temporary blob could not be created.",
            ));
        }
        let candidate = directory.join(format!(
            "hol-guard-archive-{}{}{suffix}",
            hex::encode(random_bytes),
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(opened) => {
                path = candidate;
                file = Some(opened);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => {
                return Err(RestrictedDownloadError::new(
                    "external_archive_connection_failed",
                    "External archive temporary blob could not be created.",
                ))
            }
        }
    }
    let mut file = match file {
        Some(file) => file,
        None => {
            return Err(RestrictedDownloadError::new(
                "external_archive_connection_failed",
                "External archive temporary blob could not be created.",
            ))
        }
    };
    let mut digest = Sha256::new();
    let mut size: u64 = 0;
    let result =
        (|file: &mut std::fs::File| -> Result<RestrictedArchiveDownload, RestrictedDownloadError> {
            require_remaining(deadline)?;
            let mut writer = crate::restricted_archive_write::BlobWriter::start(file, &path)?;
            loop {
                response.set_timeout(require_remaining(deadline)?);
                // Keep one byte of overflow probe capacity.
                let remaining_with_probe = max_bytes.saturating_sub(size) + 1;
                let chunk = response.read(
                    usize::try_from(remaining_with_probe.min(READ_CHUNK_BYTES))
                        .unwrap_or(usize::MAX),
                )?;
                if chunk.is_empty() {
                    break;
                }
                size += chunk.len() as u64;
                if size > max_bytes {
                    return Err(RestrictedDownloadError::new(
                        "external_archive_download_size_limit",
                        "External archive exceeded Guard's download size limit.",
                    ));
                }
                writer.write(&chunk, deadline)?;
                digest.update(&chunk);
                require_remaining(deadline)?;
            }
            if let Some(expected) = expected_size {
                if size != expected {
                    return Err(RestrictedDownloadError::new(
                        "external_archive_incomplete_response",
                        "External archive response ended before its declared content length.",
                    ));
                }
            }
            writer.finish(deadline)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(0o400))
                    .map_err(|_| {
                        RestrictedDownloadError::new(
                            "external_archive_connection_failed",
                            "External archive temporary blob could not be locked read-only.",
                        )
                    })?;
            }
            #[cfg(windows)]
            {
                let mut permissions = file
                    .metadata()
                    .map_err(|_| {
                        RestrictedDownloadError::new(
                            "external_archive_connection_failed",
                            "External archive temporary blob could not be locked read-only.",
                        )
                    })?
                    .permissions();
                permissions.set_readonly(true);
                file.set_permissions(permissions).map_err(|_| {
                    RestrictedDownloadError::new(
                        "external_archive_connection_failed",
                        "External archive temporary blob could not be locked read-only.",
                    )
                })?;
            }
            require_remaining(deadline)?;
            Ok(RestrictedArchiveDownload {
                path: path.clone(),
                sha256: hex::encode(digest.finalize()),
                size,
                source_url: source_url.to_string(),
                final_url: final_url.to_string(),
            })
        })(&mut file);
    drop(file);
    if result.is_err() {
        #[cfg(windows)]
        if let Ok(metadata) = std::fs::metadata(&path) {
            let mut permissions = metadata.permissions();
            permissions.set_readonly(false);
            let _ = std::fs::set_permissions(&path, permissions);
        }
        let _ = std::fs::remove_file(&path);
    }
    result
}
