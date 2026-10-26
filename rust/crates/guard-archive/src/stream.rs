//! Descriptor-bound byte streams: the admission hash, the decompression
//! preflight, and the digest-verifying tee that both parse passes run through.
//!
//! The inspector reads the blob more than once (hash, preflight, parse). A
//! writer that can still reach the inode could show benign bytes to the passes
//! that enforce policy and the original bytes to the pass that proves the
//! digest. To close that window every policy pass reads the file *through* a
//! running SHA-256 and, once the pass is done, drains the rest of the file
//! into the same hasher. The pass is accepted only if the digest of exactly
//! the bytes it consumed equals the caller-bound digest.

use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::time::Instant;

use flate2::read::MultiGzDecoder;
use sha2::{Digest, Sha256};

use crate::{ArchiveCaps, ArchiveOutcome};

pub(crate) const HASH_CHUNK: usize = 64 * 1024;

pub(crate) enum HashFailure {
    Timeout,
    Halted,
    Io,
    OverLimit,
}

/// A running digest plus the number of bytes it has absorbed.
pub(crate) struct StreamDigest {
    digest: Sha256,
    size: u64,
}

impl StreamDigest {
    pub(crate) fn new() -> Self {
        Self {
            digest: Sha256::new(),
            size: 0,
        }
    }

    /// Absorb the rest of `source`, honoring the byte cap, deadline, and halt
    /// predicate exactly like `_hash_stream`.
    pub(crate) fn absorb_to_eof(
        &mut self,
        source: &mut impl Read,
        max_bytes: u64,
        deadline: Instant,
        halt: &dyn Fn() -> bool,
    ) -> Result<(), HashFailure> {
        let mut buffer = vec![0u8; HASH_CHUNK];
        loop {
            if halt() {
                return Err(HashFailure::Halted);
            }
            if Instant::now() > deadline {
                return Err(HashFailure::Timeout);
            }
            let count = source.read(&mut buffer).map_err(|_| HashFailure::Io)?;
            if count == 0 {
                return Ok(());
            }
            self.size += count as u64;
            if self.size > max_bytes {
                return Err(HashFailure::OverLimit);
            }
            self.digest.update(&buffer[..count]);
        }
    }

    pub(crate) fn finish(self) -> (String, u64) {
        (hex::encode(self.digest.finalize()), self.size)
    }
}

pub(crate) fn hash_stream(
    source: &mut impl Read,
    max_bytes: u64,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
) -> Result<(String, u64), HashFailure> {
    let mut digest = StreamDigest::new();
    digest.absorb_to_eof(source, max_bytes, deadline, halt)?;
    Ok(digest.finish())
}

/// Reader that hashes every byte it hands out.
struct TeeHash<'a> {
    inner: &'a mut File,
    digest: StreamDigest,
}

impl Read for TeeHash<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buf)?;
        self.digest.digest.update(&buf[..count]);
        self.digest.size += count as u64;
        Ok(count)
    }
}

/// The digest every policy pass must reproduce.
pub(crate) struct Binding<'a> {
    pub sha256: &'a str,
    pub size: u64,
    pub actual: &'a Option<String>,
}

fn incomplete(binding: &Binding<'_>) -> ArchiveOutcome {
    ArchiveOutcome::incomplete(
        "external_archive_inspection_incomplete",
        "External archive could not be parsed completely in offline inspection.",
        binding.actual.clone(),
    )
}

/// Run `body` over the (decompressed when gzip) byte stream of `file`, then
/// prove the bytes `body` consumed were the bound bytes. Unsupported
/// compression is refused before `body` sees anything.
pub(crate) fn with_verified_stream<T>(
    file: &mut File,
    binding: &Binding<'_>,
    caps: &ArchiveCaps,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
    body: impl FnOnce(&mut dyn Read) -> Result<T, ArchiveOutcome>,
) -> Result<T, ArchiveOutcome> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| incomplete(binding))?;
    let mut tee = TeeHash {
        inner: file,
        digest: StreamDigest::new(),
    };
    // The sniffed bytes are replayed in front of the stream, so the bytes that
    // pick the decoder are the same bytes the decoder reads.
    let mut magic = [0u8; 6];
    let mut magic_len = 0;
    while magic_len < magic.len() {
        let count = tee
            .read(&mut magic[magic_len..])
            .map_err(|_| incomplete(binding))?;
        if count == 0 {
            break;
        }
        magic_len += count;
    }
    let magic = &magic[..magic_len];
    if magic.starts_with(b"BZh") || magic.starts_with(b"\xfd7zXZ\x00") {
        return Err(ArchiveOutcome::blocked(
            "external_archive_unsupported_format",
            "External archive uses an unsupported compression format.",
            binding.actual.clone(),
        ));
    }
    let gzipped = magic.starts_with(b"\x1f\x8b");
    let value = {
        let replay = Cursor::new(magic.to_vec()).chain(&mut tee);
        if gzipped {
            body(&mut MultiGzDecoder::new(replay))?
        } else {
            let mut replay = replay;
            body(&mut replay)?
        }
    };
    match tee
        .digest
        .absorb_to_eof(&mut *tee.inner, caps.max_archive_bytes, deadline, halt)
    {
        Ok(()) => {}
        Err(HashFailure::Timeout) => return Err(ArchiveOutcome::timeout(binding.actual.clone())),
        Err(HashFailure::Halted) => return Err(ArchiveOutcome::halted()),
        Err(_) => return Err(incomplete(binding)),
    }
    let (sha256, size) = tee.digest.finish();
    if size != binding.size || sha256 != binding.sha256 {
        return Err(ArchiveOutcome::blocked(
            "external_archive_digest_mismatch",
            "External archive changed during offline inspection.",
            Some(sha256),
        ));
    }
    Ok(value)
}

/// `_preflight_expanded_tar_stream`: bound the decompressed stream before tar
/// parsing touches it. Gzip members are decoded back to back, matching the
/// parse pass, and everything after a tar terminator is counted too.
pub(crate) fn preflight_expanded_stream(
    file: &mut File,
    binding: &Binding<'_>,
    caps: &ArchiveCaps,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
) -> Result<(), ArchiveOutcome> {
    let actual = binding.actual;
    with_verified_stream(file, binding, caps, deadline, halt, |reader| {
        let mut expanded: u64 = 0;
        let mut buffer = vec![0u8; HASH_CHUNK];
        loop {
            if halt() {
                return Err(ArchiveOutcome::halted());
            }
            if Instant::now() > deadline {
                return Err(ArchiveOutcome::timeout(actual.clone()));
            }
            let count = reader.read(&mut buffer).map_err(|_| incomplete(binding))?;
            if count == 0 {
                return Ok(());
            }
            expanded += count as u64;
            if expanded > caps.max_expanded_bytes {
                return Err(ArchiveOutcome::blocked(
                    "external_archive_expanded_size_limit",
                    "External archive exceeded Guard's expanded-stream limit.",
                    actual.clone(),
                ));
            }
            if (expanded as f64) > (binding.size.max(1) as f64) * caps.max_decompression_ratio {
                return Err(ArchiveOutcome::blocked(
                    "external_archive_decompression_ratio_limit",
                    "External archive exceeded Guard's decompression-ratio limit.",
                    actual.clone(),
                ));
            }
        }
    })
}
