//! Reading the files a `zip` archive carries.
//!
//! `zip` was the one archive shape the member walk left unread, because the
//! reason given for leaving it was that no zip reader was in the dependency
//! graph. That reason has expired: the member walk itself brought `flate2` in,
//! and a zip member is either stored verbatim or deflated, which is the one
//! codec `flate2` exists to provide. What is left is the container, and the
//! container is a directory of fixed-width records. Reading it here costs no
//! new dependency and no `Cargo.lock` movement.
//!
//! The directory is read rather than the stream. A zip ends with a central
//! directory naming every member, its sizes, its codec and where its data
//! begins, and that record is the archive's own account of itself. Walking it
//! means the sizes are known before a byte is inflated, so a member too large
//! for the remaining budget is skipped without being decompressed first —
//! which is the difference between bounding a zip bomb and surviving one. The
//! local header at the named offset is read only for the two lengths that say
//! where its data starts; its size fields are the ones a bomb lies in, and
//! they are not used.
//!
//! A member's checksum is read as the archive's own bookkeeping and is not
//! made a condition of reading it. The checksum says whether the archive is
//! intact, not whether what it carries is a credential, and gating on it
//! would hand anyone who wanted a secret past this scan a single flipped bit
//! to do it with.
//!
//! What is deliberately not read: an encrypted member, whose bytes are not
//! recoverable without the passphrase; a member in any codec but stored or
//! deflate, since the readers for those are exactly what is absent; and a
//! zip64 member, whose real sizes live in an extra field this reader does not
//! parse, so the sentinel values it would otherwise read as sizes are refused
//! instead of acted on. Each of those is skipped alone — the rest of the
//! archive is still walked, because one unreadable member is not a reason to
//! stop reading the members beside it.

use std::collections::HashSet;
use std::io::Read;

use super::{member_path, Caps, MAX_MEMBERS};
use crate::repository_scanner::decode_text;
use crate::secret_detection::{candidate_digest, scan_secret_text, CandidateDigest, SecretFinding};

/// `PK\x03\x04`, which begins the first member's local header and so begins
/// every zip that holds anything.
const LOCAL_SIGNATURE: &[u8] = &[0x50, 0x4b, 0x03, 0x04];
/// `PK\x05\x06`, the end-of-central-directory record. An empty zip is this
/// record alone, so it is also a way an archive can begin.
const EOCD_SIGNATURE: &[u8] = &[0x50, 0x4b, 0x05, 0x06];
/// `PK\x01\x02`, which begins each central directory record.
const CENTRAL_SIGNATURE: &[u8] = &[0x50, 0x4b, 0x01, 0x02];

/// Bytes in an end-of-central-directory record before its comment.
const EOCD_FIXED: usize = 22;
/// Bytes in a central directory record before its variable-length fields.
const CENTRAL_FIXED: usize = 46;
/// Bytes in a local file header before its variable-length fields.
const LOCAL_FIXED: usize = 30;

/// A zip's trailing comment is a `u16` length, so the record that carries it
/// begins no further back than this from the end of the file.
const MAX_COMMENT: usize = u16::MAX as usize;

/// The two codecs a member may use and still be read.
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

/// Bit 0 of a member's general-purpose flags: its data is encrypted.
const FLAG_ENCRYPTED: u16 = 1;

/// What a 32-bit size or offset field holds when the real value lives in a
/// zip64 extra field instead.
const ZIP64_SENTINEL: u32 = u32::MAX;

/// Whether these bytes begin a zip archive.
pub(super) fn is_zip(data: &[u8]) -> bool {
    data.starts_with(LOCAL_SIGNATURE) || data.starts_with(EOCD_SIGNATURE)
}

/// Findings from the members of a zip archive, with the number of member bytes
/// read, on the same terms as the tar walk beside it.
pub(super) fn scan_members(
    data: &[u8],
    path: &str,
    source: &str,
    commit: Option<&str>,
    finding_budget: usize,
    caps: Caps,
) -> (Vec<SecretFinding>, usize) {
    let mut findings: Vec<SecretFinding> = Vec::new();
    let mut scanned = 0usize;
    let Some(directory) = central_directory(data) else {
        return (findings, scanned);
    };
    // A zip may name the same member twice as readily as a tar may, and the
    // central directory is where it is cheapest to do so: a few dozen bytes
    // per repetition, all pointing at one member's data. The findings are
    // collapsed on the same key the tar walk uses.
    let mut read: HashSet<(String, usize, CandidateDigest)> = HashSet::new();
    let mut cursor = 0usize;
    let mut seen = 0usize;
    while seen < MAX_MEMBERS && findings.len() < finding_budget && scanned < caps.total {
        let Some(record) = CentralRecord::parse(directory, cursor) else {
            break;
        };
        cursor = record.next;
        seen += 1;
        let Some(name) = record.name() else {
            continue;
        };
        let room = (caps.total - scanned) as u64;
        if !record.is_readable_member() || record.uncompressed > caps.member.min(room) {
            continue;
        }
        let Some(member) = record.read(data) else {
            continue;
        };
        scanned = scanned.saturating_add(member.len());
        let member_path = member_path(path, &name);
        let Some(text) = decode_text(&member_path, &member) else {
            continue;
        };
        let remaining = finding_budget.saturating_sub(findings.len());
        let summary = scan_secret_text(text, &member_path, source, commit, remaining);
        for finding in summary.findings {
            let key = (
                finding.path.clone(),
                finding.line,
                candidate_digest(&finding.candidate),
            );
            if read.insert(key) {
                findings.push(finding);
            }
        }
    }
    (findings, scanned)
}

/// The central directory's bytes, located through the end-of-central-directory
/// record at the tail of the archive.
///
/// The record is found by searching backwards, which is what the format
/// requires: its own position depends on the length of a comment that follows
/// it. A candidate is accepted only when its stated comment length reaches
/// exactly the end of the file, so a `PK\x05\x06` that happens to occur inside
/// a member's compressed data is not mistaken for the record.
fn central_directory(data: &[u8]) -> Option<&[u8]> {
    let window = data.len().min(EOCD_FIXED + MAX_COMMENT);
    let start = data.len() - window;
    let mut candidate = data.len().checked_sub(EOCD_FIXED)?;
    loop {
        if data[candidate..].starts_with(EOCD_SIGNATURE) {
            let comment = u16_at(data, candidate + 20)? as usize;
            if candidate + EOCD_FIXED + comment == data.len() {
                let offset = u32_at(data, candidate + 16)? as usize;
                let size = u32_at(data, candidate + 12)? as usize;
                let end = offset.checked_add(size)?;
                // The directory has to lie inside the file and ahead of the
                // record that named it; a zip whose own account of itself does
                // not is not read at all rather than read partially.
                if end <= candidate {
                    return data.get(offset..end);
                }
            }
        }
        if candidate == start {
            return None;
        }
        candidate -= 1;
    }
}

/// One member's entry in the central directory.
struct CentralRecord<'a> {
    flags: u16,
    method: u16,
    compressed: u32,
    uncompressed: u64,
    local_offset: u32,
    name: &'a [u8],
    /// Where the next record begins in the directory.
    next: usize,
}

impl<'a> CentralRecord<'a> {
    fn parse(directory: &'a [u8], at: usize) -> Option<Self> {
        if !directory.get(at..)?.starts_with(CENTRAL_SIGNATURE) {
            return None;
        }
        let name_len = u16_at(directory, at + 28)? as usize;
        let extra_len = u16_at(directory, at + 30)? as usize;
        let comment_len = u16_at(directory, at + 32)? as usize;
        let name_at = at.checked_add(CENTRAL_FIXED)?;
        let name = directory.get(name_at..name_at.checked_add(name_len)?)?;
        let next = name_at
            .checked_add(name_len)?
            .checked_add(extra_len)?
            .checked_add(comment_len)?;
        Some(Self {
            flags: u16_at(directory, at + 8)?,
            method: u16_at(directory, at + 10)?,
            compressed: u32_at(directory, at + 20)?,
            uncompressed: u32_at(directory, at + 24)? as u64,
            local_offset: u32_at(directory, at + 42)?,
            name,
            next,
        })
    }

    /// The member's reported name, or nothing when it names a directory rather
    /// than a file.
    ///
    /// The name is taken as the archive spells it, as a tar member's is.
    /// Invalid bytes are replaced rather than refused: a zip written on a
    /// system that stored names in its own code page still carries whatever is
    /// inside the member.
    fn name(&self) -> Option<String> {
        let name = String::from_utf8_lossy(self.name);
        if name.is_empty() || name.ends_with('/') {
            return None;
        }
        Some(name.into_owned())
    }

    /// Whether this member's bytes can be recovered at all.
    fn is_readable_member(&self) -> bool {
        self.flags & FLAG_ENCRYPTED == 0
            && matches!(self.method, METHOD_STORED | METHOD_DEFLATE)
            && self.uncompressed != ZIP64_SENTINEL as u64
            && self.compressed != ZIP64_SENTINEL
            && self.local_offset != ZIP64_SENTINEL
            && self.uncompressed != 0
    }

    /// The member's bytes, read from the archive.
    fn read(&self, data: &[u8]) -> Option<Vec<u8>> {
        let start = self.data_offset(data)?;
        let end = start.checked_add(self.compressed as usize)?;
        let compressed = data.get(start..end)?;
        match self.method {
            METHOD_STORED => {
                // A stored member is its own data, so the directory's two
                // sizes have to agree; one that does not is malformed rather
                // than merely compressed oddly.
                (compressed.len() as u64 == self.uncompressed).then(|| compressed.to_vec())
            }
            _ => self.inflate(compressed),
        }
    }

    /// Where this member's data begins, through its local header.
    ///
    /// Only the header's two variable-length fields are read. Its sizes are
    /// the ones a hostile archive disagrees with the directory about, and a
    /// streamed member leaves them zero in any case.
    fn data_offset(&self, data: &[u8]) -> Option<usize> {
        let header = self.local_offset as usize;
        if !data.get(header..)?.starts_with(LOCAL_SIGNATURE) {
            return None;
        }
        let name_len = u16_at(data, header + 26)? as usize;
        let extra_len = u16_at(data, header + 28)? as usize;
        header
            .checked_add(LOCAL_FIXED)?
            .checked_add(name_len)?
            .checked_add(extra_len)
    }

    /// The member's deflated bytes, inflated under the size the directory
    /// claimed for it.
    ///
    /// The bound is one byte past that claim, so a stream that produces more
    /// than the directory said it would is refused rather than truncated: the
    /// two disagreeing is how a bomb gets past a check made on the directory
    /// alone, and a member whose real size is unknown is not read.
    fn inflate(&self, compressed: &[u8]) -> Option<Vec<u8>> {
        let mut inflated: Vec<u8> = Vec::new();
        flate2::read::DeflateDecoder::new(compressed)
            .take(self.uncompressed.checked_add(1)?)
            .read_to_end(&mut inflated)
            .ok()?;
        (inflated.len() as u64 == self.uncompressed).then_some(inflated)
    }
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    let bytes = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
#[path = "repository_scanner_zip_tests.rs"]
mod tests;
