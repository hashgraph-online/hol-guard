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
//! The directory is read first. A zip ends with a central directory naming
//! every member, its sizes, its codec and where its data begins, and that
//! record is the archive's own account of itself. Walking it means the sizes
//! are known before a byte is inflated, so a member too large for the
//! remaining budget is skipped without being decompressed first — which is
//! the difference between bounding a zip bomb and surviving one.
//!
//! The directory is not believed to be complete. It is an index, written
//! separately from the data it indexes, and anyone who wants a member unread
//! can leave its record out, name a shorter run of records from a forged end
//! record planted in the trailing comment, or corrupt the directory
//! altogether. None of that removes the member: its data is still in the file,
//! behind its own local header, and a reader that wants it still gets it. So
//! the local headers are walked afterwards and every member the directory did
//! not account for is read from its own header. What the directory names is
//! read on the directory's terms; what it omits is read anyway.
//!
//! What a member carries is that member's own business. A zip stored verbatim
//! inside this one holds local signatures of its own, and reading them here
//! would report the inner archive's members under this archive's path, where
//! no one removing the secret could find them. A header inside the data of a
//! member the directory named is left alone, so one level of nesting is read
//! and an archive within an archive is read as the file it is - the same bound
//! the tar walk beside this one keeps.
//!
//! A local header's sizes are the ones a bomb lies about, which is why the
//! directory's are preferred where there are two. Where the local header is
//! all there is, the lie cannot grow the read: a member is inflated under a
//! bound of its claim plus one byte and refused unless it lands exactly on the
//! claim, so a stream that produces more than its header promised yields
//! nothing rather than more. A member whose header leaves its sizes for a
//! descriptor after the data is skipped for the same reason — there is no
//! claim to bound it with until the data has already been read.
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

/// Bit 3 of those flags: the member's sizes are not in its local header but in
/// a descriptor written after its data.
const FLAG_STREAMED: u16 = 1 << 3;

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
    // A directory can name far more member bytes than the archive itself
    // holds: each record costs a few dozen bytes, and several records may name
    // one deflated run. Without a bound of its own, a few kilobytes of zip
    // could charge the whole scan's remaining allowance and leave every file
    // committed after it unread. The allowance a zip may spend is bounded the
    // same way the gzip walk bounds its own inflation.
    let total = data
        .len()
        .saturating_mul(super::MAX_EXPANSION_RATIO)
        .max(super::RATIO_FLOOR_BYTES)
        .min(caps.total);
    let mut walk = Walk {
        data,
        path,
        source,
        commit,
        finding_budget,
        member_cap: caps.member,
        total,
        findings: Vec::new(),
        scanned: 0,
        read: HashSet::new(),
        taken: HashSet::new(),
        spans: Vec::new(),
        seen: 0,
    };
    // An archive whose end record is missing or unreadable still has its
    // members, so the absence of a directory is a reason to read less, not a
    // reason to read nothing.
    if let Some(directory) = central_directory(data) {
        walk.directory_records(directory);
    }
    walk.local_headers();
    (walk.findings, walk.scanned)
}

/// One pass over an archive, and what the passes share: the budget, the
/// findings and what has already been read.
struct Walk<'a> {
    data: &'a [u8],
    path: &'a str,
    source: &'a str,
    commit: Option<&'a str>,
    finding_budget: usize,
    member_cap: u64,
    total: usize,
    findings: Vec<SecretFinding>,
    scanned: usize,
    /// A zip may name the same member twice as readily as a tar may, and the
    /// central directory is where it is cheapest to do so: a few dozen bytes
    /// per repetition, all pointing at one member's data. The findings are
    /// collapsed on the same key the tar walk uses.
    read: HashSet<(String, usize, CandidateDigest)>,
    /// The local headers whose data the directory pass already read, so the
    /// second pass spends the budget only on what the first one missed.
    taken: HashSet<usize>,
    /// Where each member the directory accounted for keeps its data. A member
    /// stored verbatim may carry a local signature inside those bytes - a zip
    /// inside a zip is the ordinary case - and a signature found there belongs
    /// to the inner archive, not to this one.
    spans: Vec<(usize, usize)>,
    seen: usize,
}

impl Walk<'_> {
    /// Whether there is budget left to read another member.
    fn more(&self) -> bool {
        self.seen < MAX_MEMBERS
            && self.findings.len() < self.finding_budget
            && self.scanned < self.total
    }

    /// The largest member this walk will still read.
    fn room(&self) -> u64 {
        self.member_cap.min((self.total - self.scanned) as u64)
    }

    /// Every member the archive's own account of itself names.
    fn directory_records(&mut self, directory: &[u8]) {
        let mut cursor = 0usize;
        while self.more() {
            let Some(record) = CentralRecord::parse(directory, cursor) else {
                break;
            };
            cursor = record.next;
            self.seen += 1;
            let Some(member) = record.member(self.data) else {
                continue;
            };
            self.take(&member);
        }
    }

    /// Where a member the directory accounted for keeps its data, so a
    /// signature found inside those bytes is read as the inner archive's and
    /// not as this archive's.
    fn note_span(&mut self, member: &Member<'_>) {
        let Some(end) = member.data_at.checked_add(member.compressed as usize) else {
            return;
        };
        if end > member.data_at {
            self.spans.push((member.data_at, end));
        }
    }

    /// Whether this header sits inside the data of a member the directory
    /// already named.
    fn inside_a_member(&self, header: usize) -> bool {
        self.spans
            .iter()
            .any(|&(from, to)| header >= from && header < to)
    }

    /// Every member whose data the directory did not account for, found
    /// through the local header that owns it.
    ///
    /// The search is for the signature rather than a walk by arithmetic,
    /// because the lengths that would carry a walk from one member to the next
    /// are exactly what an archive hiding a member gets wrong. The cost of
    /// searching is that a member stored verbatim holds whatever bytes it
    /// holds, and a zip stored inside this one carries local signatures of its
    /// own. Those belong to the inner archive: reading them here would report
    /// the inner members under this archive's path, where no one removing the
    /// secret could find them, and would charge their bytes twice. So a header
    /// inside the data of a member the directory named is left alone, and an
    /// archive within an archive is read as the file it is, the same way the
    /// tar walk beside this one reads one.
    fn local_headers(&mut self) {
        let mut at = 0usize;
        while self.more() {
            let Some(header) = find_local_header(self.data, at) else {
                break;
            };
            at = header + LOCAL_SIGNATURE.len();
            if self.taken.contains(&header) || self.inside_a_member(header) {
                continue;
            }
            let Some(member) = local_member(self.data, header) else {
                continue;
            };
            self.seen += 1;
            self.note_span(&member);
            self.take(&member);
        }
    }

    /// Read one member and keep what it holds, on the budget's terms.
    fn take(&mut self, member: &Member<'_>) {
        let Some(name) = member.name() else {
            return;
        };
        if !member.is_readable() || member.uncompressed > self.room() {
            return;
        }
        let Some(bytes) = member.read(self.data) else {
            return;
        };
        self.taken.insert(member.header_at);
        self.note_span(member);
        self.scanned = self.scanned.saturating_add(bytes.len());
        let member_path = member_path(self.path, &name);
        let Some(text) = decode_text(&member_path, &bytes) else {
            return;
        };
        let remaining = self.finding_budget.saturating_sub(self.findings.len());
        let summary = scan_secret_text(text, &member_path, self.source, self.commit, remaining);
        for finding in summary.findings {
            let key = (
                finding.path.clone(),
                finding.line,
                candidate_digest(&finding.candidate),
            );
            if self.read.insert(key) {
                self.findings.push(finding);
            }
        }
    }
}

/// Where the next local header begins at or after `from`.
fn find_local_header(data: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(LOCAL_SIGNATURE.len())
        .position(|window| window == LOCAL_SIGNATURE)
        .map(|offset| from + offset)
}

/// The central directory's bytes, located through the end-of-central-directory
/// record at the tail of the archive.
///
/// The record is found by searching backwards and the last candidate wins,
/// which is what the format requires and what every extractor does: the
/// record's own position depends on the length of a comment that follows it,
/// so the only way to find it is from the end. A candidate is accepted only
/// when its stated comment length reaches exactly the end of the file, so a
/// `PK\x05\x06` that happens to occur inside a member's compressed data is not
/// mistaken for the record, and only when the directory it names is one, so
/// the cheapest forgery planted in the archive's own comment does not stand in
/// for the archive's account of itself.
///
/// These are not the last line against a hidden member, and they are not meant
/// to be. A directory that passes every check here can still leave a member
/// out, and this returns nothing at all for an archive whose tail is damaged.
/// Both cases are answered by the local-header pass rather than by a stricter
/// rule here, because a rule strict enough to catch them would also refuse
/// archives that real extractors read.
fn central_directory(data: &[u8]) -> Option<&[u8]> {
    // An archive that holds anything begins with its first member's local
    // header. One that does not is the end record alone, and the empty
    // directory it names is the whole truth about it.
    let holds_members = data.starts_with(LOCAL_SIGNATURE);
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
                // record that named it, and it has to begin with a record of
                // its own unless the archive holds no members at all. The one
                // position a forged end record is reached from before the real
                // one is the archive's own trailing comment, and the cheapest
                // forgery there names an empty directory at offset zero, which
                // satisfies every bound while hiding every member behind it.
                if end <= candidate {
                    if let Some(directory) = data.get(offset..end) {
                        if directory.starts_with(CENTRAL_SIGNATURE)
                            || (!holds_members && directory.is_empty())
                        {
                            return Some(directory);
                        }
                    }
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

    /// The member this record names, located through the local header at the
    /// offset it gives.
    ///
    /// The sizes stay the directory's. Only the local header's two
    /// variable-length fields are read, for where the data starts; its own
    /// sizes are the ones a hostile archive disagrees with the directory
    /// about, and a streamed member leaves them zero in any case.
    fn member(&self, data: &'a [u8]) -> Option<Member<'a>> {
        let header_at = self.local_offset as usize;
        Some(Member {
            flags: self.flags,
            method: self.method,
            compressed: self.compressed,
            uncompressed: self.uncompressed,
            name: self.name,
            data_at: data_offset(data, header_at)?,
            header_at,
        })
    }
}

/// A member's data and what the archive said about it, wherever the record
/// that said so was read from.
struct Member<'a> {
    flags: u16,
    method: u16,
    compressed: u32,
    uncompressed: u64,
    name: &'a [u8],
    /// Where the member's data begins in the archive.
    data_at: usize,
    /// Where the local header that owns that data begins.
    header_at: usize,
}

/// The member a local header owns, read from that header alone.
///
/// A member whose header defers its sizes to a descriptor written after the
/// data is not one: there is no claim to bound the read with until the data has
/// already been read, which is the opposite of the order this walk needs. The
/// directory knows that member's real sizes, so it is read on the first pass or
/// not at all.
fn local_member(data: &[u8], at: usize) -> Option<Member<'_>> {
    if !data.get(at..)?.starts_with(LOCAL_SIGNATURE) {
        return None;
    }
    if u16_at(data, at + 6)? & FLAG_STREAMED != 0 {
        return None;
    }
    let name_len = u16_at(data, at + 26)? as usize;
    let name_at = at.checked_add(LOCAL_FIXED)?;
    Some(Member {
        flags: u16_at(data, at + 6)?,
        method: u16_at(data, at + 8)?,
        compressed: u32_at(data, at + 18)?,
        uncompressed: u32_at(data, at + 22)? as u64,
        name: data.get(name_at..name_at.checked_add(name_len)?)?,
        data_at: data_offset(data, at)?,
        header_at: at,
    })
}

/// Where the data owned by the local header at `at` begins.
fn data_offset(data: &[u8], at: usize) -> Option<usize> {
    if !data.get(at..)?.starts_with(LOCAL_SIGNATURE) {
        return None;
    }
    let name_len = u16_at(data, at + 26)? as usize;
    let extra_len = u16_at(data, at + 28)? as usize;
    at.checked_add(LOCAL_FIXED)?
        .checked_add(name_len)?
        .checked_add(extra_len)
}

impl Member<'_> {
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
    fn is_readable(&self) -> bool {
        self.flags & FLAG_ENCRYPTED == 0
            && matches!(self.method, METHOD_STORED | METHOD_DEFLATE)
            && self.uncompressed != ZIP64_SENTINEL as u64
            && self.compressed != ZIP64_SENTINEL
            && self.uncompressed != 0
    }

    /// The member's bytes, read from the archive.
    fn read(&self, data: &[u8]) -> Option<Vec<u8>> {
        let end = self.data_at.checked_add(self.compressed as usize)?;
        let compressed = data.get(self.data_at..end)?;
        match self.method {
            METHOD_STORED => {
                // A stored member is its own data, so the two sizes claimed
                // for it have to agree; one that does not is malformed rather
                // than merely compressed oddly.
                (compressed.len() as u64 == self.uncompressed).then(|| compressed.to_vec())
            }
            _ => self.inflate(compressed),
        }
    }

    /// The member's deflated bytes, inflated under the size claimed for it.
    ///
    /// The bound is one byte past that claim, so a stream that produces more
    /// than it was said to is refused rather than truncated: the two
    /// disagreeing is how a bomb gets past a check made on a size field alone,
    /// and a member whose real size is unknown is not read.
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
