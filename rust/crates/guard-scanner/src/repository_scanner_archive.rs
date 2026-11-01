//! Reading the files an archive carries, so a credential committed inside one
//! is read rather than skipped.
//!
//! A repository scan drops a file whose bytes are not text: `BINARY_SUFFIXES`
//! names `gz`, `tar`, `zip` and the rest, and `decode_text` returns `None` for
//! anything else holding a NUL. That is right for an image and wrong for an
//! archive, which is a container of files rather than a file of its own. A
//! `.env` committed inside `backup.tar.gz` was invisible to every scan: the
//! working tree walk, the bounded history walk and the staged scan all reach
//! the same `scan_blob`, so all three missed it.
//!
//! This module reads the members of the archive formats a repository actually
//! carries: gzip, tar, the two of them together, and zip. A
//! member is reported under the name `backup.tar.gz!/etc/config.env`, which
//! says both which archive held it and where inside. The separator opens a
//! fresh path segment instead of running the two names together, so a member
//! keeps its own basename and a rule that reads one, such as the stricter bar
//! a `.env` earns, still recognises it.
//!
//! Every bound here exists because an archive is attacker-shaped input: a few
//! hundred bytes of gzip expand to gigabytes, a tar names a thousand empty
//! members, a member claims a size the stream never delivers. The caps are
//! deliberately smaller than the scan's own file cap, and the caller's own
//! remaining allowance narrows them further, since what this module reports
//! back is inflated bytes rather than the compressed length the caller weighed
//! before handing the blob over.
//!
//! The container reading is split by shape: a tar is a stream of headers, read
//! here; a zip is a directory of records, read in `repository_scanner_zip`.
//! Both end in the same place, a member's bytes handed to the same text decode
//! and the same detector the rest of the scan uses.

use std::collections::HashSet;
use std::io::{Cursor, Read};

use super::{decode_text, scan_secret_text, SecretFinding};
use crate::secret_detection::{candidate_digest, CandidateDigest};

// The zip container is a directory of fixed-width records rather than a
// stream, so reading it shares none of the tar walk's code. It lives in its
// own file to keep this one readable, and as a child module so it can use the
// bounds and the member-path spelling here without widening either.
#[path = "repository_scanner_zip.rs"]
mod zip;

/// Most members read from one archive. A credential-bearing archive in a
/// repository is a backup or a bundle, not a thousand-file corpus.
const MAX_MEMBERS: usize = 512;

/// Most bytes read from one member. A credential lives on a line; a member
/// larger than this is data, and reading it would only buy a scan of a file
/// the repository does not actually track.
const MAX_MEMBER_BYTES: u64 = 4 * 1024 * 1024;

/// Most bytes read from one archive across every member.
const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;

/// Expansion a gzip stream may claim before the ratio is treated as an attack
/// rather than as compression. Text compresses well, so the cap is generous.
const MAX_EXPANSION_RATIO: usize = 512;

/// Expansion below this size is never judged by ratio: a few compressed bytes
/// becoming a few thousand is ordinary, not a bomb.
const RATIO_FLOOR_BYTES: usize = 64 * 1024;

/// What separates an archive's own path from the member inside it. The
/// trailing slash is part of it: it starts the member on a path segment of its
/// own so its basename survives the join.
pub(super) const MEMBER_SEPARATOR: &str = "!/";

/// What one blob's scan may read, as the caller's own remaining allowance
/// rather than this module's constants alone.
///
/// A plain file arrives already bounded: the caller refuses to read more than
/// its per-file cap, and weighs the blob's length against the scan's total
/// before handing it over. An archive does not, because its members are only
/// sized once it is opened and what it reports back is inflated bytes rather
/// than the compressed length that was weighed. Carrying both caps inward is
/// what stops one archive from spending megabytes the scan had already
/// promised to the files after it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ByteBudget {
    /// Most bytes one member may contribute: the caller's per-file cap.
    pub(crate) max_member_bytes: usize,
    /// Bytes left in the whole scan's allowance.
    pub(crate) remaining_total_bytes: usize,
}

impl ByteBudget {
    /// A caller that bounds nothing of its own, for a one-off scan of a blob
    /// already in hand. This module's own caps still apply.
    #[cfg(test)]
    pub(crate) fn unbounded() -> Self {
        Self {
            max_member_bytes: usize::MAX,
            remaining_total_bytes: usize::MAX,
        }
    }
}

/// The two byte caps this module works to, once the caller's budget and its
/// own constants have been reconciled.
#[derive(Clone, Copy)]
struct Caps {
    /// Most bytes one member may contribute.
    member: u64,
    /// Most bytes the whole archive may contribute.
    total: usize,
}

/// Findings from the members of `data`, or `None` when `data` is not an
/// archive this module reads.
///
/// `path` is the archive's own reported path; member paths are built from it.
/// The returned count is the number of member bytes actually read, which the
/// caller adds to the scan's byte total — the archive's own compressed length
/// would understate what the scan did.
pub(super) fn scan_archive_members(
    data: &[u8],
    path: &str,
    source: &str,
    commit: Option<&str>,
    finding_budget: usize,
    byte_budget: ByteBudget,
) -> Option<(Vec<SecretFinding>, usize)> {
    let caps = Caps {
        member: MAX_MEMBER_BYTES.min(byte_budget.max_member_bytes as u64),
        total: MAX_TOTAL_BYTES.min(byte_budget.remaining_total_bytes),
    };
    let payload = if is_gzip(data) {
        Payload::Owned(inflate_gzip(data, caps.total)?)
    } else if is_tar(data) || zip_start(data).is_some() {
        Payload::Borrowed(data)
    } else {
        return None;
    };
    let bytes = payload.as_slice();
    if is_tar(bytes) {
        return Some(scan_tar(bytes, path, source, commit, finding_budget, caps));
    }
    // Recognised after inflation as well as before it, so a `.zip.gz` — which
    // a mail gateway or a backup script produces without meaning to — is read
    // rather than handed to the single-member path as one opaque blob.
    if let Some(start) = zip_start(bytes) {
        return Some(zip::scan_members(
            &bytes[start..],
            path,
            source,
            commit,
            finding_budget,
            caps,
        ));
    }
    // A plain `.gz`: one file compressed on its own, named for the archive
    // without the suffix that says it was compressed. It is still reported
    // under the archive that held it, because a repository that commits
    // `prod.env.gz` commonly has a `prod.env` beside it, and reporting the
    // compressed copy under the plain name let one of the two findings be
    // dropped as a duplicate of the other.
    if bytes.len() as u64 > caps.member || bytes.len() > caps.total {
        return Some((Vec::new(), 0));
    }
    Some(scan_single_member(
        bytes,
        &member_path(path, &gunzipped_leaf(path)),
        source,
        commit,
        finding_budget,
    ))
}

/// Where the zip in `bytes` begins, which is byte zero for an archive sent as
/// itself and further in for one with a stub in front of it.
///
/// A self-extracting archive is an executable carrying a zip, and it reached
/// this module as a binary blob with nothing in it to read. It is read as the
/// archive it is now, from where the archive starts; the stub itself is not a
/// member and is not reported as one.
fn zip_start(bytes: &[u8]) -> Option<usize> {
    if zip::is_zip(bytes) {
        return Some(0);
    }
    zip::embedded_start(bytes)
}

/// Inflated bytes either own their buffer or point at the caller's.
enum Payload<'a> {
    Owned(Vec<u8>),
    Borrowed(&'a [u8]),
}

impl Payload<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Borrowed(bytes) => bytes,
        }
    }
}

fn is_gzip(data: &[u8]) -> bool {
    data.starts_with(&[0x1f, 0x8b])
}

/// A tar header carries its format marker at a fixed offset, which is the only
/// reliable way to recognise one: tar has no leading magic. The pre-POSIX
/// format wrote zeros there instead, and is not recognised; every tar written
/// in this century carries the marker.
fn is_tar(data: &[u8]) -> bool {
    const MAGIC_OFFSET: usize = 257;
    const MAGIC: &[u8] = b"ustar";
    data.len() >= MAGIC_OFFSET + MAGIC.len()
        && &data[MAGIC_OFFSET..MAGIC_OFFSET + MAGIC.len()] == MAGIC
}

/// Inflate a gzip stream under one bound that already carries both the ratio
/// cap and the absolute cap.
///
/// The ratio is spent on the decoder rather than tested afterwards: a bomb is
/// refused once it has produced the few hundred kilobytes its own size allows,
/// instead of after the absolute cap's worth of memory has been filled on its
/// behalf. A thousand-byte stream is held to half a megabyte, not to thirty-two.
fn inflate_gzip(data: &[u8], total_cap: usize) -> Option<Vec<u8>> {
    let allowance = data
        .len()
        .saturating_mul(MAX_EXPANSION_RATIO)
        .max(RATIO_FLOOR_BYTES)
        .min(total_cap);
    // Several gzip streams may be written end to end into one file — `gzip`
    // does it when it is handed more than one input — and a single-member
    // decoder stops at the first, leaving the rest of the file unread.
    let mut decoder = flate2::read::MultiGzDecoder::new(data);
    let mut inflated: Vec<u8> = Vec::new();
    // One byte past the allowance, so a stream that exactly fills it is told
    // apart from one that would have run over.
    let read = (&mut decoder)
        .take(allowance as u64 + 1)
        .read_to_end(&mut inflated);
    if inflated.len() > allowance {
        return None;
    }
    // Reading end to end is also how the tail of a file stops being gzip: the
    // zero padding a backup tool writes after the last member reads as a
    // header that will not parse. What was already inflated is whole archive
    // up to that point, and a credential inside it is still a credential, so
    // the error only ends the read rather than discarding it.
    if read.is_err() && inflated.is_empty() {
        return None;
    }
    Some(inflated)
}

/// `backup.tar.gz` names a tar once gunzipped; `notes.txt.gz` names a text
/// file. Either way the compression suffix is what stops naming the content,
/// and what is left is the member's own name inside the archive.
fn gunzipped_leaf(path: &str) -> String {
    let leaf = path
        .rsplit('/')
        .next()
        .unwrap_or(path)
        .rsplit('\\')
        .next()
        .unwrap_or(path);
    for suffix in [".gz", ".GZ"] {
        // An empty stem means the whole name was the suffix, which names
        // nothing; the archive's own leaf is the better answer then.
        if let Some(stem) = leaf.strip_suffix(suffix).filter(|stem| !stem.is_empty()) {
            return stem.to_owned();
        }
    }
    if let Some(stem) = leaf
        .strip_suffix(".tgz")
        .or_else(|| leaf.strip_suffix(".TGZ"))
        .filter(|stem| !stem.is_empty())
    {
        return format!("{stem}.tar");
    }
    leaf.to_owned()
}

/// An archive's own path joined to the name of a member inside it.
fn member_path(archive: &str, member: &str) -> String {
    format!("{archive}{MEMBER_SEPARATOR}{member}")
}

fn scan_tar(
    bytes: &[u8],
    path: &str,
    source: &str,
    commit: Option<&str>,
    finding_budget: usize,
    caps: Caps,
) -> (Vec<SecretFinding>, usize) {
    let mut findings: Vec<SecretFinding> = Vec::new();
    let mut scanned = 0usize;
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let Ok(mut entries) = archive.entries() else {
        return (findings, scanned);
    };
    // A tar may name the same member twice, and nothing stops it naming the
    // same member five hundred times. Every copy produces the finding the
    // first one did, which the caller later collapses — after the budget that
    // would have carried a different credential elsewhere in the archive has
    // already been spent on them.
    let mut read: HashSet<(String, usize, CandidateDigest)> = HashSet::new();
    let mut seen = 0usize;
    loop {
        if seen >= MAX_MEMBERS || findings.len() >= finding_budget || scanned >= caps.total {
            break;
        }
        // Asking for the next entry is what makes the reader parse its header,
        // and the long-name and extended-attribute records that may precede
        // it. Checking the caps first is therefore what keeps an exhausted
        // walk from doing that parsing at all.
        let Some(entry) = entries.next() else { break };
        seen += 1;
        // A truncated or malformed archive stops the walk rather than
        // discarding what was already read: a partial tar is still evidence.
        let Ok(mut entry) = entry else { break };
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let Ok(size) = entry.header().size() else {
            continue;
        };
        // A member is read whole or not at all: half a credential is not one,
        // and reading the first part of an oversized member would spend the
        // archive's remaining bytes to find nothing.
        let room = (caps.total - scanned) as u64;
        if size == 0 || size > caps.member || size > room {
            continue;
        }
        let Some(member_name) = entry_name(&entry) else {
            continue;
        };
        let mut member: Vec<u8> = Vec::new();
        // Bounded by the header's claim and by the member cap, so a header
        // that lies about a short member cannot pull in the rest of the tar.
        if entry.by_ref().take(size).read_to_end(&mut member).is_err() {
            continue;
        }
        scanned = scanned.saturating_add(member.len());
        let member_path = member_path(path, &member_name);
        let remaining = finding_budget.saturating_sub(findings.len());
        let Some(text) = decode_text(&member_path, &member) else {
            continue;
        };
        let summary = scan_secret_text(text, &member_path, source, commit, remaining);
        for finding in summary.findings {
            let key = (
                finding.path.clone(),
                finding.line,
                candidate_digest(&finding.candidate),
            );
            if !read.insert(key) {
                continue;
            }
            findings.push(finding);
        }
    }
    (findings, scanned)
}

/// A tar member's path as a reported name.
///
/// The name is taken as the archive spells it. A backslash is left alone: on
/// the format's own terms it is an ordinary character in a filename, and
/// rewriting it to a slash made `a\b.env` and `a/b.env` the same reported
/// path. Invalid UTF-8 is still replaced rather than refused, because the
/// member that carries it is exactly the one worth reading.
fn entry_name<R: Read>(entry: &tar::Entry<'_, R>) -> Option<String> {
    let path = entry.path().ok()?;
    let name = path.to_string_lossy();
    if name.is_empty() {
        return None;
    }
    Some(name.into_owned())
}

fn scan_single_member(
    bytes: &[u8],
    member_path: &str,
    source: &str,
    commit: Option<&str>,
    finding_budget: usize,
) -> (Vec<SecretFinding>, usize) {
    let Some(text) = decode_text(member_path, bytes) else {
        return (Vec::new(), 0);
    };
    let summary = scan_secret_text(text, member_path, source, commit, finding_budget);
    (summary.findings, bytes.len())
}

#[cfg(test)]
#[path = "repository_scanner_archive_tests.rs"]
mod tests;
