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
//! This module reads the members of the archive formats whose readers the
//! workspace already carries: gzip, tar, and the two of them together. A
//! member is reported under the name `backup.tar.gz!etc/config.env`, which
//! says both which archive held it and where inside, and which no real path
//! can collide with because `!` cannot appear in a tar member name that the
//! reader accepts after normalisation.
//!
//! Every bound here exists because an archive is attacker-shaped input: a few
//! hundred bytes of gzip expand to gigabytes, a tar names a thousand empty
//! members, a member claims a size the stream never delivers. The caps are
//! deliberately smaller than the scan's own file cap, since a credential is a
//! line of text and nothing here needs to read a disk image to find one.
//!
//! `zip` is still unread: no zip reader is in the dependency graph, and adding
//! one moves `Cargo.lock`, so it is left to a change that can carry that.

use std::io::{Cursor, Read};

use super::{decode_text, scan_secret_text, SecretFinding};

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

/// The separator between an archive's own path and the member inside it.
pub(super) const MEMBER_SEPARATOR: char = '!';

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
) -> Option<(Vec<SecretFinding>, usize)> {
    let payload = if is_gzip(data) {
        Payload::Owned(inflate_gzip(data)?)
    } else if is_tar(data) {
        Payload::Borrowed(data)
    } else {
        return None;
    };
    let bytes = payload.as_slice();
    if is_tar(bytes) {
        return Some(scan_tar(bytes, path, source, commit, finding_budget));
    }
    // A plain `.gz`: one file compressed on its own, named for the archive
    // without the suffix that says it was compressed.
    Some(scan_single_member(
        bytes,
        &gunzipped_name(path),
        source,
        commit,
        finding_budget,
    ))
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

/// Inflate a gzip stream under both an absolute cap and a ratio cap, so
/// neither a long stream nor a short one that claims to be long is read.
fn inflate_gzip(data: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut inflated: Vec<u8> = Vec::new();
    // One byte past the cap, so a stream that exactly fills it is told apart
    // from one that would have run over.
    let read = (&mut decoder)
        .take(MAX_TOTAL_BYTES as u64 + 1)
        .read_to_end(&mut inflated);
    if read.is_err() || inflated.len() > MAX_TOTAL_BYTES {
        return None;
    }
    if inflated.len() > RATIO_FLOOR_BYTES
        && inflated.len() / data.len().max(1) > MAX_EXPANSION_RATIO
    {
        return None;
    }
    Some(inflated)
}

/// `backup.tar.gz` names a tar once gunzipped; `notes.txt.gz` names a text
/// file. Either way the compression suffix is what stops naming the content.
fn gunzipped_name(path: &str) -> String {
    for suffix in [".gz", ".GZ"] {
        if let Some(stem) = path.strip_suffix(suffix) {
            return stem.to_owned();
        }
    }
    if let Some(stem) = path
        .strip_suffix(".tgz")
        .or_else(|| path.strip_suffix(".TGZ"))
    {
        return format!("{stem}.tar");
    }
    path.to_owned()
}

fn scan_tar(
    bytes: &[u8],
    path: &str,
    source: &str,
    commit: Option<&str>,
    finding_budget: usize,
) -> (Vec<SecretFinding>, usize) {
    let mut findings: Vec<SecretFinding> = Vec::new();
    let mut scanned = 0usize;
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let Ok(entries) = archive.entries() else {
        return (findings, scanned);
    };
    for (seen, entry) in entries.enumerate() {
        if seen >= MAX_MEMBERS || findings.len() >= finding_budget || scanned >= MAX_TOTAL_BYTES {
            break;
        }
        // A truncated or malformed archive stops the walk rather than
        // discarding what was already read: a partial tar is still evidence.
        let Ok(mut entry) = entry else { break };
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let Ok(size) = entry.header().size() else {
            continue;
        };
        if size == 0 || size > MAX_MEMBER_BYTES {
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
        let member_path = format!("{path}{MEMBER_SEPARATOR}{member_name}");
        let remaining = finding_budget.saturating_sub(findings.len());
        let Some(text) = decode_text(&member_path, &member) else {
            continue;
        };
        let summary = scan_secret_text(text, &member_path, source, commit, remaining);
        findings.extend(summary.findings);
    }
    (findings, scanned)
}

/// A tar member's path as a reported name: relative, slash-separated, and
/// never carrying the separator that would make it look like its own archive.
fn entry_name<R: Read>(entry: &tar::Entry<'_, R>) -> Option<String> {
    let path = entry.path().ok()?;
    let name = path.to_string_lossy();
    if name.is_empty() || name.contains(MEMBER_SEPARATOR) {
        return None;
    }
    Some(name.replace('\\', "/"))
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
