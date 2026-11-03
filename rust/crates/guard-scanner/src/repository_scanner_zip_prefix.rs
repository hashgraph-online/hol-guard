//! Where the zip in a blob begins when something is written in front of it.
//!
//! A self-extracting archive is an executable with a zip appended to it, and
//! it is the common way a secret leaves a repository in a shape no reader
//! looks inside. Two things keep the walk beside this module from reading
//! one. The bytes at offset zero belong to the stub, so the signature check
//! says this is not an archive; and the offsets the archive records are
//! counted from somewhere other than the start of the file, so following them
//! against the whole blob lands in the stub.
//!
//! Both are answered by finding the position those offsets are counted from
//! and reading from there, which is the rebase the format asks for and
//! nothing more. The end records are found from the tail the way they always
//! are. Each one states its directory's size and the directory's offset from
//! the archive's own origin, and the directory ends where the record begins,
//! so the origin is the record's position less the two.
//!
//! Which origin is used matters as much as finding one. An archive's trailing
//! comment is the cheapest place to plant a second end record, and one
//! planted there is reached from the tail before the real one. A forged
//! record naming a later member would, if it decided alone, cut every member
//! in front of that one out of the bytes handed to the walk. So every end
//! record in the window is read and the earliest origin any of them names is
//! the one used: the walk over the local headers reaches every member behind
//! that point, and a forged record can only ever name a later one.
//!
//! Two spellings of the offsets reach this module. An archive appended to a
//! stub counts from its own first local header, so the origin is the stub's
//! length. A builder such as `zip -A`, and the WinZip and WinRAR self-extractor
//! builders, adjust the recorded offsets to the whole file instead, and for
//! those the origin is byte zero even though the file begins with `MZ`. The
//! same arithmetic yields both, and the check that an origin is real is made
//! against the first record's own account of where its member sits rather than
//! against an assumption about byte zero.

use super::{
    is_zip, u16_at, u32_at, CENTRAL_SIGNATURE, EOCD_FIXED, EOCD_SIGNATURE, LOCAL_SIGNATURE,
    MAX_COMMENT,
};

/// Where a central directory record states the offset of the local header
/// that owns its member.
const LOCAL_OFFSET_FIELD: usize = 42;

/// The position the offsets in `data`'s archive are counted from, or `None`
/// when there is no archive behind those bytes.
///
/// The earliest origin any readable end record names is the one returned, so
/// a record planted in an archive's comment cannot shorten what is read.
pub(super) fn embedded_start(data: &[u8]) -> Option<usize> {
    let window = data.len().min(EOCD_FIXED + MAX_COMMENT);
    let first = data.len() - window;
    let last = data.len().checked_sub(EOCD_FIXED)?;
    let mut earliest: Option<usize> = None;
    for candidate in first..=last {
        // The window is the whole tail of every binary blob that holds no
        // archive at all, so one byte decides almost every position in it and
        // the four-byte compare runs only where that byte can begin a record.
        if data[candidate] != EOCD_SIGNATURE[0] || data[candidate + 1] != EOCD_SIGNATURE[1] {
            continue;
        }
        if !data[candidate..].starts_with(EOCD_SIGNATURE) {
            continue;
        }
        let Some(origin) = origin_at(data, candidate) else {
            continue;
        };
        earliest = Some(match earliest {
            Some(earlier) => earlier.min(origin),
            None => origin,
        });
        // Nothing lies in front of the start of the file, so there is no
        // earlier origin left for the rest of the window to name.
        if earliest == Some(0) {
            break;
        }
    }
    earliest
}

/// The origin the end record at `candidate` implies, when the archive it names
/// is really there.
fn origin_at(data: &[u8], candidate: usize) -> Option<usize> {
    let comment = u16_at(data, candidate + 20)? as usize;
    if candidate + EOCD_FIXED + comment != data.len() {
        return None;
    }
    let size = u32_at(data, candidate + 12)? as usize;
    let offset = u32_at(data, candidate + 16)? as usize;
    // An empty directory names no member, so there is nothing behind the stub
    // for this to reach. A zip64 archive states both figures as sentinels,
    // which the subtraction below refuses rather than acts on.
    if size == 0 {
        return None;
    }
    // The directory ends where the record naming it begins, which is how every
    // archiver writes one. An archive with slack between them lands this in
    // the wrong place, and the checks below are what refuse it rather than
    // rebase on it.
    let directory_at = candidate.checked_sub(size)?;
    let origin = directory_at.checked_sub(offset)?;
    // An archive that already begins with a zip signature is read where the
    // signature check found it rather than twice. An origin of zero for a blob
    // that does not is the adjusted spelling, and it is the answer.
    if origin == 0 && is_zip(data) {
        return None;
    }
    let directory = data.get(directory_at..)?;
    if !directory.starts_with(CENTRAL_SIGNATURE) {
        return None;
    }
    // The first record's own account of where its member sits is what tells an
    // archive from an end record that happened to fall inside a binary, and
    // reading the position from the record rather than assuming the archive
    // begins at its origin is what lets both spellings of the offsets through.
    let member_at = origin.checked_add(u32_at(directory, LOCAL_OFFSET_FIELD)? as usize)?;
    data.get(member_at..)?
        .starts_with(LOCAL_SIGNATURE)
        .then_some(origin)
}

#[cfg(test)]
#[path = "repository_scanner_zip_prefix_tests.rs"]
mod tests;
