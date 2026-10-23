//! Bounded readers for stored (uncompressed) ZIP archives.
//!
//! The delivery containers and the offline transfer archive share one reading
//! discipline: a member is admitted only when its central entry, local header,
//! declared lengths and CRC all agree, and nothing is decompressed. Each caller
//! adds its own naming, count and layout policy on top of these primitives.
use std::ops::Range;

const END: &[u8] = b"PK\x05\x06";
const CENTRAL: &[u8] = b"PK\x01\x02";
const LOCAL: &[u8] = b"PK\x03\x04";
const END_BYTES: usize = 22;
const CENTRAL_BYTES: usize = 46;
const LOCAL_BYTES: usize = 30;

pub(crate) fn u16at(bytes: &[u8], at: usize) -> Option<usize> {
    let raw = bytes.get(at..at.checked_add(2)?)?;
    Some(usize::from(u16::from_le_bytes(raw.try_into().ok()?)))
}

pub(crate) fn u32at(bytes: &[u8], at: usize) -> Option<usize> {
    let raw = bytes.get(at..at.checked_add(4)?)?;
    usize::try_from(u32::from_le_bytes(raw.try_into().ok()?)).ok()
}

/// The end-of-central-directory record of a single-disk archive without comment.
pub(crate) struct End {
    pub(crate) count: usize,
    pub(crate) start: usize,
    pub(crate) central: usize,
    pub(crate) tail: usize,
}

/// Locate the central directory. It must end exactly where the record begins.
pub(crate) fn end(bytes: &[u8]) -> Option<End> {
    let tail = bytes.len().checked_sub(END_BYTES)?;
    if bytes.get(tail..tail + 4)? != END
        || u16at(bytes, tail + 4)? != 0
        || u16at(bytes, tail + 6)? != 0
        || u16at(bytes, tail + 20)? != 0
    {
        return None;
    }
    let count = u16at(bytes, tail + 10)?;
    let central = u32at(bytes, tail + 12)?;
    let start = u32at(bytes, tail + 16)?;
    if count == 0 || u16at(bytes, tail + 8)? != count || start.checked_add(central)? != tail {
        return None;
    }
    Some(End {
        count,
        start,
        central,
        tail,
    })
}

/// One central-directory entry. Each caller states which of its optional
/// fields it admits; this reader only reports them.
pub(crate) struct Entry<'a> {
    pub(crate) name: &'a str,
    pub(crate) flags: usize,
    pub(crate) method: usize,
    pub(crate) crc: usize,
    pub(crate) packed: usize,
    pub(crate) size: usize,
    pub(crate) extra: usize,
    pub(crate) comment: usize,
    pub(crate) disk: usize,
    pub(crate) attr: usize,
    pub(crate) header: usize,
    pub(crate) next: usize,
}

impl Entry<'_> {
    pub(crate) fn regular(&self) -> bool {
        (self.attr >> 16) & 0o170000 == 0o100000
    }
}

pub(crate) fn entry(bytes: &[u8], at: usize) -> Option<Entry<'_>> {
    if bytes.get(at..at.checked_add(4)?)? != CENTRAL {
        return None;
    }
    let length = u16at(bytes, at + 28)?;
    let extra = u16at(bytes, at + 30)?;
    let comment = u16at(bytes, at + 32)?;
    let named = at.checked_add(CENTRAL_BYTES)?.checked_add(length)?;
    let name = std::str::from_utf8(bytes.get(at + CENTRAL_BYTES..named)?).ok()?;
    Some(Entry {
        name,
        flags: u16at(bytes, at + 8)?,
        method: u16at(bytes, at + 10)?,
        crc: u32at(bytes, at + 16)?,
        packed: u32at(bytes, at + 20)?,
        size: u32at(bytes, at + 24)?,
        extra,
        comment,
        disk: u16at(bytes, at + 34)?,
        attr: u32at(bytes, at + 38)?,
        header: u32at(bytes, at + 42)?,
        next: named.checked_add(extra)?.checked_add(comment)?,
    })
}

/// The member's bytes, after its local header and CRC agree with the central
/// entry. `limit` is where the central directory begins; data may not reach it.
pub(crate) fn data(bytes: &[u8], entry: &Entry<'_>, limit: usize) -> Option<Range<usize>> {
    let header = entry.header;
    let length = entry.name.len();
    if bytes.get(header..header.checked_add(4)?)? != LOCAL
        || u16at(bytes, header + 6)? != entry.flags
        || u16at(bytes, header + 8)? != entry.method
        || u32at(bytes, header + 14)? != entry.crc
        || u32at(bytes, header + 18)? != entry.packed
        || u32at(bytes, header + 22)? != entry.size
        || u16at(bytes, header + 26)? != length
        || u16at(bytes, header + 28)? != 0
        || bytes.get(header + LOCAL_BYTES..header + LOCAL_BYTES + length)? != entry.name.as_bytes()
    {
        return None;
    }
    let begin = header + LOCAL_BYTES + length;
    let finish = begin.checked_add(entry.size)?;
    if finish > limit {
        return None;
    }
    let mut crc = flate2::Crc::new();
    crc.update(bytes.get(begin..finish)?);
    if usize::try_from(crc.sum()).ok()? != entry.crc {
        return None;
    }
    Some(begin..finish)
}

#[cfg(test)]
#[path = "stored_zip_tests.rs"]
pub(crate) mod tests;
