//! Pre-allocation tar framing guard.
//!
//! `tar` sizes several buffers from numbers a header advertises: GNU long
//! name/link and PAX records are read whole, and a GNU sparse header drags in
//! an unbounded chain of extension blocks that each become heap entries. None
//! of that is subject to the inspector's caps. This reader sits between the
//! decoder and `tar::Archive`, walks the same 512-byte framing the library
//! walks (using the library's own header parsing so the two cannot disagree on
//! a field), and fails the stream *before* the offending header is handed to
//! the library, so the library never gets to allocate for it.
//!
//! It also polls the caller's halt predicate and deadline on every read, which
//! bounds the time spent inside one `entries().next()` call that consumes
//! many metadata records without yielding a member.
//!
//! The guard never changes a byte it forwards. Anything it cannot interpret it
//! stops tracking (`Done`): `tar` then rejects the same header itself.

use std::cell::Cell;
use std::io::{self, Read};
use std::rc::Rc;
use std::time::Instant;

use tar::{Header, PaxExtensions};

const BLOCK: usize = 512;
const SPARSE_EXTENDED_FLAG_OFFSET: usize = 504;

/// Largest GNU long name/link or PAX record accepted (further capped by the
/// caller's per-member limit). Real records are a few KiB; `tar` may hold a
/// long name, a long link and a PAX record per member at once.
pub(crate) const METADATA_RECORD_CAP: u64 = 1024 * 1024;
/// Longest GNU sparse extension chain accepted. Sparse members are refused by
/// member policy anyway; this only bounds the work done to reach that verdict.
pub(crate) const MAX_SPARSE_EXTENSION_BLOCKS: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    MetadataTooLarge,
    SparseChainTooLong,
    /// A PAX record set that parsers resolve differently (a repeated
    /// `path`, `linkpath` or `size`, or a record that does not parse).
    AmbiguousPax,
    Halted,
    Timeout,
}

/// What the guard observed, shared with the member loop.
#[derive(Default)]
pub(crate) struct GuardReport {
    verdict: Cell<Option<Verdict>>,
    entry_header_pos: Cell<Option<u64>>,
}

impl GuardReport {
    pub(crate) fn verdict(&self) -> Option<Verdict> {
        self.verdict.get()
    }

    /// Header offset of the most recent header `tar` yields as a member; the
    /// member loop compares it with `Entry::raw_header_position` so any
    /// framing disagreement is detected instead of assumed away.
    pub(crate) fn entry_header_pos(&self) -> Option<u64> {
        self.entry_header_pos.get()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Meta {
    LongName,
    LongLink,
    Pax,
}

enum State {
    Header {
        buf: Box<[u8; BLOCK]>,
        filled: usize,
    },
    Skip {
        remaining: u64,
    },
    PaxData {
        remaining: u64,
        padding: u64,
        buf: Vec<u8>,
    },
    SparseExt {
        buf: Box<[u8; BLOCK]>,
        filled: usize,
        blocks: u64,
        then_skip: u64,
    },
    Done,
}

fn fresh_header() -> State {
    State::Header {
        buf: Box::new([0; BLOCK]),
        filled: 0,
    }
}

fn skip_or_header(remaining: u64) -> State {
    if remaining == 0 {
        fresh_header()
    } else {
        State::Skip { remaining }
    }
}

/// The framing state machine, independent of any I/O so it can be driven
/// byte-by-byte in tests.
pub(crate) struct Framer {
    offset: u64,
    header_start: u64,
    state: State,
    /// A PAX record was read and has not yet been attached to a member.
    pending_pax: bool,
    pending_pax_size: Option<u64>,
    /// The pending PAX record carries a `path` / `linkpath` key.
    pending_pax_path: bool,
    pending_pax_linkpath: bool,
    /// A GNU long name / long link header was read for the next member.
    pending_long_name: bool,
    pending_long_link: bool,
    meta_cap: u64,
    entry_header_pos: Option<u64>,
}

impl Framer {
    pub(crate) fn new(meta_cap: u64) -> Self {
        Self {
            offset: 0,
            header_start: 0,
            state: fresh_header(),
            pending_pax: false,
            pending_pax_size: None,
            pending_pax_path: false,
            pending_pax_linkpath: false,
            pending_long_name: false,
            pending_long_link: false,
            meta_cap: meta_cap.min(METADATA_RECORD_CAP),
            entry_header_pos: None,
        }
    }

    pub(crate) fn entry_header_pos(&self) -> Option<u64> {
        self.entry_header_pos
    }

    pub(crate) fn feed(&mut self, mut data: &[u8]) -> Result<(), Verdict> {
        while !data.is_empty() {
            match &mut self.state {
                State::Done => return Ok(()),
                State::Skip { remaining } => {
                    let take = (*remaining).min(data.len() as u64) as usize;
                    *remaining -= take as u64;
                    data = &data[take..];
                    self.offset += take as u64;
                    if *remaining == 0 {
                        self.state = fresh_header();
                    }
                }
                State::PaxData {
                    remaining,
                    padding,
                    buf,
                } => {
                    let take = (*remaining).min(data.len() as u64) as usize;
                    buf.extend_from_slice(&data[..take]);
                    *remaining -= take as u64;
                    data = &data[take..];
                    self.offset += take as u64;
                    if *remaining == 0 {
                        if pax_is_ambiguous(buf) {
                            return Err(Verdict::AmbiguousPax);
                        }
                        let size = pax_extensions_value(buf, "size");
                        let (has_path, has_linkpath) = pax_path_keys(buf);
                        let padding = *padding;
                        // A GNU long name and a PAX `path` (likewise a long
                        // link and `linkpath`) name the same member twice and
                        // extractors disagree on which wins.
                        if (has_path && self.pending_long_name)
                            || (has_linkpath && self.pending_long_link)
                        {
                            return Err(Verdict::AmbiguousPax);
                        }
                        self.pending_pax_size = size;
                        self.pending_pax_path = has_path;
                        self.pending_pax_linkpath = has_linkpath;
                        self.state = skip_or_header(padding);
                    }
                }
                State::Header { buf, filled } => {
                    let take = (BLOCK - *filled).min(data.len());
                    buf[*filled..*filled + take].copy_from_slice(&data[..take]);
                    *filled += take;
                    data = &data[take..];
                    self.offset += take as u64;
                    if *filled == BLOCK {
                        let block = **buf;
                        self.header_start = self.offset - BLOCK as u64;
                        self.on_header(&block)?;
                    }
                }
                State::SparseExt {
                    buf,
                    filled,
                    blocks,
                    then_skip,
                } => {
                    let take = (BLOCK - *filled).min(data.len());
                    buf[*filled..*filled + take].copy_from_slice(&data[..take]);
                    *filled += take;
                    data = &data[take..];
                    self.offset += take as u64;
                    if *filled == BLOCK {
                        *blocks += 1;
                        // `tar` keeps reading extension blocks while the flag
                        // byte is exactly 1.
                        if buf[SPARSE_EXTENDED_FLAG_OFFSET] == 1 {
                            if *blocks >= MAX_SPARSE_EXTENSION_BLOCKS {
                                return Err(Verdict::SparseChainTooLong);
                            }
                            *filled = 0;
                        } else {
                            let skip = *then_skip;
                            self.state = skip_or_header(skip);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn on_header(&mut self, block: &[u8; BLOCK]) -> Result<(), Verdict> {
        // All-zero block: `tar` ends the archive here and reads no further.
        if block.iter().all(|byte| *byte == 0) {
            self.state = State::Done;
            return Ok(());
        }
        let mut header = Header::new_old();
        header.as_mut_bytes().copy_from_slice(block);
        // `tar` rejects a bad checksum or size field itself; stop tracking.
        let Ok(checksum) = header.cksum() else {
            self.state = State::Done;
            return Ok(());
        };
        let sum = block[..148]
            .iter()
            .chain(&block[156..])
            .fold(0u32, |acc, byte| acc.wrapping_add(u32::from(*byte)))
            .wrapping_add(8 * 32);
        if sum != checksum {
            self.state = State::Done;
            return Ok(());
        }
        let entry_type = header.entry_type();
        let is_extension_type = entry_type.is_gnu_longname()
            || entry_type.is_gnu_longlink()
            || entry_type.is_pax_local_extensions()
            || entry_type.is_pax_global_extensions();
        let pax_size = if is_extension_type {
            None
        } else {
            self.pending_pax_size
        };
        let Ok(field_size) = header.entry_size() else {
            self.state = State::Done;
            return Ok(());
        };
        let size = pax_size.unwrap_or(field_size);
        let Some(padded) = size
            .checked_add(BLOCK as u64 - 1)
            .map(|rounded| rounded & !(BLOCK as u64 - 1))
        else {
            self.state = State::Done;
            return Ok(());
        };
        let recognized = header.as_gnu().is_some() || header.as_ustar().is_some();
        let meta = if !recognized {
            None
        } else if entry_type.is_gnu_longname() {
            Some(Meta::LongName)
        } else if entry_type.is_gnu_longlink() {
            Some(Meta::LongLink)
        } else if entry_type.is_pax_local_extensions() {
            Some(Meta::Pax)
        } else {
            None
        };
        if let Some(meta) = meta {
            // Checked against the header's own size field: extension headers
            // never take a PAX size override.
            if size > self.meta_cap {
                return Err(Verdict::MetadataTooLarge);
            }
            match meta {
                Meta::LongName => {
                    if self.pending_pax_path {
                        return Err(Verdict::AmbiguousPax);
                    }
                    self.pending_long_name = true;
                }
                Meta::LongLink => {
                    if self.pending_pax_linkpath {
                        return Err(Verdict::AmbiguousPax);
                    }
                    self.pending_long_link = true;
                }
                Meta::Pax => {}
            }
            if meta == Meta::Pax {
                if self.pending_pax {
                    // `tar` rejects two PAX records for one member.
                    self.state = State::Done;
                    return Ok(());
                }
                self.pending_pax = true;
                self.pending_pax_size = None;
                self.state = State::PaxData {
                    remaining: size,
                    padding: padded - size,
                    buf: Vec::with_capacity(size as usize),
                };
                if size == 0 {
                    self.state = skip_or_header(padded);
                }
                return Ok(());
            }
            self.state = skip_or_header(padded);
            return Ok(());
        }
        // `tar` yields this header as a member and consumes the pending PAX
        // record whether or not the size override applied.
        self.pending_pax = false;
        self.pending_pax_size = None;
        self.pending_pax_path = false;
        self.pending_pax_linkpath = false;
        self.pending_long_name = false;
        self.pending_long_link = false;
        self.entry_header_pos = Some(self.header_start);
        if entry_type.is_gnu_sparse() {
            match header.as_gnu() {
                Some(gnu) if gnu.is_extended() => {
                    self.state = State::SparseExt {
                        buf: Box::new([0; BLOCK]),
                        filled: 0,
                        blocks: 0,
                        then_skip: padded,
                    };
                    return Ok(());
                }
                Some(_) => {}
                None => {
                    self.state = State::Done;
                    return Ok(());
                }
            }
        }
        self.state = skip_or_header(padded);
        Ok(())
    }
}

/// POSIX lets a later record override an earlier one, `tar` keeps the first,
/// and other extractors differ again. A path-bearing or size-bearing key that
/// appears twice, or a record that does not parse, therefore has no single
/// meaning; refuse it rather than pick the interpretation that looks safe.
fn pax_is_ambiguous(records: &[u8]) -> bool {
    let (mut paths, mut links, mut sizes) = (0u32, 0u32, 0u32);
    for extension in PaxExtensions::new(records) {
        let Ok(extension) = extension else {
            return true;
        };
        match extension.key() {
            Ok("path") => paths += 1,
            Ok("linkpath") => links += 1,
            Ok("size") => sizes += 1,
            Ok(_) => {}
            Err(_) => return true,
        }
    }
    paths > 1 || links > 1 || sizes > 1
}

/// Whether a PAX record set carries a `path` and a `linkpath` key.
fn pax_path_keys(records: &[u8]) -> (bool, bool) {
    let (mut path, mut linkpath) = (false, false);
    for extension in PaxExtensions::new(records).flatten() {
        match extension.key() {
            Ok("path") => path = true,
            Ok("linkpath") => linkpath = true,
            _ => {}
        }
    }
    (path, linkpath)
}

/// `tar`'s private `pax_extensions_value`, rebuilt on its public parser: the
/// first record with this key wins, and an unparsable record yields `None`.
fn pax_extensions_value(records: &[u8], key: &str) -> Option<u64> {
    for extension in PaxExtensions::new(records) {
        let extension = match extension {
            Ok(extension) => extension,
            Err(_) => return None,
        };
        if extension.key() != Ok(key) {
            continue;
        }
        return extension.value().ok()?.parse::<u64>().ok();
    }
    None
}

/// Reader adapter that applies [`Framer`] to everything flowing to `tar`.
pub(crate) struct FramingGuard<'h, R> {
    inner: R,
    framer: Framer,
    report: Rc<GuardReport>,
    deadline: Instant,
    halt: &'h dyn Fn() -> bool,
}

impl<'h, R: Read> FramingGuard<'h, R> {
    pub(crate) fn new(
        inner: R,
        meta_cap: u64,
        deadline: Instant,
        halt: &'h dyn Fn() -> bool,
        report: Rc<GuardReport>,
    ) -> Self {
        Self {
            inner,
            framer: Framer::new(meta_cap),
            report,
            deadline,
            halt,
        }
    }

    fn fail(&self, verdict: Verdict) -> io::Error {
        if self.report.verdict.get().is_none() {
            self.report.verdict.set(Some(verdict));
        }
        io::Error::other(format!("tar framing guard refused the stream: {verdict:?}"))
    }
}

impl<R: Read> Read for FramingGuard<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(verdict) = self.report.verdict.get() {
            return Err(self.fail(verdict));
        }
        if (self.halt)() {
            return Err(self.fail(Verdict::Halted));
        }
        if Instant::now() > self.deadline {
            return Err(self.fail(Verdict::Timeout));
        }
        let count = self.inner.read(buf)?;
        match self.framer.feed(&buf[..count]) {
            Ok(()) => {
                self.report
                    .entry_header_pos
                    .set(self.framer.entry_header_pos());
                Ok(count)
            }
            Err(verdict) => Err(self.fail(verdict)),
        }
    }
}
