//! Bounded DEFLATE / zlib / gzip readers mirroring the CPython `zlib` and `gzip`
//! behaviours that `safe_decode._bytes_to_text` relies on.
//!
//! The decoder is incremental in the sense that matters for parity: input that ends
//! mid-stream yields the output decoded so far (no error), while malformed streams are
//! rejected with the same conditions zlib reports.

/// How an `inflate` run ended.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) enum InflateEnd {
    /// Final block fully decoded.
    Done,
    /// Input exhausted before the final block ended.
    Truncated,
    /// Output cap reached.
    Limit,
}

pub(super) struct Inflated {
    pub out: Vec<u8>,
    pub end: InflateEnd,
    /// Bytes consumed (rounded up to a byte boundary); meaningful for `Done`.
    pub consumed: usize,
}

/// Failure categories of the Python `gzip` read path.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) enum GzipFailure {
    /// `OSError` / `zlib.error`: suppressed by `_bytes_to_text` (raw bytes kept).
    Suppressed,
    /// `EOFError`: propagates out of `decode_layers`.
    Eof,
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    /// Reads `n` (<= 16) bits LSB-first; `None` when input is exhausted.
    fn take(&mut self, n: usize) -> Option<u32> {
        if self.pos + n > self.data.len() * 8 {
            return None;
        }
        let mut value = 0u32;
        for i in 0..n {
            let bit = (self.data[(self.pos + i) >> 3] >> ((self.pos + i) & 7)) & 1;
            value |= u32::from(bit) << i;
        }
        self.pos += n;
        Some(value)
    }
}

enum Step<T> {
    Ok(T),
    Truncated,
    Error,
}

struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    /// Builds a canonical code, applying zlib's `inflate_table` acceptance rules.
    fn build(lengths: &[u8], require_complete: bool) -> Option<Huffman> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            counts[usize::from(len)] += 1;
        }
        let max = (1..16).rev().find(|&l| counts[l] != 0).unwrap_or(0);
        let mut left: i32 = 1;
        for &count in counts.iter().skip(1) {
            left <<= 1;
            left -= i32::from(count);
            if left < 0 {
                return None;
            }
        }
        if max != 0 && left > 0 && (require_complete || max != 1) {
            return None;
        }
        let mut offsets = [0u16; 16];
        for l in 1..15 {
            offsets[l + 1] = offsets[l] + counts[l];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (sym, &len) in lengths.iter().enumerate() {
            if len != 0 {
                symbols[usize::from(offsets[usize::from(len)])] = sym as u16;
                offsets[usize::from(len)] += 1;
            }
        }
        counts[0] = 0;
        Some(Huffman { counts, symbols })
    }

    fn decode(&self, bits: &mut Bits<'_>) -> Step<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            let Some(bit) = bits.take(1) else {
                return Step::Truncated;
            };
            code |= bit as i32;
            let count = i32::from(self.counts[len]);
            if code - count < first {
                // `code >= first` holds for canonical codes, so the slot is in
                // range; a bad table still ends as a malformed stream, not a panic.
                let slot = usize::try_from(index + (code - first)).ok();
                return match slot.and_then(|slot| self.symbols.get(slot)) {
                    Some(&symbol) => Step::Ok(symbol),
                    None => Step::Error,
                };
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Step::Error
    }
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn finish(out: Vec<u8>, end: InflateEnd, bits: &Bits<'_>) -> Inflated {
    Inflated {
        out,
        end,
        consumed: bits.pos.div_ceil(8),
    }
}

fn bits_step(bits: &mut Bits<'_>, n: usize) -> Step<u32> {
    bits.take(n).map_or(Step::Truncated, Step::Ok)
}

fn fixed_tables() -> (Huffman, Huffman) {
    let mut lengths = [0u8; 288];
    for (i, slot) in lengths.iter_mut().enumerate() {
        *slot = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let lit = Huffman::build(&lengths, true).expect("fixed literal table is complete");
    let dist = Huffman::build(&[5u8; 32], true).expect("fixed distance table is complete");
    (lit, dist)
}

fn dynamic_tables(bits: &mut Bits<'_>) -> Step<(Huffman, Huffman)> {
    macro_rules! t {
        ($e:expr) => {
            match $e {
                Step::Ok(v) => v,
                Step::Truncated => return Step::Truncated,
                Step::Error => return Step::Error,
            }
        };
    }
    let nlen = t!(bits_step(bits, 5)) as usize + 257;
    let ndist = t!(bits_step(bits, 5)) as usize + 1;
    let ncode = t!(bits_step(bits, 4)) as usize + 4;
    if nlen > 286 || ndist > 30 {
        return Step::Error;
    }
    let mut clens = [0u8; 19];
    for &slot in CLEN_ORDER.iter().take(ncode) {
        clens[slot] = t!(bits_step(bits, 3)) as u8;
    }
    let Some(code_table) = Huffman::build(&clens, true) else {
        return Step::Error;
    };
    let mut lengths = vec![0u8; nlen + ndist];
    let mut have = 0usize;
    while have < nlen + ndist {
        let sym = t!(code_table.decode(bits));
        if sym < 16 {
            lengths[have] = sym as u8;
            have += 1;
            continue;
        }
        let (prev, repeat) = match sym {
            16 => {
                if have == 0 {
                    return Step::Error;
                }
                (lengths[have - 1], 3 + t!(bits_step(bits, 2)) as usize)
            }
            17 => (0, 3 + t!(bits_step(bits, 3)) as usize),
            _ => (0, 11 + t!(bits_step(bits, 7)) as usize),
        };
        if have + repeat > nlen + ndist {
            return Step::Error;
        }
        for _ in 0..repeat {
            lengths[have] = prev;
            have += 1;
        }
    }
    if lengths[256] == 0 {
        return Step::Error;
    }
    let Some(lit) = Huffman::build(&lengths[..nlen], false) else {
        return Step::Error;
    };
    let Some(dist) = Huffman::build(&lengths[nlen..], false) else {
        return Step::Error;
    };
    Step::Ok((lit, dist))
}

/// Raw DEFLATE decode capped at `limit` output bytes.
pub(super) fn inflate(data: &[u8], limit: usize) -> Result<Inflated, ()> {
    let mut bits = Bits { data, pos: 0 };
    let mut out: Vec<u8> = Vec::new();
    macro_rules! need {
        ($e:expr) => {
            match $e {
                Step::Ok(v) => v,
                Step::Truncated => return Ok(finish(out, InflateEnd::Truncated, &bits)),
                Step::Error => return Err(()),
            }
        };
    }

    loop {
        let last = need!(bits_step(&mut bits, 1));
        let kind = need!(bits_step(&mut bits, 2));
        match kind {
            0 => {
                bits.pos = bits.pos.div_ceil(8) * 8;
                let start = bits.pos / 8;
                if start + 4 > data.len() {
                    return Ok(finish(out, InflateEnd::Truncated, &bits));
                }
                let len = usize::from(data[start]) | (usize::from(data[start + 1]) << 8);
                let nlen = usize::from(data[start + 2]) | (usize::from(data[start + 3]) << 8);
                if len != (!nlen & 0xffff) {
                    return Err(());
                }
                let body = start + 4;
                let avail = data.len() - body;
                let take = len.min(avail).min(limit - out.len());
                out.extend_from_slice(&data[body..body + take]);
                bits.pos = (body + take) * 8;
                if out.len() >= limit {
                    return Ok(finish(out, InflateEnd::Limit, &bits));
                }
                if take < len {
                    return Ok(finish(out, InflateEnd::Truncated, &bits));
                }
            }
            1 | 2 => {
                let (lit, dist) = if kind == 1 {
                    fixed_tables()
                } else {
                    need!(dynamic_tables(&mut bits))
                };
                loop {
                    let sym = need!(lit.decode(&mut bits)) as usize;
                    if sym < 256 {
                        out.push(sym as u8);
                        if out.len() >= limit {
                            return Ok(finish(out, InflateEnd::Limit, &bits));
                        }
                        continue;
                    }
                    if sym == 256 {
                        break;
                    }
                    if sym > 285 {
                        return Err(());
                    }
                    let li = sym - 257;
                    let extra = need!(bits_step(&mut bits, usize::from(LEN_EXTRA[li])));
                    let length = usize::from(LEN_BASE[li]) + extra as usize;
                    let dsym = need!(dist.decode(&mut bits)) as usize;
                    if dsym > 29 {
                        return Err(());
                    }
                    let dextra = need!(bits_step(&mut bits, usize::from(DIST_EXTRA[dsym])));
                    let distance = usize::from(DIST_BASE[dsym]) + dextra as usize;
                    if distance > out.len() {
                        return Err(());
                    }
                    for _ in 0..length {
                        out.push(out[out.len() - distance]);
                        if out.len() >= limit {
                            return Ok(finish(out, InflateEnd::Limit, &bits));
                        }
                    }
                }
            }
            _ => return Err(()),
        }
        if last == 1 {
            return Ok(finish(out, InflateEnd::Done, &bits));
        }
    }
}

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data {
        c = CRC_TABLE[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xffff_ffff
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// `zlib.decompressobj().decompress(raw, max_length=limit)`; `Err` is a `zlib.error`.
pub(super) fn zlib_decompress(raw: &[u8], limit: usize) -> Result<Vec<u8>, ()> {
    if raw.len() < 2 {
        return Ok(Vec::new());
    }
    let (cmf, flg) = (u32::from(raw[0]), u32::from(raw[1]));
    if ((cmf << 8) | flg) % 31 != 0 || cmf & 15 != 8 || (cmf >> 4) + 8 > 15 {
        return Err(());
    }
    if flg & 0x20 != 0 {
        return if raw.len() < 6 {
            Ok(Vec::new())
        } else {
            Err(())
        };
    }
    let body = inflate(&raw[2..], limit)?;
    if body.end == InflateEnd::Done {
        let tail = &raw[2 + body.consumed..];
        if tail.len() >= 4 {
            let want = u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]);
            if want != adler32(&body.out) {
                return Err(());
            }
        }
    }
    Ok(body.out)
}

fn read_header(raw: &[u8], mut pos: usize) -> Result<usize, GzipFailure> {
    if raw.len() - pos < 2 || raw[pos] != 0x1f || raw[pos + 1] != 0x8b {
        return Err(GzipFailure::Suppressed);
    }
    if raw.len() - pos < 10 {
        return Err(GzipFailure::Eof);
    }
    let (method, flag) = (raw[pos + 2], raw[pos + 3]);
    pos += 10;
    if method != 8 {
        return Err(GzipFailure::Suppressed);
    }
    if flag & 4 != 0 {
        if raw.len() - pos < 2 {
            return Err(GzipFailure::Eof);
        }
        let extra = usize::from(raw[pos]) | (usize::from(raw[pos + 1]) << 8);
        pos += 2;
        if raw.len() - pos < extra {
            return Err(GzipFailure::Eof);
        }
        pos += extra;
    }
    for mask in [8u8, 16u8] {
        if flag & mask != 0 {
            while pos < raw.len() {
                let byte = raw[pos];
                pos += 1;
                if byte == 0 {
                    break;
                }
            }
        }
    }
    if flag & 2 != 0 {
        if raw.len() - pos < 2 {
            return Err(GzipFailure::Eof);
        }
        pos += 2;
    }
    Ok(pos)
}

/// `gzip.GzipFile(...).read(limit)` over a complete in-memory buffer.
pub(super) fn gzip_read(raw: &[u8], limit: usize) -> Result<Vec<u8>, GzipFailure> {
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    loop {
        if out.len() >= limit || pos >= raw.len() {
            return Ok(out);
        }
        pos = read_header(raw, pos)?;
        let member =
            inflate(&raw[pos..], limit - out.len()).map_err(|()| GzipFailure::Suppressed)?;
        match member.end {
            InflateEnd::Truncated => return Err(GzipFailure::Eof),
            InflateEnd::Limit => {
                out.extend_from_slice(&member.out);
                return Ok(out);
            }
            InflateEnd::Done => {}
        }
        pos += member.consumed;
        let produced = member.out.len();
        let crc = crc32(&member.out);
        out.extend_from_slice(&member.out);
        if out.len() >= limit {
            return Ok(out);
        }
        if raw.len() - pos < 8 {
            return Err(GzipFailure::Eof);
        }
        let want_crc = u32::from_le_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]);
        let want_len = u32::from_le_bytes([raw[pos + 4], raw[pos + 5], raw[pos + 6], raw[pos + 7]]);
        if want_crc != crc || want_len != (produced as u64 & 0xffff_ffff) as u32 {
            return Err(GzipFailure::Suppressed);
        }
        pos += 8;
        while pos < raw.len() && raw[pos] == 0 {
            pos += 1;
        }
    }
}

#[cfg(test)]
mod huffman_tests {
    use super::{Bits, Huffman, Step};

    fn decode(table: &Huffman, byte: u8) -> Option<u16> {
        let data = [byte, byte];
        match table.decode(&mut Bits {
            data: &data,
            pos: 0,
        }) {
            Step::Ok(symbol) => Some(symbol),
            Step::Truncated | Step::Error => None,
        }
    }

    #[test]
    fn single_code_distance_tree_decodes_zero_bit_and_rejects_one_bit() {
        let table = Huffman::build(&[0, 0, 1], false).expect("zlib accepts one length-1 code");
        assert_eq!(decode(&table, 0x00), Some(2));
        assert_eq!(decode(&table, 0xff), None);
    }
}
