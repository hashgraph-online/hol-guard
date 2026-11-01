//! Bounded HTTP content-coding decode for managed fetches.
//!
//! The managed fetch client never lets its HTTP stack decompress a response.
//! It hands the raw body and the `Content-Encoding` values here, and this
//! module refuses anything it does not fully understand before a decoder is
//! constructed: unknown codings, coding parameters, empty list members and
//! stacks deeper than the caller allows. Only then are layers decoded, last
//! applied first, with every layer's output bounded by an absolute byte cap,
//! a ratio against the raw body, the caller's deadline and its halt
//! predicate. Brotli is decoded in strict RFC 7932 mode, so a stream that
//! asks for a large window is malformed rather than a 1 GiB allocation.
//!
//! Callers run this inside a contained worker; the bounds here are the
//! in-process half of that containment, not a substitute for it.

use std::io::Read;
use std::time::Instant;

use brotli_decompressor::{BrotliDecompressStream, BrotliResult, BrotliState, StandardAlloc};
use flate2::bufread::{MultiGzDecoder, ZlibDecoder};

/// The deepest coding stack any caller may request.
pub const CONTENT_CODING_MAX_LAYERS: usize = 4;
/// Longest `Content-Encoding` value accepted before parsing.
const MAX_HEADER_VALUE_BYTES: usize = 256;
/// Decode step size; also the granularity of the deadline and halt checks.
const CHUNK_BYTES: usize = 64 * 1024;
/// Outputs at or below this size never trip the ratio check, so short bodies
/// that compress well are not refused for being small.
const RATIO_FLOOR_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentCoding {
    Gzip,
    Deflate,
    Brotli,
}

impl ContentCoding {
    pub fn token(self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Brotli => "br",
        }
    }
}

/// Caller-supplied bounds. Every one is enforced; none has a default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentCodingCaps {
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    /// Largest decoded size of any layer as a multiple of the raw body.
    pub max_ratio: u64,
    pub max_layers: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentDecodeStatus {
    /// The input was refused; nothing about it is trusted.
    Rejected,
    /// The decode ran out of time.
    Incomplete,
    /// The caller's halt predicate stopped the decode.
    Halted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDecodeError {
    pub status: ContentDecodeStatus,
    pub code: &'static str,
    pub message: &'static str,
}

impl ContentDecodeError {
    fn rejected(code: &'static str, message: &'static str) -> Self {
        Self {
            status: ContentDecodeStatus::Rejected,
            code,
            message,
        }
    }
}

/// What a decode did, filled in whether it succeeds or not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentDecodeCounters {
    /// Decoders constructed. Zero proves a refusal happened before decode.
    pub decoder_calls: u64,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub layers: u64,
}

fn unsupported() -> ContentDecodeError {
    ContentDecodeError::rejected(
        "content_coding_unsupported",
        "The response uses a content coding Guard does not decode.",
    )
}

/// Parse every `Content-Encoding` header value, in order of appearance, into
/// the coding stack. `identity` members are dropped; anything else that is
/// not exactly `gzip`, `x-gzip`, `deflate` or `br` refuses the response.
pub fn parse_content_codings(
    values: &[&str],
    max_layers: usize,
) -> Result<Vec<ContentCoding>, ContentDecodeError> {
    let mut codings = Vec::new();
    for value in values {
        if value.len() > MAX_HEADER_VALUE_BYTES {
            return Err(unsupported());
        }
        for member in value.split(',') {
            let token = member.trim_matches([' ', '\t']);
            let coding = if token.eq_ignore_ascii_case("identity") {
                continue;
            } else if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
                ContentCoding::Gzip
            } else if token.eq_ignore_ascii_case("deflate") {
                ContentCoding::Deflate
            } else if token.eq_ignore_ascii_case("br") {
                ContentCoding::Brotli
            } else {
                return Err(unsupported());
            };
            if codings.len() == max_layers.min(CONTENT_CODING_MAX_LAYERS) {
                return Err(ContentDecodeError::rejected(
                    "content_coding_too_deep",
                    "The response stacks more content codings than Guard allows.",
                ));
            }
            codings.push(coding);
        }
    }
    Ok(codings)
}

/// Decode `raw` through `codings` (in header order; the last is undone
/// first). The returned body is still untrusted content.
pub fn decode_content(
    raw: &[u8],
    codings: &[ContentCoding],
    caps: &ContentCodingCaps,
    deadline: Instant,
    halt: &dyn Fn() -> bool,
    counters: &mut ContentDecodeCounters,
) -> Result<Vec<u8>, ContentDecodeError> {
    counters.input_bytes = raw.len() as u64;
    if raw.len() as u64 > caps.max_input_bytes {
        return Err(ContentDecodeError::rejected(
            "content_input_too_large",
            "The response body exceeds Guard's raw size limit.",
        ));
    }
    if codings.len() > caps.max_layers.min(CONTENT_CODING_MAX_LAYERS) {
        return Err(ContentDecodeError::rejected(
            "content_coding_too_deep",
            "The response stacks more content codings than Guard allows.",
        ));
    }
    let ratio_limit = (raw.len() as u64)
        .saturating_mul(caps.max_ratio)
        .max(RATIO_FLOOR_BYTES);
    let mut sink = BoundedSink {
        max_output: caps.max_output_bytes,
        ratio_limit,
        deadline,
        halt,
        out: Vec::new(),
    };
    let mut current = raw.to_vec();
    for coding in codings.iter().rev() {
        counters.decoder_calls += 1;
        sink.out = Vec::new();
        match coding {
            ContentCoding::Gzip => drain_flate(MultiGzDecoder::new(current.as_slice()), &mut sink)?,
            ContentCoding::Deflate => drain_flate(ZlibDecoder::new(current.as_slice()), &mut sink)?,
            ContentCoding::Brotli => drain_brotli(&current, &mut sink)?,
        }
        counters.layers += 1;
        current = std::mem::take(&mut sink.out);
        counters.output_bytes = current.len() as u64;
    }
    Ok(current)
}

struct BoundedSink<'a> {
    max_output: u64,
    ratio_limit: u64,
    deadline: Instant,
    halt: &'a dyn Fn() -> bool,
    out: Vec<u8>,
}

impl BoundedSink<'_> {
    fn check_live(&self) -> Result<(), ContentDecodeError> {
        if (self.halt)() {
            return Err(ContentDecodeError {
                status: ContentDecodeStatus::Halted,
                code: "content_decode_halted",
                message: "Content decoding was halted.",
            });
        }
        if Instant::now() >= self.deadline {
            return Err(ContentDecodeError {
                status: ContentDecodeStatus::Incomplete,
                code: "content_decode_timeout",
                message: "Content decoding exceeded Guard's time limit.",
            });
        }
        Ok(())
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), ContentDecodeError> {
        let next = self.out.len() as u64 + bytes.len() as u64;
        if next > self.max_output {
            return Err(ContentDecodeError::rejected(
                "content_output_too_large",
                "The decoded response exceeds Guard's size limit.",
            ));
        }
        if next > self.ratio_limit {
            return Err(ContentDecodeError::rejected(
                "content_ratio_exceeded",
                "The response expands more than Guard allows for its size.",
            ));
        }
        self.out.extend_from_slice(bytes);
        Ok(())
    }
}

fn malformed() -> ContentDecodeError {
    ContentDecodeError::rejected(
        "content_coding_malformed",
        "The response body is not valid for its declared content coding.",
    )
}

trait IntoRemaining {
    fn remaining(self) -> usize;
}

impl IntoRemaining for MultiGzDecoder<&[u8]> {
    fn remaining(self) -> usize {
        self.into_inner().len()
    }
}

impl IntoRemaining for ZlibDecoder<&[u8]> {
    fn remaining(self) -> usize {
        self.into_inner().len()
    }
}

fn drain_flate<D: Read + IntoRemaining>(
    mut decoder: D,
    sink: &mut BoundedSink<'_>,
) -> Result<(), ContentDecodeError> {
    let mut chunk = vec![0u8; CHUNK_BYTES];
    loop {
        sink.check_live()?;
        let read = decoder.read(&mut chunk).map_err(|_| malformed())?;
        if read == 0 {
            break;
        }
        sink.push(&chunk[..read])?;
    }
    if decoder.remaining() != 0 {
        return Err(malformed());
    }
    Ok(())
}

fn drain_brotli(input: &[u8], sink: &mut BoundedSink<'_>) -> Result<(), ContentDecodeError> {
    // `new_strict` keeps the RFC 7932 16 MiB window ceiling; the reader API
    // would accept large-window streams that HTTP `br` never carries.
    let mut state = BrotliState::new_strict(
        StandardAlloc::default(),
        StandardAlloc::default(),
        StandardAlloc::default(),
    );
    let mut chunk = vec![0u8; CHUNK_BYTES];
    let mut available_in = input.len();
    let mut input_offset = 0usize;
    let mut total_out = 0usize;
    loop {
        sink.check_live()?;
        let mut available_out = chunk.len();
        let mut output_offset = 0usize;
        let result = BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            input,
            &mut available_out,
            &mut output_offset,
            &mut chunk,
            &mut total_out,
            &mut state,
        );
        sink.push(&chunk[..output_offset])?;
        match result {
            BrotliResult::NeedsMoreOutput => continue,
            BrotliResult::ResultSuccess if available_in == 0 => return Ok(()),
            BrotliResult::ResultSuccess
            | BrotliResult::NeedsMoreInput
            | BrotliResult::ResultFailure => return Err(malformed()),
        }
    }
}

#[cfg(test)]
#[path = "content_coding_tests.rs"]
mod tests;
