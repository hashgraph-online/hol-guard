use std::io::Write;
use std::time::{Duration, Instant};

use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;

use super::*;

const PLAIN: &[u8] = include_bytes!("../tests/fixtures/content-coding/plain.txt");
const PLAIN_BR: &[u8] = include_bytes!("../tests/fixtures/content-coding/plain.txt.br");
const PLAIN_GZ_BR: &[u8] = include_bytes!("../tests/fixtures/content-coding/plain.txt.gz.br");
const ZEROS_64M_BR: &[u8] = include_bytes!("../tests/fixtures/content-coding/zeros-64m.br");
const LARGE_WINDOW_BR: &[u8] = include_bytes!("../tests/fixtures/content-coding/large-window.br");

fn caps() -> ContentCodingCaps {
    ContentCodingCaps {
        max_input_bytes: 1024 * 1024,
        max_output_bytes: 8 * 1024 * 1024,
        max_ratio: 100,
        max_layers: 2,
    }
}

fn later() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn never() -> bool {
    false
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn zlib(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

/// Parse then decode, the way the managed fetch does it, reporting how many
/// decoders were built whatever the outcome.
fn run(
    values: &[&str],
    raw: &[u8],
    caps: &ContentCodingCaps,
) -> (Result<Vec<u8>, ContentDecodeError>, ContentDecodeCounters) {
    let mut counters = ContentDecodeCounters::default();
    let result = parse_content_codings(values, caps.max_layers)
        .and_then(|codings| decode_content(raw, &codings, caps, later(), &never, &mut counters));
    (result, counters)
}

fn code(result: &Result<Vec<u8>, ContentDecodeError>) -> &'static str {
    result
        .as_ref()
        .err()
        .map(|error| error.code)
        .unwrap_or("decoded")
}

#[test]
fn brotli_returns_the_exact_content() {
    let (result, counters) = run(&["br"], PLAIN_BR, &caps());
    assert_eq!(result.unwrap(), PLAIN);
    assert_eq!(counters.decoder_calls, 1);
    assert_eq!(counters.output_bytes, PLAIN.len() as u64);
}

#[test]
fn stacked_codings_are_undone_last_first() {
    let (result, counters) = run(&["gzip, br"], PLAIN_GZ_BR, &caps());
    assert_eq!(result.unwrap(), PLAIN);
    assert_eq!(counters.layers, 2);
    // The same stack split across two header lines decodes the same way.
    let (result, _) = run(&["gzip", "br"], PLAIN_GZ_BR, &caps());
    assert_eq!(result.unwrap(), PLAIN);
}

#[test]
fn gzip_deflate_and_identity_decode_exactly() {
    assert_eq!(run(&["gzip"], &gzip(PLAIN), &caps()).0.unwrap(), PLAIN);
    assert_eq!(run(&["X-GZIP"], &gzip(PLAIN), &caps()).0.unwrap(), PLAIN);
    assert_eq!(run(&["deflate"], &zlib(PLAIN), &caps()).0.unwrap(), PLAIN);
    let (result, counters) = run(&["identity"], PLAIN, &caps());
    assert_eq!(result.unwrap(), PLAIN);
    assert_eq!(counters.decoder_calls, 0);
    let (result, counters) = run(&[], PLAIN, &caps());
    assert_eq!(result.unwrap(), PLAIN);
    assert_eq!(counters.decoder_calls, 0);
}

#[test]
fn unsupported_codings_are_refused_before_any_decoder_exists() {
    let too_long = "gzip".repeat(80);
    let cases: [&[&str]; 9] = [
        &["zstd"],
        &["compress"],
        &["gzip;q=1"],
        &["gzip,,br"],
        &["gzip, "],
        &["br, zstd"],
        &["gzip", "dcb"],
        &["gzip\u{00a0}"],
        &[too_long.as_str()],
    ];
    for values in cases {
        let (result, counters) = run(values, PLAIN_BR, &caps());
        assert_eq!(code(&result), "content_coding_unsupported", "{values:?}");
        assert_eq!(counters.decoder_calls, 0, "{values:?}");
        assert_eq!(result.unwrap_err().status, ContentDecodeStatus::Rejected);
    }
}

#[test]
fn stacks_deeper_than_the_cap_are_refused_before_decode() {
    let (result, counters) = run(&["gzip, gzip, br"], PLAIN_GZ_BR, &caps());
    assert_eq!(code(&result), "content_coding_too_deep");
    assert_eq!(counters.decoder_calls, 0);
    // A caller cannot raise the ceiling past the crate's own.
    let mut wide = caps();
    wide.max_layers = 64;
    let five = ["gzip"; CONTENT_CODING_MAX_LAYERS + 1];
    let (result, counters) = run(&five, PLAIN, &wide);
    assert_eq!(code(&result), "content_coding_too_deep");
    assert_eq!(counters.decoder_calls, 0);
    // decode_content enforces the cap on its own too.
    let mut counters = ContentDecodeCounters::default();
    let stack = [ContentCoding::Gzip; 3];
    let result = decode_content(PLAIN, &stack, &caps(), later(), &never, &mut counters);
    assert_eq!(code(&result), "content_coding_too_deep");
    assert_eq!(counters.decoder_calls, 0);
}

#[test]
fn raw_bodies_over_the_input_cap_are_refused_before_decode() {
    let mut small = caps();
    small.max_input_bytes = 100;
    let (result, counters) = run(&["br"], PLAIN_BR, &small);
    assert_eq!(code(&result), "content_input_too_large");
    assert_eq!(counters.decoder_calls, 0);
}

#[test]
fn a_brotli_bomb_stops_at_the_output_cap() {
    // With the ratio out of the way the absolute cap is what stops it.
    let mut loose_ratio = caps();
    loose_ratio.max_ratio = 10_000_000;
    let (result, counters) = run(&["br"], ZEROS_64M_BR, &loose_ratio);
    assert_eq!(code(&result), "content_output_too_large");
    assert!(counters.output_bytes == 0);
    let mut roomy = caps();
    roomy.max_output_bytes = 128 * 1024 * 1024;
    let (result, _) = run(&["br"], ZEROS_64M_BR, &roomy);
    assert_eq!(code(&result), "content_ratio_exceeded");
}

#[test]
fn a_gzip_bomb_stops_at_the_ratio() {
    let bomb = gzip(&vec![0u8; 16 * 1024 * 1024]);
    let mut roomy = caps();
    roomy.max_output_bytes = 64 * 1024 * 1024;
    let (result, _) = run(&["gzip"], &bomb, &roomy);
    assert_eq!(code(&result), "content_ratio_exceeded");
}

#[test]
fn nested_layers_are_bounded_against_the_raw_body() {
    // The outer layer expands only a little; the inner one is measured
    // against the raw body the server sent, not against its own input.
    let inner = gzip(&vec![b'a'; 4 * 1024 * 1024]);
    let outer = gzip(&inner);
    let mut roomy = caps();
    roomy.max_output_bytes = 64 * 1024 * 1024;
    let (result, counters) = run(&["gzip, gzip"], &outer, &roomy);
    assert_eq!(code(&result), "content_ratio_exceeded");
    assert_eq!(counters.layers, 1);
}

#[test]
fn malformed_streams_are_refused() {
    let mut trailing_gzip = gzip(PLAIN);
    trailing_gzip.extend_from_slice(b"tail");
    let mut trailing_zlib = zlib(PLAIN);
    trailing_zlib.extend_from_slice(b"tail");
    let short_gzip = gzip(PLAIN);
    let mut trailing_br = PLAIN_BR.to_vec();
    trailing_br.extend_from_slice(b"tail");
    let cases: [(&str, &[u8]); 9] = [
        ("br", &PLAIN_BR[..PLAIN_BR.len() / 2]),
        ("br", &trailing_br),
        ("br", b"not brotli at all"),
        ("br", LARGE_WINDOW_BR),
        ("gzip", &trailing_gzip),
        ("gzip", &short_gzip[..40]),
        ("gzip", b""),
        ("deflate", &trailing_zlib),
        ("deflate", PLAIN),
    ];
    for (coding, raw) in cases {
        let (result, _) = run(&[coding], raw, &caps());
        assert_eq!(code(&result), "content_coding_malformed", "{coding}");
    }
}

#[test]
fn deadline_and_halt_stop_the_decode() {
    let mut counters = ContentDecodeCounters::default();
    let past = Instant::now() - Duration::from_millis(1);
    let result = decode_content(
        PLAIN_BR,
        &[ContentCoding::Brotli],
        &caps(),
        past,
        &never,
        &mut counters,
    );
    let error = result.unwrap_err();
    assert_eq!(error.status, ContentDecodeStatus::Incomplete);
    assert_eq!(error.code, "content_decode_timeout");
    let halt = || true;
    let result = decode_content(
        PLAIN_BR,
        &[ContentCoding::Brotli],
        &caps(),
        later(),
        &halt,
        &mut counters,
    );
    assert_eq!(result.unwrap_err().status, ContentDecodeStatus::Halted);
}
