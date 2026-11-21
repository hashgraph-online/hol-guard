//! Measured memory for hostile content codings. A 106-byte Brotli stream and
//! a gzip stream both claim far more output than the cap; the peak live heap
//! must track the cap, not the claim.

use std::time::{Duration, Instant};

use guard_alloc_probe::CountingAllocator;
use guard_archive::content_coding::{
    decode_content, parse_content_codings, ContentCodingCaps, ContentDecodeCounters,
};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const MIB: u64 = 1024 * 1024;
const ZEROS_64M_BR: &[u8] = include_bytes!("fixtures/content-coding/zeros-64m.br");

fn decode_measured(values: &[&str], raw: &[u8], caps: &ContentCodingCaps) -> (&'static str, u64) {
    let codings = parse_content_codings(values, caps.max_layers).unwrap();
    let never = || false;
    let deadline = Instant::now() + Duration::from_secs(30);
    let (result, measured) = guard_alloc_probe::measure(|| {
        let mut counters = ContentDecodeCounters::default();
        decode_content(raw, &codings, caps, deadline, &never, &mut counters)
    });
    let code = result.err().map(|error| error.code).unwrap_or("decoded");
    (code, measured.peak_live_bytes)
}

#[test]
fn a_brotli_bomb_peaks_near_the_output_cap_not_its_claim() {
    let caps = ContentCodingCaps {
        max_input_bytes: MIB,
        max_output_bytes: 4 * MIB,
        max_ratio: 10_000_000,
        max_layers: 2,
    };
    let (code, peak) = decode_measured(&["br"], ZEROS_64M_BR, &caps);
    assert_eq!(code, "content_output_too_large");
    // Output vector (at most twice the cap while growing), the strict
    // 16 MiB-window ring buffer ceiling and decoder tables.
    assert!(peak <= 2 * 4 * MIB + 16 * MIB + 2 * MIB, "peak {peak}");
}

#[test]
fn a_gzip_bomb_peaks_near_the_ratio_limit() {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut encoder, &vec![0u8; 32 * MIB as usize]).unwrap();
    let bomb = encoder.finish().unwrap();
    let caps = ContentCodingCaps {
        max_input_bytes: MIB,
        max_output_bytes: 64 * MIB,
        max_ratio: 50,
        max_layers: 2,
    };
    let (code, peak) = decode_measured(&["gzip"], &bomb, &caps);
    assert_eq!(code, "content_ratio_exceeded");
    let ratio_limit = (bomb.len() as u64 * 50).max(64 * 1024);
    assert!(peak <= 2 * ratio_limit + 2 * MIB, "peak {peak}");
}
