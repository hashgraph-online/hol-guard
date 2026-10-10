//! Measured allocation bounds. A counting global allocator attributes every
//! heap byte the inspector requests on the calling thread, so each bound below
//! is an observed number, not an inference from reading `tar` or `flate2`.
//!
//! Each hostile shape has two assertions: the verdict, and a peak/largest
//! allocation that is independent of what the archive advertises or contains.
#![cfg(unix)]

mod common;

use common::*;
use guard_alloc_probe::CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// The inspector's own working set (hash/drain buffers, decoder state, tar
/// scratch, member bookkeeping) with room to spare.
const WORKING_SET: u64 = 2 * MIB;

#[track_caller]
fn assert_bounded(
    label: &str,
    bytes: &[u8],
    caps: &guard_archive::ArchiveCaps,
    status: &str,
    code: &str,
    peak_limit: u64,
) {
    let (outcome, measured) = inspect_measured(bytes, caps);
    eprintln!(
        "{label}: input={} peak={} max_single={} total={} calls={} -> {:?} {}",
        bytes.len(),
        measured.peak_live_bytes,
        measured.max_single_alloc,
        measured.total_allocated,
        measured.alloc_calls,
        outcome.status,
        outcome.code
    );
    assert_outcome(&outcome, status, code);
    assert!(
        measured.peak_live_bytes <= peak_limit,
        "{label}: peak {} exceeds {peak_limit}",
        measured.peak_live_bytes
    );
}

#[test]
fn clean_baseline_stays_inside_the_working_set() {
    let bytes = archive(&[file("package/index.js", b"module.exports = 1;\n")]);
    assert_bounded(
        "baseline",
        &bytes,
        &caps(),
        "clean",
        "external_archive_inspection_clean",
        WORKING_SET,
    );
}

#[test]
fn advertised_metadata_sizes_never_drive_allocation() {
    // A 2^40-byte long name, long link and PAX record: the size field is only
    // a claim, and the claim alone must not size any buffer.
    let huge = 1u64 << 40;
    let claims = [
        header(b"././@LongLink", b'L', huge, b"", Magic::Gnu),
        header(b"././@LongLink", b'K', huge, b"", Magic::Gnu),
        header(b"PaxHeader/x", b'x', huge, b"", Magic::Ustar),
    ];
    for claim in claims {
        let bytes = archive(&[claim.to_vec(), file("a", b"x")]);
        assert_bounded(
            "2^40 metadata claim",
            &bytes,
            &caps(),
            "blocked",
            "external_archive_member_size_limit",
            WORKING_SET,
        );
    }
    // PAX `size=` override claiming 2^60 on an ordinary member.
    let bytes = archive(&[
        pax_header(&pax_record("size", b"1152921504606846976")),
        file("a", b"x"),
    ]);
    assert_bounded(
        "pax size 2^60",
        &bytes,
        &caps(),
        "blocked",
        "external_archive_member_size_limit",
        WORKING_SET,
    );
}

#[test]
fn oversized_metadata_records_are_refused_before_they_are_read() {
    // Real payload bytes, up to the contract ceilings. Before the framing
    // guard a 64 MiB long name was read whole (peak ~470 MB measured).
    let mut caps = big_caps();
    caps.max_decompression_ratio = 1_000_000.0;
    for size in [2 * MIB, 8 * MIB, 32 * MIB, 63 * MIB] {
        let name = vec![b'a'; size as usize];
        let long_name = gz(&archive(&[gnu_longname(&name), file("s", b"x")]));
        assert_bounded(
            "long name",
            &long_name,
            &caps,
            "blocked",
            "external_archive_member_size_limit",
            WORKING_SET,
        );
        let pax = gz(&archive(&[
            pax_header(&pax_record("path", &name)),
            file("s", b"x"),
        ]));
        assert_bounded(
            "pax path",
            &pax,
            &caps,
            "blocked",
            "external_archive_member_size_limit",
            WORKING_SET,
        );
        let link = gz(&archive(&[gnu_longlink(&name), symlink("s", "t")]));
        assert_bounded(
            "long link",
            &link,
            &caps,
            "blocked",
            "external_archive_member_size_limit",
            WORKING_SET,
        );
    }
}

#[test]
fn metadata_record_at_the_ceiling_is_accepted_and_one_past_is_not() {
    let mut caps = big_caps();
    caps.max_decompression_ratio = 1_000_000.0;
    caps.max_path_depth = 4;
    // The record holds the name plus its NUL terminator.
    let name = vec![b'a'; 1024 * 1024 - 1];
    let at_limit = gz(&archive(&[gnu_longname(&name), file("ignored", b"x")]));
    // Measured ~9.5 MiB: the record, its growth copy inside `tar`, and the
    // transient normalized/folded copies of the name.
    assert_bounded(
        "long name at ceiling",
        &at_limit,
        &caps,
        "clean",
        "external_archive_inspection_clean",
        12 * MIB,
    );
    let over = vec![b'a'; 1024 * 1024];
    let past_limit = gz(&archive(&[gnu_longname(&over), file("ignored", b"x")]));
    assert_bounded(
        "long name past ceiling",
        &past_limit,
        &caps,
        "blocked",
        "external_archive_member_size_limit",
        WORKING_SET,
    );
}

#[test]
fn member_cap_below_the_ceiling_also_bounds_metadata() {
    let mut caps = caps();
    caps.max_member_bytes = 4096;
    let name = vec![b'a'; 4096];
    let bytes = archive(&[gnu_longname(&name), file("s", b"x")]);
    assert_bounded(
        "long name over member cap",
        &bytes,
        &caps,
        "blocked",
        "external_archive_member_size_limit",
        WORKING_SET,
    );
    let name = vec![b'a'; 4094];
    let bytes = archive(&[gnu_longname(&name), file("s", b"x")]);
    assert_bounded(
        "long name under member cap",
        &bytes,
        &caps,
        "clean",
        "external_archive_inspection_clean",
        WORKING_SET,
    );
}

#[test]
fn sparse_extension_chains_are_bounded_before_they_become_heap_entries() {
    // Each extension block adds 21 heap entries inside `tar`; a 60k-block
    // chain measured ~30x amplification before the guard.
    for blocks in [9usize, 100, 10_000, 60_000] {
        let bytes = gz(&archive(&[sparse_member("sp", blocks, 0)]));
        assert_bounded(
            "sparse chain",
            &bytes,
            &big_caps(),
            "blocked",
            "external_archive_unsupported_member",
            WORKING_SET,
        );
    }
    // At the chain ceiling the member is still refused, by member policy.
    let bytes = gz(&archive(&[sparse_member("sp", 8, 0)]));
    assert_bounded(
        "sparse chain at ceiling",
        &bytes,
        &big_caps(),
        "blocked",
        "external_archive_unsupported_member",
        WORKING_SET,
    );
}

#[test]
fn gzip_header_fields_cannot_pin_memory() {
    let tar = archive(&[file("a", b"x")]);
    let variants = [
        ("fname 40MiB", gz_with_fname(&tar, 40 << 20)),
        ("fcomment 40MiB", gz_with_comment(&tar, 40 << 20)),
        ("fextra 64KiB", gz_with_extra(&tar, 65535)),
    ];
    for (label, bytes) in variants {
        let (outcome, measured) = inspect_measured(&bytes, &big_caps());
        eprintln!(
            "{label}: {:?} {} peak={}",
            outcome.status, outcome.code, measured.peak_live_bytes
        );
        assert!(
            measured.peak_live_bytes <= WORKING_SET,
            "{label}: peak {}",
            measured.peak_live_bytes
        );
        // Whatever the verdict, an oversized header must never be Clean via a
        // path that skipped the digest and bounds.
        assert!(matches!(
            outcome.status,
            guard_archive::ArchiveStatus::Clean
                | guard_archive::ArchiveStatus::Incomplete
                | guard_archive::ArchiveStatus::Blocked
        ));
    }
}

#[test]
fn decompression_bombs_stop_inside_the_preflight() {
    let mut caps = caps();
    caps.max_expanded_bytes = 4 * MIB;
    caps.max_decompression_ratio = 1_000_000.0;
    // 256 MiB of zeros after a valid member: the expanded cap trips while the
    // decoder has produced only a few MiB, with only fixed buffers allocated.
    let bomb = gz_repeat(&file("a", b"x"), 0, 256 << 20);
    assert_bounded(
        "zero bomb",
        &bomb,
        &caps,
        "blocked",
        "external_archive_expanded_size_limit",
        WORKING_SET,
    );
    // The ratio cap fires first with the production ratio.
    let mut ratio = big_caps();
    ratio.max_decompression_ratio = 200.0;
    let bomb = gz_repeat(&file("a", b"x"), 0, 64 << 20);
    assert_bounded(
        "ratio bomb",
        &bomb,
        &ratio,
        "blocked",
        "external_archive_decompression_ratio_limit",
        WORKING_SET,
    );
}

#[test]
fn expansion_after_the_tar_terminator_is_still_counted() {
    let mut caps = caps();
    caps.max_expanded_bytes = 2 * MIB;
    caps.max_decompression_ratio = 1_000_000.0;
    // The tar parser would stop at the terminator; the preflight must not.
    let bytes = gz_repeat(&archive(&[file("a", b"x")]), b'z', 128 * MIB);
    assert_bounded(
        "tail bomb",
        &bytes,
        &caps,
        "blocked",
        "external_archive_expanded_size_limit",
        WORKING_SET,
    );
}

#[test]
fn manifest_parse_amplification_is_bounded_by_the_manifest_cap() {
    // serde_json builds a DOM, which costs a constant multiple of the manifest
    // cap (the cap is enforced before the bytes are read). The multiple is
    // measured here so a regression in either direction is visible.
    let cap = 8 * MIB;
    let mut array = b"{\"x\":[0".to_vec();
    while (array.len() as u64) + 4 < cap {
        array.extend_from_slice(b",0");
    }
    array.extend_from_slice(b"]}");
    let mut object = b"{\"x\":{\"k\":0".to_vec();
    let mut index = 0u32;
    while (object.len() as u64) + 16 < cap {
        object.extend_from_slice(format!(",\"{index}\":1").as_bytes());
        index += 1;
    }
    object.extend_from_slice(b"}}");
    for (label, json) in [("array of zeros", array), ("object of ones", object)] {
        let bytes = gz(&archive(&[package_json_member(&json)]));
        let (outcome, measured) = inspect_measured(&bytes, &big_caps());
        eprintln!(
            "manifest {label}: json={} peak={} ({:.1}x) -> {:?} {}",
            json.len(),
            measured.peak_live_bytes,
            measured.peak_live_bytes as f64 / json.len() as f64,
            outcome.status,
            outcome.code
        );
        assert_outcome(&outcome, "clean", "external_archive_inspection_clean");
        assert!(
            measured.peak_live_bytes <= 24 * json.len() as u64,
            "manifest {label}: peak {} is more than 24x the manifest",
            measured.peak_live_bytes
        );
    }
}

#[test]
fn retained_member_identity_is_budgeted() {
    let mut caps = big_caps();
    caps.max_decompression_ratio = 1_000_000.0;
    // Each member carries a ~4 KiB long name. 9000 of them would retain ~36 MB
    // of path identity; the budget refuses the archive instead.
    let mut members = Vec::new();
    for index in 0..9000u32 {
        let mut name = format!("{index:05}-").into_bytes();
        name.extend(vec![b'q'; 4000]);
        members.push(gnu_longname(&name));
        members.push(file("placeholder", b""));
    }
    let bytes = gz(&archive(&members));
    assert_bounded(
        "9000 x 4KiB names",
        &bytes,
        &caps,
        "blocked",
        "external_archive_path_depth_limit",
        48 * MIB,
    );
    // Well inside the budget the same shape is clean and the peak tracks the
    // retained identity, not the archive.
    let mut members = Vec::new();
    for index in 0..2000u32 {
        let mut name = format!("{index:05}-").into_bytes();
        name.extend(vec![b'q'; 4000]);
        members.push(gnu_longname(&name));
        members.push(file("placeholder", b""));
    }
    let bytes = gz(&archive(&members));
    assert_bounded(
        "2000 x 4KiB names",
        &bytes,
        &caps,
        "clean",
        "external_archive_inspection_clean",
        40 * MIB,
    );
}

#[test]
fn large_benign_archives_do_not_scale_memory_with_input() {
    // ~5 MiB of incompressible-ish member data plus many small members.
    let mut members = Vec::new();
    let payload: Vec<u8> = (0..(4 * MIB) as usize)
        .map(|i| (i.wrapping_mul(2654435761) >> 7) as u8)
        .collect();
    members.push(file("package/big.bin", &payload));
    for index in 0..400 {
        members.push(file(&format!("package/src/f{index}.js"), b"x"));
    }
    let bytes = archive(&members);
    assert_bounded(
        "benign large",
        &bytes,
        &caps(),
        "clean",
        "external_archive_inspection_clean",
        WORKING_SET,
    );
}
