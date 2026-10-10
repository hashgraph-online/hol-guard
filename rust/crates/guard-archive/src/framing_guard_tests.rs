//! Unit and differential tests for the framing guard.
//!
//! The load-bearing property is *transparency and sync*: for every stream the
//! guard forwards, `tar` yields exactly the members it yields without the
//! guard, and the guard's own idea of each member's header offset equals the
//! library's `raw_header_position`. Anything else would let the guard and the
//! library disagree about where members start.

#[path = "../tests/common/mod.rs"]
mod common;

use std::io::Cursor;
use std::rc::Rc;
use std::time::{Duration, Instant};

use common::*;

use crate::framing_guard::{
    Framer, FramingGuard, GuardReport, Verdict, MAX_SPARSE_EXTENSION_BLOCKS, METADATA_RECORD_CAP,
};

const CAP: u64 = METADATA_RECORD_CAP;

fn feed_all(framer: &mut Framer, bytes: &[u8], chunk: usize) -> Result<(), Verdict> {
    for piece in bytes.chunks(chunk.max(1)) {
        framer.feed(piece)?;
    }
    Ok(())
}

struct Walk {
    /// `raw_header_position` of every member `tar` yielded.
    positions: Vec<u64>,
    verdict: Option<Verdict>,
    ended_in_error: bool,
    /// Every yielded member's position matched the guard's.
    in_sync: bool,
}

fn walk_plain(bytes: &[u8]) -> (Vec<u64>, bool) {
    let mut archive = tar::Archive::new(Cursor::new(bytes));
    let mut positions = Vec::new();
    let Ok(entries) = archive.entries() else {
        return (positions, true);
    };
    for entry in entries {
        match entry {
            Ok(entry) => positions.push(entry.raw_header_position()),
            Err(_) => return (positions, true),
        }
    }
    (positions, false)
}

fn walk_guarded(bytes: &[u8], meta_cap: u64) -> Walk {
    let report = Rc::new(GuardReport::default());
    let halt = || false;
    let guard = FramingGuard::new(
        Cursor::new(bytes),
        meta_cap,
        Instant::now() + Duration::from_secs(60),
        &halt,
        Rc::clone(&report),
    );
    let mut archive = tar::Archive::new(guard);
    let mut walk = Walk {
        positions: Vec::new(),
        verdict: None,
        ended_in_error: false,
        in_sync: true,
    };
    if let Ok(entries) = archive.entries() {
        for entry in entries {
            match entry {
                Ok(entry) => {
                    let position = entry.raw_header_position();
                    walk.in_sync &= report.entry_header_pos() == Some(position);
                    walk.positions.push(position);
                }
                Err(_) => {
                    walk.ended_in_error = true;
                    break;
                }
            }
        }
    } else {
        walk.ended_in_error = true;
    }
    walk.verdict = report.verdict();
    walk
}

#[test]
fn metadata_records_are_bounded_at_the_header_before_any_data() {
    for (label, block) in [
        (
            "long name",
            header(b"././@LongLink", b'L', CAP + 1, b"", Magic::Gnu),
        ),
        (
            "long link",
            header(b"././@LongLink", b'K', CAP + 1, b"", Magic::Gnu),
        ),
        (
            "pax",
            header(b"PaxHeader/x", b'x', CAP + 1, b"", Magic::Ustar),
        ),
        (
            "long name 2^40",
            header(b"x", b'L', 1 << 40, b"", Magic::Gnu),
        ),
    ] {
        let mut framer = Framer::new(CAP);
        assert_eq!(
            framer.feed(&block),
            Err(Verdict::MetadataTooLarge),
            "{label}"
        );
    }
    for (label, block) in [
        (
            "long name",
            header(b"././@LongLink", b'L', CAP, b"", Magic::Gnu),
        ),
        (
            "long link",
            header(b"././@LongLink", b'K', CAP, b"", Magic::Gnu),
        ),
        ("pax", header(b"PaxHeader/x", b'x', CAP, b"", Magic::Ustar)),
    ] {
        let mut framer = Framer::new(CAP);
        assert_eq!(framer.feed(&block), Ok(()), "{label} at the ceiling");
    }
}

#[test]
fn the_caller_member_cap_tightens_the_metadata_ceiling() {
    let block = header(b"././@LongLink", b'L', 4097, b"", Magic::Gnu);
    assert_eq!(
        Framer::new(4096).feed(&block),
        Err(Verdict::MetadataTooLarge)
    );
    assert_eq!(Framer::new(4097).feed(&block), Ok(()));
    // A cap above the ceiling never loosens it.
    let block = header(b"././@LongLink", b'L', CAP + 1, b"", Magic::Gnu);
    assert_eq!(
        Framer::new(u64::MAX).feed(&block),
        Err(Verdict::MetadataTooLarge)
    );
}

#[test]
fn unrecognized_extension_headers_are_ordinary_members() {
    // `tar` only treats L/K/x as metadata when the magic is ustar or GNU; an
    // old-format header with those type flags is yielded as a member, so the
    // guard must not apply the metadata ceiling to it (and must skip its data
    // exactly as `tar` does).
    let mut bytes = member_with(b"x", b'L', &vec![b'a'; 3000], b"", Magic::Old);
    bytes.extend(file("after", b"x"));
    bytes.resize(bytes.len() + 2 * BLOCK, 0);
    let (plain, plain_error) = walk_plain(&bytes);
    let guarded = walk_guarded(&bytes, 1024);
    assert_eq!(guarded.verdict, None);
    assert_eq!(guarded.positions, plain);
    assert_eq!(guarded.ended_in_error, plain_error);
    assert!(guarded.in_sync);
    assert_eq!(plain.len(), 2);
}

#[test]
fn pax_size_override_moves_the_framing_exactly_like_tar() {
    // The override makes `a` claim 1024 bytes while the header says 3: the
    // next header is where the override says, not where the field says.
    let mut bytes = pax_header(&pax_record("size", b"1024"));
    bytes.extend(header(b"a", b'0', 3, b"", Magic::Ustar));
    bytes.extend(padded(&[b'z'; 1024]));
    bytes.extend(file("b", b"hello"));
    bytes.resize(bytes.len() + 2 * BLOCK, 0);
    let (plain, plain_error) = walk_plain(&bytes);
    let guarded = walk_guarded(&bytes, CAP);
    assert_eq!(guarded.positions, plain);
    assert_eq!(guarded.ended_in_error, plain_error);
    assert!(guarded.in_sync);
    assert_eq!(plain.len(), 2, "override must have been honored");
}

#[test]
fn pax_size_override_does_not_leak_onto_extension_headers_or_later_members() {
    let mut bytes = pax_header(&pax_record("size", b"600"));
    bytes.extend(gnu_longname(b"a-long-name"));
    bytes.extend(member_with(b"x", b'0', &[b'q'; 600], b"", Magic::Ustar));
    bytes.extend(file("next", b"n"));
    bytes.resize(bytes.len() + 2 * BLOCK, 0);
    let (plain, _) = walk_plain(&bytes);
    let guarded = walk_guarded(&bytes, CAP);
    assert_eq!(guarded.positions, plain);
    assert!(guarded.in_sync);
    assert_eq!(plain.len(), 2);
}

#[test]
fn invalid_pax_size_values_fall_back_to_the_header_size() {
    for value in [&b"abc"[..], b"-1", b"", b"99999999999999999999999"] {
        let mut bytes = pax_header(&pax_record("size", value));
        bytes.extend(file("a", b"hello"));
        bytes.extend(file("b", b"world"));
        bytes.resize(bytes.len() + 2 * BLOCK, 0);
        let (plain, plain_error) = walk_plain(&bytes);
        let guarded = walk_guarded(&bytes, CAP);
        assert_eq!(guarded.positions, plain, "{value:?}");
        assert_eq!(guarded.ended_in_error, plain_error);
        assert!(guarded.in_sync);
    }
}

#[test]
fn sparse_extension_chain_boundary() {
    let at = MAX_SPARSE_EXTENSION_BLOCKS as usize;
    let mut framer = Framer::new(CAP);
    assert_eq!(framer.feed(&sparse_member("s", at, 0)), Ok(()));
    let mut framer = Framer::new(CAP);
    assert_eq!(
        framer.feed(&sparse_member("s", at + 1, 0)),
        Err(Verdict::SparseChainTooLong)
    );
    // Only the exact flag byte 1 continues a chain, as in `tar`.
    for flag in [2u8, 0x80, 0xff] {
        let mut framer = Framer::new(CAP);
        assert_eq!(
            framer.feed(&sparse_member("s", at + 1, flag)),
            Err(Verdict::SparseChainTooLong)
        );
        let mut framer = Framer::new(CAP);
        assert_eq!(framer.feed(&sparse_member("s", 1, flag)), Ok(()));
    }
}

#[test]
fn sparse_chain_is_refused_before_the_library_reads_the_whole_chain() {
    // Count how far into the stream the library gets before the guard stops it.
    let bytes = archive(&[sparse_member("s", 50_000, 0)]);
    let report = Rc::new(GuardReport::default());
    let halt = || false;
    let guard = FramingGuard::new(
        Cursor::new(bytes.as_slice()),
        CAP,
        Instant::now() + Duration::from_secs(60),
        &halt,
        Rc::clone(&report),
    );
    let mut archive = tar::Archive::new(guard);
    let first = archive.entries().unwrap().next().unwrap();
    assert!(first.is_err());
    assert_eq!(report.verdict(), Some(Verdict::SparseChainTooLong));
}

#[test]
fn chunking_does_not_change_the_verdict_or_positions() {
    let long = vec![b'p'; 3000];
    let mut bytes = Vec::new();
    bytes.extend(pax_header(&pax_record("path", &long)));
    bytes.extend(file("a", b"alpha"));
    bytes.extend(gnu_longname(&long));
    bytes.extend(symlink("s", "a"));
    bytes.extend(pax_header(&pax_record("size", b"700")));
    bytes.extend(member_with(b"c", b'0', &[b'c'; 700], b"", Magic::Ustar));
    bytes.extend(sparse_member("sp", 3, 0));
    bytes.resize(bytes.len() + 2 * BLOCK, 0);
    let mut reference = Framer::new(CAP);
    let reference_verdict = feed_all(&mut reference, &bytes, bytes.len());
    for chunk in [1usize, 2, 7, 100, 511, 512, 513, 1000, 4096] {
        let mut framer = Framer::new(CAP);
        let verdict = feed_all(&mut framer, &bytes, chunk);
        assert_eq!(verdict, reference_verdict, "chunk {chunk}");
        assert_eq!(
            framer.entry_header_pos(),
            reference.entry_header_pos(),
            "chunk {chunk}"
        );
    }
}

#[test]
fn the_guard_polls_halt_and_the_deadline_on_every_read() {
    let bytes = archive(&[file("a", b"x")]);
    let halt = || true;
    let report = Rc::new(GuardReport::default());
    let mut guard = FramingGuard::new(
        Cursor::new(bytes.as_slice()),
        CAP,
        Instant::now() + Duration::from_secs(60),
        &halt,
        Rc::clone(&report),
    );
    let mut buffer = [0u8; 16];
    assert!(std::io::Read::read(&mut guard, &mut buffer).is_err());
    assert_eq!(report.verdict(), Some(Verdict::Halted));

    let never = || false;
    let report = Rc::new(GuardReport::default());
    let mut guard = FramingGuard::new(
        Cursor::new(bytes.as_slice()),
        CAP,
        Instant::now() - Duration::from_secs(1),
        &never,
        Rc::clone(&report),
    );
    assert!(std::io::Read::read(&mut guard, &mut buffer).is_err());
    assert_eq!(report.verdict(), Some(Verdict::Timeout));
}

// ------------------------------------------------------------- differential

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn random_name(rng: &mut Rng, max: u64) -> Vec<u8> {
    let len = 1 + rng.below(max) as usize;
    (0..len).map(|_| b'a' + rng.below(26) as u8).collect()
}

fn random_item(rng: &mut Rng) -> Vec<u8> {
    match rng.below(14) {
        0 | 1 => file(
            &String::from_utf8(random_name(rng, 40)).unwrap(),
            &vec![b'd'; rng.below(1500) as usize],
        ),
        2 => dir(&String::from_utf8(random_name(rng, 20)).unwrap()),
        3 => symlink("l", &String::from_utf8(random_name(rng, 20)).unwrap()),
        4 => gnu_longname(&random_name(rng, 700)),
        5 => gnu_longlink(&random_name(rng, 700)),
        6 => {
            let mut records = pax_record("path", &random_name(rng, 300));
            if rng.below(2) == 0 {
                let size = rng.below(1400).to_string();
                records.extend(pax_record("size", size.as_bytes()));
            }
            if rng.below(4) == 0 {
                records.extend(pax_record("size", b"not-a-number"));
            }
            pax_header(&records)
        }
        7 => member_with(
            b"g",
            b'g',
            &pax_record("comment", b"global"),
            b"",
            Magic::Ustar,
        ),
        8 => sparse_member(
            "sp",
            rng.below(11) as usize,
            [0u8, 1, 2][rng.below(3) as usize],
        ),
        9 => member_with(
            b"old",
            [b'L', b'K', b'x'][rng.below(3) as usize],
            &vec![b'o'; rng.below(900) as usize],
            b"",
            Magic::Old,
        ),
        10 => {
            // A block of noise: usually a checksum failure, sometimes not.
            let mut block = [0u8; BLOCK];
            for byte in &mut block {
                *byte = rng.next() as u8;
            }
            block.to_vec()
        }
        11 => vec![0u8; BLOCK],
        12 => {
            // Header with an octal size field that is garbage or base-256.
            let field: &[u8] = [
                &b"zzzzzzzzzzz\0"[..],
                b"\x80\0\0\0\0\0\0\0\0\0\x02\x00",
                b"77777777777\0",
            ][rng.below(3) as usize];
            let mut out = raw_header(b"w", b'0', field, b"", Magic::Ustar).to_vec();
            out.extend(vec![b'w'; rng.below(1200) as usize]);
            out
        }
        _ => member_with(
            b"p",
            b'0',
            &vec![b'p'; rng.below(600) as usize],
            b"",
            Magic::Gnu,
        ),
    }
}

fn random_archive(rng: &mut Rng) -> Vec<u8> {
    let items = 1 + rng.below(9);
    let mut bytes = Vec::new();
    for _ in 0..items {
        bytes.extend(random_item(rng));
    }
    if rng.below(3) != 0 {
        bytes.resize(bytes.len() + 2 * BLOCK, 0);
    }
    if rng.below(4) == 0 && !bytes.is_empty() {
        let at = rng.below(bytes.len() as u64) as usize;
        bytes[at] ^= 1 << rng.below(8);
    }
    if rng.below(5) == 0 {
        let keep = rng.below(bytes.len() as u64 + 1) as usize;
        bytes.truncate(keep);
    }
    bytes
}

#[test]
fn guard_is_transparent_and_in_sync_with_tar_across_random_archives() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut with_verdict = 0u32;
    let mut with_members = 0u32;
    for round in 0..6000 {
        let bytes = random_archive(&mut rng);
        let (plain, plain_error) = walk_plain(&bytes);
        let guarded = walk_guarded(&bytes, 1024);
        assert!(
            guarded.in_sync,
            "round {round}: guard and tar disagree on a member offset"
        );
        match guarded.verdict {
            None => {
                assert_eq!(guarded.positions, plain, "round {round}");
                assert_eq!(guarded.ended_in_error, plain_error, "round {round}");
            }
            Some(_) => {
                with_verdict += 1;
                // A refusal can only shorten what the library sees.
                assert!(plain.starts_with(&guarded.positions), "round {round}");
                assert!(guarded.ended_in_error, "round {round}");
            }
        }
        with_members += u32::from(!plain.is_empty());
    }
    // The generator must actually reach both regimes, or the test proves nothing.
    assert!(with_verdict > 100, "only {with_verdict} refusals");
    assert!(
        with_members > 3000,
        "only {with_members} archives with members"
    );
}

#[test]
fn ambiguous_pax_record_sets_are_refused_before_tar_sees_them() {
    let dup = |key: &str| pax_header(&[pax_record(key, b"1"), pax_record(key, b"2")].concat());
    for key in ["path", "linkpath", "size"] {
        let mut framer = Framer::new(CAP);
        assert_eq!(framer.feed(&dup(key)), Err(Verdict::AmbiguousPax), "{key}");
    }
    let mut framer = Framer::new(CAP);
    assert_eq!(
        framer.feed(&pax_header(b"zz path=a\n")),
        Err(Verdict::AmbiguousPax)
    );
    // Repeating a key that carries no path or size is not ambiguous.
    let mut framer = Framer::new(CAP);
    let harmless = pax_header(&[pax_record("comment", b"1"), pax_record("comment", b"2")].concat());
    assert_eq!(framer.feed(&harmless), Ok(()));
}

#[test]
fn gnu_long_names_and_pax_paths_for_one_member_are_refused_in_either_order() {
    let pax = |key: &str| pax_header(&pax_record(key, b"../../x"));
    let cases: [(&str, Vec<u8>, Vec<u8>); 4] = [
        ("path", pax("path"), gnu_longname(b"benign")),
        ("linkpath", pax("linkpath"), gnu_longlink(b"benign")),
        ("path", gnu_longname(b"benign"), pax("path")),
        ("linkpath", gnu_longlink(b"benign"), pax("linkpath")),
    ];
    for (key, first, second) in cases {
        let mut framer = Framer::new(CAP);
        let result = framer.feed(&first).and_then(|()| framer.feed(&second));
        assert_eq!(result, Err(Verdict::AmbiguousPax), "{key}");
    }
    // Unrelated pairings are not ambiguous, and the flags reset per member.
    let mut framer = Framer::new(CAP);
    let mixed = [
        pax("path"),
        gnu_longlink(b"benign"),
        file("a", b""),
        gnu_longname(b"benign"),
        pax("linkpath"),
        file("b", b""),
        gnu_longname(b"benign"),
        file("c", b""),
        pax("path"),
        file("d", b""),
    ]
    .concat();
    assert_eq!(framer.feed(&mixed), Ok(()));
}
