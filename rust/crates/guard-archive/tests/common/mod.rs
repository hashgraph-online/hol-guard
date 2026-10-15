//! Shared fixtures for the adversarial archive corpus. Everything is generated
//! programmatically so no binary blobs are committed; blobs are written the way
//! the runtime expects them (single-linked, read-only regular files) into a
//! unique temp directory that is removed on drop.
#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use guard_alloc_probe::Measurement;
use guard_archive::{inspect_path, ArchiveCaps, ArchiveOutcome};
use sha2::{Digest, Sha256};

pub const BLOCK: usize = 512;
pub const KIB: u64 = 1024;
pub const MIB: u64 = 1024 * 1024;

/// Production-shaped caps (mirrors `tests/fixtures/native-archive-inspection`).
pub fn caps() -> ArchiveCaps {
    ArchiveCaps {
        max_archive_bytes: 6 * MIB,
        max_files: 500,
        max_expanded_bytes: 32 * MIB,
        max_member_bytes: 8 * MIB,
        max_package_json_bytes: 256 * KIB,
        max_decompression_ratio: 200.0,
        max_nested_archives: 8,
        max_path_depth: 64,
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A blob on disk plus the digest the caller bound to it.
pub struct Blob {
    pub dir: PathBuf,
    pub path: PathBuf,
    pub sha256: String,
}

impl Blob {
    pub fn inspect(&self, caps: &ArchiveCaps) -> ArchiveOutcome {
        self.inspect_with_halt(caps, &|| false)
    }

    pub fn inspect_with_halt(&self, caps: &ArchiveCaps, halt: &dyn Fn() -> bool) -> ArchiveOutcome {
        inspect_path(
            &self.path,
            &self.sha256,
            caps,
            Instant::now() + Duration::from_secs(120),
            halt,
        )
    }
}

impl Drop for Blob {
    fn drop(&mut self) {
        restore_writable(&self.dir);
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

fn restore_writable(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
            }
        }
    }
}

pub fn unique_dir(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    // Keep the path short: macOS temp roots are long and sandboxes cap sun_path.
    let dir = std::env::temp_dir().join(format!(
        "ga-{}-{}-{label}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create test dir");
    dir
}

pub fn write_blob(bytes: &[u8]) -> Blob {
    write_blob_named(bytes, "blob.tar")
}

pub fn write_blob_named(bytes: &[u8], name: &str) -> Blob {
    use std::os::unix::fs::PermissionsExt;
    let dir = unique_dir("blob");
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write blob");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).expect("chmod blob");
    Blob {
        dir,
        path,
        sha256: sha256_hex(bytes),
    }
}

pub fn inspect(bytes: &[u8]) -> ArchiveOutcome {
    write_blob(bytes).inspect(&caps())
}

pub fn inspect_with(bytes: &[u8], caps: &ArchiveCaps) -> ArchiveOutcome {
    write_blob(bytes).inspect(caps)
}

/// Inspect while the counting allocator measures this thread. The blob is
/// written first so only inspection allocations are attributed.
pub fn inspect_measured(bytes: &[u8], caps: &ArchiveCaps) -> (ArchiveOutcome, Measurement) {
    let blob = write_blob(bytes);
    guard_alloc_probe::measure(|| blob.inspect(caps))
}

#[track_caller]
pub fn assert_outcome(outcome: &ArchiveOutcome, status: &str, code: &str) {
    let actual = format!("{:?}", outcome.status).to_lowercase();
    assert_eq!(
        (actual.as_str(), outcome.code),
        (status, code),
        "unexpected outcome: {outcome:?}"
    );
}

// ---------------------------------------------------------------- tar bytes

pub fn octal_field(value: u64, width: usize) -> Vec<u8> {
    let mut field = format!("{value:0w$o}", w = width - 1).into_bytes();
    field.push(0);
    field
}

pub fn finish_checksum(block: &mut [u8; BLOCK]) {
    block[148..156].copy_from_slice(b"        ");
    let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Magic {
    /// POSIX ustar (`ustar\000`).
    Ustar,
    /// GNU (`ustar  \0`).
    Gnu,
    /// Old V7: no magic at all.
    Old,
}

/// A fully custom header block. `size_field` is written verbatim so malformed
/// and base-256 encodings can be expressed.
pub fn raw_header(
    name: &[u8],
    typeflag: u8,
    size_field: &[u8],
    linkname: &[u8],
    magic: Magic,
) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    let take = name.len().min(100);
    block[..take].copy_from_slice(&name[..take]);
    block[100..108].copy_from_slice(b"0000644\0");
    block[108..116].copy_from_slice(b"0000000\0");
    block[116..124].copy_from_slice(b"0000000\0");
    let size_take = size_field.len().min(12);
    block[124..124 + size_take].copy_from_slice(&size_field[..size_take]);
    block[136..148].copy_from_slice(b"00000000000\0");
    block[156] = typeflag;
    let link_take = linkname.len().min(100);
    block[157..157 + link_take].copy_from_slice(&linkname[..link_take]);
    match magic {
        Magic::Ustar => {
            block[257..263].copy_from_slice(b"ustar\0");
            block[263..265].copy_from_slice(b"00");
        }
        Magic::Gnu => block[257..265].copy_from_slice(b"ustar  \0"),
        Magic::Old => {}
    }
    finish_checksum(&mut block);
    block
}

pub fn header(name: &[u8], typeflag: u8, size: u64, linkname: &[u8], magic: Magic) -> [u8; BLOCK] {
    raw_header(name, typeflag, &octal_field(size, 12), linkname, magic)
}

pub fn padded(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    out.resize(data.len().div_ceil(BLOCK) * BLOCK, 0);
    out
}

/// Header followed by 512-padded data; `size` is the real data length.
pub fn member_with(
    name: &[u8],
    typeflag: u8,
    data: &[u8],
    linkname: &[u8],
    magic: Magic,
) -> Vec<u8> {
    let mut out = header(name, typeflag, data.len() as u64, linkname, magic).to_vec();
    out.extend(padded(data));
    out
}

pub fn file(name: &str, data: &[u8]) -> Vec<u8> {
    member_with(name.as_bytes(), b'0', data, b"", Magic::Ustar)
}

pub fn dir(name: &str) -> Vec<u8> {
    member_with(name.as_bytes(), b'5', b"", b"", Magic::Ustar)
}

pub fn symlink(name: &str, target: &str) -> Vec<u8> {
    member_with(name.as_bytes(), b'2', b"", target.as_bytes(), Magic::Ustar)
}

pub fn hardlink(name: &str, target: &str) -> Vec<u8> {
    member_with(name.as_bytes(), b'1', b"", target.as_bytes(), Magic::Ustar)
}

/// `NN key=value\n` where NN counts itself, as pax requires.
pub fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    let body_len = key.len() + value.len() + 3; // ' ', '=', '\n'
    let mut digits = 1;
    loop {
        let total = body_len + digits;
        if total.to_string().len() == digits {
            let mut out = format!("{total} {key}=").into_bytes();
            out.extend_from_slice(value);
            out.push(b'\n');
            return out;
        }
        digits += 1;
    }
}

pub fn pax_header(records: &[u8]) -> Vec<u8> {
    member_with(b"PaxHeader/x", b'x', records, b"", Magic::Ustar)
}

pub fn gnu_longname(name: &[u8]) -> Vec<u8> {
    let mut data = name.to_vec();
    data.push(0);
    member_with(b"././@LongLink", b'L', &data, b"", Magic::Gnu)
}

pub fn gnu_longlink(target: &[u8]) -> Vec<u8> {
    let mut data = target.to_vec();
    data.push(0);
    member_with(b"././@LongLink", b'K', &data, b"", Magic::Gnu)
}

/// Archive of the given pre-built members plus the two-block terminator.
pub fn archive(members: &[Vec<u8>]) -> Vec<u8> {
    let mut out = members.concat();
    out.resize(out.len() + 2 * BLOCK, 0);
    out
}

pub fn gz(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).expect("gzip write");
    encoder.finish().expect("gzip finish")
}

/// Gzip a long run of one byte without materializing it.
pub fn gz_repeat(prefix: &[u8], byte: u8, count: u64) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(prefix).expect("gzip write");
    let chunk = vec![byte; 64 * 1024];
    let mut remaining = count;
    while remaining > 0 {
        let step = remaining.min(chunk.len() as u64) as usize;
        encoder.write_all(&chunk[..step]).expect("gzip write");
        remaining -= step as u64;
    }
    encoder.finish().expect("gzip finish")
}

pub fn package_json_member(json: &[u8]) -> Vec<u8> {
    file("package/package.json", json)
}

/// The contract ceilings from `guard-contracts` (what production can be asked
/// to run with), so bounds are measured at the largest sizes that are legal.
pub fn big_caps() -> ArchiveCaps {
    ArchiveCaps {
        max_archive_bytes: 64 * MIB,
        max_files: 10_000,
        max_expanded_bytes: 256 * MIB,
        max_member_bytes: 64 * MIB,
        max_package_json_bytes: 8 * MIB,
        max_decompression_ratio: 10_000.0,
        max_nested_archives: 64,
        max_path_depth: 256,
    }
}

/// Gzip with an optional header field inserted (flag bit, then the field).
fn gz_with_header_field(bytes: &[u8], flag: u8, field: &[u8]) -> Vec<u8> {
    let plain = gz(bytes);
    let mut out = plain[..10].to_vec();
    out[3] |= flag;
    out.extend_from_slice(field);
    out.extend_from_slice(&plain[10..]);
    out
}

/// Gzip whose FNAME field is `len` bytes long.
pub fn gz_with_fname(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut field = vec![b'n'; len];
    field.push(0);
    gz_with_header_field(bytes, 0x08, &field)
}

/// Gzip whose FCOMMENT field is `len` bytes long.
pub fn gz_with_comment(bytes: &[u8], len: usize) -> Vec<u8> {
    let mut field = vec![b'c'; len];
    field.push(0);
    gz_with_header_field(bytes, 0x10, &field)
}

/// Gzip whose FEXTRA field declares `len` bytes (at most 65535).
pub fn gz_with_extra(bytes: &[u8], len: u16) -> Vec<u8> {
    let mut field = len.to_le_bytes().to_vec();
    field.extend(vec![b'e'; usize::from(len)]);
    gz_with_header_field(bytes, 0x04, &field)
}

/// A GNU sparse (`S`) header named `name` followed by `extension_blocks`
/// extension blocks, each declaring 21 empty sparse slots. `last_flag` is the
/// "another block follows" byte of the final extension block.
pub fn sparse_member(name: &str, extension_blocks: usize, last_flag: u8) -> Vec<u8> {
    let mut head = header(name.as_bytes(), b'S', 0, b"", Magic::Gnu);
    head[482] = u8::from(extension_blocks > 0);
    // Declared real size equals where the last slot ends, so `tar` accepts the
    // chain and the verdict comes from member policy rather than a size error.
    head[483..495].copy_from_slice(&octal_field((extension_blocks * 21) as u64, 12));
    finish_checksum(&mut head);
    let mut out = head.to_vec();
    for index in 0..extension_blocks {
        let mut block = [0u8; BLOCK];
        for slot in 0..21 {
            let at = slot * 24;
            block[at..at + 12].copy_from_slice(&octal_field((index * 21 + slot + 1) as u64, 12));
            block[at + 12..at + 24].copy_from_slice(&octal_field(0, 12));
        }
        block[504] = if index + 1 < extension_blocks {
            1
        } else {
            last_flag
        };
        out.extend_from_slice(&block);
    }
    out
}

// ----------------------------------------------------------- corpus tables

pub const CLEAN: (&str, &str) = ("clean", "external_archive_inspection_clean");
pub const SLIP: (&str, &str) = ("blocked", "tarball_zip_slip");
pub const CONFLICT: (&str, &str) = ("blocked", "external_archive_path_conflict");
pub const UNSUPPORTED: (&str, &str) = ("blocked", "external_archive_unsupported_member");
pub const INCOMPLETE: (&str, &str) = ("incomplete", "external_archive_inspection_incomplete");
pub const MEMBER_LIMIT: (&str, &str) = ("blocked", "external_archive_member_size_limit");
pub const FORMAT: (&str, &str) = ("blocked", "external_archive_unsupported_format");
pub fn run(rows: Vec<(&str, Vec<u8>, (&str, &str))>) {
    let mut failures = Vec::new();
    for (label, bytes, (status, code)) in rows {
        let outcome = inspect(&bytes);
        let actual = format!("{:?}", outcome.status).to_lowercase();
        if (actual.as_str(), outcome.code) != (status, code) {
            failures.push(format!(
                "{label}: expected ({status}, {code}) got ({actual}, {})",
                outcome.code
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "corpus mismatches:\n{}",
        failures.join("\n")
    );
}
