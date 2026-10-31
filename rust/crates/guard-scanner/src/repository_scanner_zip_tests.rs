use std::io::Write;

use super::super::{ByteBudget, MAX_MEMBER_BYTES};
use super::{is_zip, scan_members};
use crate::repository_scanner::scan_blob;

/// Assembled rather than written out, so no whole provider-shaped token is a
/// literal in this file.
fn credential_line() -> String {
    format!(
        "GH_TOKEN = {}{}",
        "ghp_", "Jd2RmVe9XtB4kPdW7LcZsY6JhG3uA1oF5rT8"
    )
}

/// A second, different token, for the cases that need two findings told apart.
fn other_credential_line() -> String {
    format!(
        "GH_TOKEN = {}{}",
        "ghp_", "Ks4TcJx6ZbQ1nK8vD3mYpL9gH5rE7uA2fN0i"
    )
}

/// The two codecs a zip member may use, as the format numbers them.
const STORED: u16 = 0;
const DEFLATE: u16 = 8;

/// One member, as the builder below will write it. The fields a well-formed
/// archive derives are separate from the ones a malformed archive lies about,
/// so a test can set either on its own.
struct Entry {
    name: String,
    /// The bytes written into the file, already in whatever codec `method`
    /// names.
    stored: Vec<u8>,
    /// What the directory claims the member expands to, which an honest
    /// archive and a bomb spell differently.
    uncompressed: u32,
    method: u16,
    flags: u16,
    /// The member's checksum, so these fixtures are archives any zip tool
    /// opens rather than something only this reader accepts.
    crc: u32,
    /// Whether the directory points at this member's data with the value that
    /// means "the real offset is in a zip64 extra field".
    zip64_offset: bool,
}

fn crc32(body: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(body);
    crc.sum()
}

fn stored(name: &str, body: &[u8]) -> Entry {
    Entry {
        name: name.to_string(),
        stored: body.to_vec(),
        uncompressed: body.len() as u32,
        method: STORED,
        flags: 0,
        crc: crc32(body),
        zip64_offset: false,
    }
}

fn deflated(name: &str, body: &[u8]) -> Entry {
    Entry {
        name: name.to_string(),
        stored: deflate(body),
        uncompressed: body.len() as u32,
        method: DEFLATE,
        flags: 0,
        crc: crc32(body),
        zip64_offset: false,
    }
}

fn deflate(body: &[u8]) -> Vec<u8> {
    let mut encoder =
        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(body).unwrap();
    encoder.finish().unwrap()
}

fn zip_bytes(entries: &[Entry]) -> Vec<u8> {
    zip_bytes_with_comment(entries, b"")
}

/// A zip written by hand, so a test can shape the container as well as the
/// members. Writing one with a library would only exercise the shapes that
/// library produces, and the shapes worth testing are the ones it never would.
fn zip_bytes_with_comment(entries: &[Entry], comment: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();
    for entry in entries {
        offsets.push(out.len() as u32);
        out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]);
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&entry.flags.to_le_bytes());
        out.extend_from_slice(&entry.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // modified time
        out.extend_from_slice(&0u16.to_le_bytes()); // modified date
        out.extend_from_slice(&entry.crc.to_le_bytes());
        out.extend_from_slice(&(entry.stored.len() as u32).to_le_bytes());
        out.extend_from_slice(&entry.uncompressed.to_le_bytes());
        out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend_from_slice(entry.name.as_bytes());
        out.extend_from_slice(&entry.stored);
    }
    let directory_at = out.len() as u32;
    for (entry, offset) in entries.iter().zip(&offsets) {
        out.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]);
        out.extend_from_slice(&20u16.to_le_bytes()); // version made by
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&entry.flags.to_le_bytes());
        out.extend_from_slice(&entry.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // modified time
        out.extend_from_slice(&0u16.to_le_bytes()); // modified date
        out.extend_from_slice(&entry.crc.to_le_bytes());
        out.extend_from_slice(&(entry.stored.len() as u32).to_le_bytes());
        out.extend_from_slice(&entry.uncompressed.to_le_bytes());
        out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend_from_slice(&0u16.to_le_bytes()); // comment length
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        out.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        let at = if entry.zip64_offset {
            u32::MAX
        } else {
            *offset
        };
        out.extend_from_slice(&at.to_le_bytes());
        out.extend_from_slice(entry.name.as_bytes());
    }
    let directory_len = out.len() as u32 - directory_at;
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk the directory starts on
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&directory_len.to_le_bytes());
    out.extend_from_slice(&directory_at.to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    out
}

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

fn scan(archive: &[u8], path: &str) -> (Vec<String>, usize) {
    let (findings, scanned) = scan_blob(
        archive,
        path,
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    (findings.into_iter().map(|f| f.path).collect(), scanned)
}

#[test]
fn a_credential_inside_a_deflated_zip_is_read_under_the_member_it_came_from() {
    let member = format!("line one\n{}\n", credential_line());
    let archive = zip_bytes(&[deflated("config/prod.env", member.as_bytes())]);
    let (findings, scanned) = scan_blob(
        &archive,
        "backup.zip",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "backup.zip!/config/prod.env");
    assert_eq!(findings[0].rule_id, "github-token");
    assert_eq!(findings[0].line, 2);
    assert_eq!(findings[0].source, "working_tree");
    // The member's own bytes, not the compressed archive's.
    assert_eq!(scanned, member.len());
}

#[test]
fn a_stored_member_is_read_like_a_deflated_one() {
    // A zip writer leaves a member stored when compressing it would not pay,
    // which is exactly what happens to the short files credentials live in.
    let member = credential_line();
    let archive = zip_bytes(&[stored("etc/secrets.env", member.as_bytes())]);
    let (paths, scanned) = scan(&archive, "release.zip");
    assert_eq!(paths, ["release.zip!/etc/secrets.env"]);
    assert_eq!(scanned, member.len());
}

#[test]
fn every_member_of_a_zip_is_read_not_only_the_first() {
    let first = credential_line();
    let second = other_credential_line();
    let archive = zip_bytes(&[
        stored("one.env", first.as_bytes()),
        deflated("two/other.env", second.as_bytes()),
    ]);
    let (paths, _) = scan(&archive, "pair.zip");
    assert_eq!(paths, ["pair.zip!/one.env", "pair.zip!/two/other.env"]);
}

#[test]
fn a_member_keeps_the_basename_its_bar_is_read_from() {
    // The separator opens a fresh path segment, so `.env` is still the
    // member's suffix and still earns the stricter bar a `.env` earns. A
    // reader that ran the names together would read `secrets.zipprod.env`.
    let member = credential_line();
    let archive = zip_bytes(&[stored("prod.env", member.as_bytes())]);
    let (paths, _) = scan(&archive, "secrets.zip");
    assert_eq!(paths, ["secrets.zip!/prod.env"]);
}

#[test]
fn a_binary_member_is_left_undecoded_like_a_binary_file() {
    let mut member = credential_line().into_bytes();
    member.push(0);
    let archive = zip_bytes(&[stored("logo.png", &member)]);
    let (paths, scanned) = scan(&archive, "assets.zip");
    assert!(paths.is_empty());
    // Read out of the archive, then declined by the same decode the rest of
    // the scan uses; the bytes were still spent.
    assert_eq!(scanned, member.len());
}

#[test]
fn a_directory_entry_is_not_read_as_a_file() {
    let member = credential_line();
    let archive = zip_bytes(&[
        stored("config/", b""),
        stored("config/prod.env", member.as_bytes()),
    ]);
    let (paths, _) = scan(&archive, "tree.zip");
    assert_eq!(paths, ["tree.zip!/config/prod.env"]);
}

#[test]
fn an_encrypted_member_is_skipped_rather_than_read_as_ciphertext() {
    let member = credential_line();
    let mut entry = stored("prod.env", member.as_bytes());
    entry.flags = 1;
    let archive = zip_bytes(&[entry]);
    let (paths, scanned) = scan(&archive, "locked.zip");
    assert!(paths.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn a_member_in_an_unreadable_codec_is_skipped_and_the_rest_is_read() {
    // Method 9 is deflate64, whose reader is not here. One member no reader
    // handles is not a reason to stop reading the members beside it.
    let unreadable = credential_line();
    let readable = other_credential_line();
    let mut entry = stored("first.env", unreadable.as_bytes());
    entry.method = 9;
    let archive = zip_bytes(&[entry, stored("second.env", readable.as_bytes())]);
    let (paths, _) = scan(&archive, "mixed.zip");
    assert_eq!(paths, ["mixed.zip!/second.env"]);
}

#[test]
fn a_zip64_member_is_skipped_rather_than_read_at_a_sentinel_offset() {
    // `0xFFFFFFFF` in the offset field means the real one lives in an extra
    // field this reader does not parse. Reading it as an offset would point
    // four gigabytes past the end of every archive that uses it.
    let member = credential_line();
    let mut entry = stored("prod.env", member.as_bytes());
    entry.zip64_offset = true;
    let archive = zip_bytes(&[entry]);
    let (paths, scanned) = scan(&archive, "large.zip");
    assert!(paths.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn a_member_claiming_a_size_its_stream_does_not_deliver_is_refused() {
    // The directory says the member is one byte longer than the deflate
    // stream produces. A reader that trusted whichever number suited it would
    // be the one a bomb aims at.
    let member = credential_line();
    let mut entry = deflated("prod.env", member.as_bytes());
    entry.uncompressed += 1;
    let archive = zip_bytes(&[entry]);
    let (paths, scanned) = scan(&archive, "lying.zip");
    assert!(paths.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn a_stored_member_whose_two_sizes_disagree_is_refused() {
    let member = credential_line();
    let mut entry = stored("prod.env", member.as_bytes());
    entry.uncompressed += 1;
    let archive = zip_bytes(&[entry]);
    let (paths, scanned) = scan(&archive, "malformed.zip");
    assert!(paths.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn a_member_that_expands_far_past_the_cap_is_not_inflated() {
    // A megabyte of one repeated byte deflates to almost nothing, which is
    // the whole shape of a zip bomb. The size comes from the directory, so
    // the cap is applied before a byte is inflated.
    let bomb = vec![b'A'; (MAX_MEMBER_BYTES + 1) as usize];
    let archive = zip_bytes(&[deflated("huge.env", &bomb)]);
    let (paths, scanned) = scan(&archive, "bomb.zip");
    assert!(paths.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn a_member_past_the_callers_own_file_cap_is_skipped() {
    let member = credential_line();
    let archive = zip_bytes(&[stored("small.env", member.as_bytes())]);
    let (findings, scanned) = scan_blob(
        &archive,
        "capped.zip",
        "working_tree",
        None,
        200,
        ByteBudget {
            max_member_bytes: member.len() - 1,
            remaining_total_bytes: usize::MAX,
        },
    );
    assert!(findings.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn a_member_the_scan_has_no_bytes_left_for_is_not_read() {
    let member = credential_line();
    let archive = zip_bytes(&[stored("small.env", member.as_bytes())]);
    let (findings, scanned) = scan_blob(
        &archive,
        "tight.zip",
        "working_tree",
        None,
        200,
        ByteBudget {
            max_member_bytes: usize::MAX,
            remaining_total_bytes: member.len() - 1,
        },
    );
    assert!(findings.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn the_finding_budget_stops_the_member_walk() {
    let first = credential_line();
    let second = other_credential_line();
    let archive = zip_bytes(&[
        stored("one.env", first.as_bytes()),
        stored("two.env", second.as_bytes()),
    ]);
    let (findings, scanned) = scan_blob(
        &archive,
        "budget.zip",
        "working_tree",
        None,
        1,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "budget.zip!/one.env");
    // The second member was never read, so its bytes were never spent.
    assert_eq!(scanned, first.len());
}

#[test]
fn a_member_named_twice_does_not_spend_the_budget_meant_for_another() {
    // A zip may name the same member twice as readily as a tar may, and the
    // directory is where it is cheapest to do so.
    let repeated = credential_line();
    let other = other_credential_line();
    let archive = zip_bytes(&[
        stored("same.env", repeated.as_bytes()),
        stored("same.env", repeated.as_bytes()),
        stored("other.env", other.as_bytes()),
    ]);
    let (findings, _) = scan_blob(
        &archive,
        "repeat.zip",
        "working_tree",
        None,
        2,
        ByteBudget::unbounded(),
    );
    let paths: Vec<&str> = findings.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, ["repeat.zip!/same.env", "repeat.zip!/other.env"]);
}

#[test]
fn a_zip_whose_directory_names_more_members_than_the_walk_reads_stops_at_the_bound() {
    let member = credential_line();
    let mut entries: Vec<Entry> = (0..super::MAX_MEMBERS)
        .map(|index| stored(&format!("pad{index}.txt"), b"nothing here\n"))
        .collect();
    entries.push(stored("last.env", member.as_bytes()));
    let archive = zip_bytes(&entries);
    let (paths, _) = scan(&archive, "many.zip");
    assert!(paths.is_empty());
}

#[test]
fn a_zip_carrying_a_trailing_comment_is_still_read() {
    // The end-of-directory record's own position depends on the length of the
    // comment that follows it, which is why it is searched for backwards.
    let member = credential_line();
    let archive = zip_bytes_with_comment(
        &[stored("prod.env", member.as_bytes())],
        b"written by a backup tool",
    );
    let (paths, _) = scan(&archive, "commented.zip");
    assert_eq!(paths, ["commented.zip!/prod.env"]);
}

#[test]
fn a_record_signature_inside_a_members_data_is_not_mistaken_for_the_directory() {
    // A stored member may contain any bytes at all, the end-of-directory
    // signature included. Searching backwards from the tail reaches the real
    // record first, and a candidate is accepted only when its own comment
    // length reaches exactly the end of the file, so the planted one is not
    // read as the directory's address.
    let mut member = Vec::new();
    member.extend_from_slice(b"PK\x05\x06");
    member.extend_from_slice(&[0u8; 18]);
    member.extend_from_slice(credential_line().as_bytes());
    member.push(b'\n');
    let archive = zip_bytes(&[stored("prod.env", &member)]);
    let (paths, _) = scan(&archive, "tricky.zip");
    assert_eq!(paths, ["tricky.zip!/prod.env"]);
}

#[test]
fn an_empty_zip_is_recognised_and_reports_nothing() {
    let archive = zip_bytes(&[]);
    assert!(is_zip(&archive));
    let (paths, scanned) = scan(&archive, "empty.zip");
    assert!(paths.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn bytes_that_only_begin_like_a_zip_are_not_read_as_one() {
    // Without a directory there is nothing to walk, and guessing at local
    // headers is how a reader walks off the end of a truncated file.
    let archive = b"PK\x03\x04 and then nothing that follows the format";
    assert!(is_zip(archive));
    let (findings, scanned) = scan_members(
        archive,
        "truncated.zip",
        "working_tree",
        None,
        200,
        super::super::Caps {
            member: MAX_MEMBER_BYTES,
            total: 1024,
        },
    );
    assert!(findings.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn a_gzipped_zip_is_read_as_the_zip_it_is() {
    // A mail gateway or a backup script compresses an archive that was
    // already one. The second shape is recognised after inflation, not only
    // before it.
    let member = credential_line();
    let archive = gzip_bytes(&zip_bytes(&[stored("prod.env", member.as_bytes())]));
    let (paths, _) = scan(&archive, "double.zip.gz");
    assert_eq!(paths, ["double.zip.gz!/prod.env"]);
}

#[test]
fn a_zip_inside_a_tar_is_not_opened_twice() {
    // One level of nesting is read, which is what a committed archive is.
    // Walking an archive inside an archive inside an archive is how a bounded
    // walk stops being bounded, so the inner zip is read as the file it is.
    let inner = zip_bytes(&[stored("prod.env", credential_line().as_bytes())]);
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(inner.len() as u64);
    header.set_mode(0o644);
    builder
        .append_data(&mut header, "nested.zip", inner.as_slice())
        .unwrap();
    let archive = builder.into_inner().unwrap();
    let (paths, _) = scan(&archive, "outer.tar");
    assert!(paths.is_empty());
}

#[test]
fn a_member_whose_checksum_does_not_match_its_bytes_is_still_read() {
    // The checksum says whether the archive is intact, not whether what it
    // carries is a credential. Refusing a member over it would hand anyone
    // who wanted a secret past this scan a one-byte way to get it there.
    let member = credential_line();
    let mut entry = stored("prod.env", member.as_bytes());
    entry.crc ^= 1;
    let archive = zip_bytes(&[entry]);
    let (paths, _) = scan(&archive, "corrupt.zip");
    assert_eq!(paths, ["corrupt.zip!/prod.env"]);
}
