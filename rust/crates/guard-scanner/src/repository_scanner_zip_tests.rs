use std::io::Write;

use super::super::{ByteBudget, MAX_MEMBER_BYTES};
use super::{is_zip, scan_members};
use crate::repository_scanner::scan_blob;

/// Assembled rather than written out, so no whole provider-shaped token is a
/// literal in this file.
pub(super) fn credential_line() -> String {
    format!(
        "GH_TOKEN = {}{}",
        "ghp_", "Jd2RmVe9XtB4kPdW7LcZsY6JhG3uA1oF5rT8"
    )
}

/// A second, different token, for the cases that need two findings told apart.
pub(super) fn other_credential_line() -> String {
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
pub(super) struct Entry {
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

pub(super) fn stored(name: &str, body: &[u8]) -> Entry {
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

pub(super) fn deflated(name: &str, body: &[u8]) -> Entry {
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

pub(super) fn zip_bytes(entries: &[Entry]) -> Vec<u8> {
    zip_bytes_with_comment(entries, b"")
}

pub(super) fn zip_bytes_with_comment(entries: &[Entry], comment: &[u8]) -> Vec<u8> {
    let named: Vec<usize> = (0..entries.len()).collect();
    zip_bytes_naming(entries, &named, comment)
}

/// A zip written by hand, so a test can shape the container as well as the
/// members. Writing one with a library would only exercise the shapes that
/// library produces, and the shapes worth testing are the ones it never would.
///
/// `named` says which of the members the directory accounts for. Every member
/// is written into the file either way, which is the point: an archive hiding
/// one from a reader that trusts the directory still carries it.
fn zip_bytes_naming(entries: &[Entry], named: &[usize], comment: &[u8]) -> Vec<u8> {
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
    for (entry, offset) in named.iter().map(|&at| (&entries[at], offsets[at])) {
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
        let at = if entry.zip64_offset { u32::MAX } else { offset };
        out.extend_from_slice(&at.to_le_bytes());
        out.extend_from_slice(entry.name.as_bytes());
    }
    let directory_len = out.len() as u32 - directory_at;
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]);
    out.extend_from_slice(&0u16.to_le_bytes()); // this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk the directory starts on
    out.extend_from_slice(&(named.len() as u16).to_le_bytes());
    out.extend_from_slice(&(named.len() as u16).to_le_bytes());
    out.extend_from_slice(&directory_len.to_le_bytes());
    out.extend_from_slice(&directory_at.to_le_bytes());
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment);
    out
}

/// Set the encrypted flag on one member's central record and nowhere else,
/// so the directory's account of that member disagrees with the local header
/// that owns it. A builder that wrote both from one `Entry` could not shape
/// this, and a directory disagreeing with the data it indexes is the whole
/// reason the local headers are walked.
fn claim_encrypted_in_the_directory(archive: &mut [u8], name: &str) {
    const CENTRAL_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];
    const FIXED: usize = 46;
    let mut at = 0usize;
    loop {
        // A `while let` over the search would hold the borrow of the archive
        // across the body, where the record is written; a `let ... else`
        // statement drops it at the end of the statement.
        let Some(offset) = archive[at..]
            .windows(CENTRAL_SIGNATURE.len())
            .position(|window| window == CENTRAL_SIGNATURE)
        else {
            panic!("no central record names {name}");
        };
        let record = at + offset;
        at = record + CENTRAL_SIGNATURE.len();
        let length = u16::from_le_bytes([archive[record + 28], archive[record + 29]]) as usize;
        if &archive[record + FIXED..record + FIXED + length] != name.as_bytes() {
            continue;
        }
        archive[record + 8] = 1;
        return;
    }
}

pub(super) fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

pub(super) fn scan(archive: &[u8], path: &str) -> (Vec<String>, usize) {
    let (findings, scanned) = scan_blob(
        archive,
        path,
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    (findings.iter().map(|f| f.path.clone()).collect(), scanned)
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
fn a_zip64_offset_is_not_followed_and_the_member_is_read_anyway() {
    // `0xFFFFFFFF` in the offset field means the real one lives in an extra
    // field this reader does not parse. Reading it as an offset would point
    // four gigabytes past the end of every archive that uses it, so the
    // record is dropped - and the member is then found through its own local
    // header, the way a member no directory accounts for is. A credential
    // does not stop being one because the record naming it was unusable.
    let member = credential_line();
    let mut entry = stored("prod.env", member.as_bytes());
    entry.zip64_offset = true;
    let archive = zip_bytes(&[entry]);
    let (paths, scanned) = scan(&archive, "large.zip");
    assert_eq!(paths, ["large.zip!/prod.env"]);
    // Once, by the second pass, not twice.
    assert_eq!(scanned, member.len());
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
fn a_directory_that_lies_about_a_member_does_not_hide_it() {
    // The directory is the archive's own account of itself, and an archive
    // that wants a member left unread can call it encrypted there while the
    // bytes sit in plain sight behind a local header that says otherwise.
    // Charging the walk for a member it could not read must not also spend
    // the second pass's right to read it from the header that owns it.
    let hidden = credential_line();
    let mut archive = zip_bytes(&[stored("prod.env", hidden.as_bytes())]);
    claim_encrypted_in_the_directory(&mut archive, "prod.env");
    let (paths, scanned) = scan(&archive, "lying.zip");
    assert_eq!(paths, ["lying.zip!/prod.env"]);
    assert_eq!(scanned, hidden.len());
}

#[test]
fn a_directory_naming_one_member_over_and_over_leaves_room_for_the_rest() {
    // A record costs a few dozen bytes and the member it names costs whatever
    // the member costs, so repeating one record is the cheapest way to spend
    // a walk's allowance on nothing. The repeats name one member, so they are
    // charged for one, and the member they say nothing about is still read.
    let hidden = other_credential_line();
    let entries = [
        stored("pad.txt", b"nothing here\n"),
        stored("hidden.env", hidden.as_bytes()),
    ];
    let named = vec![0usize; super::MAX_MEMBERS];
    let archive = zip_bytes_naming(&entries, &named, b"");
    let (paths, scanned) = scan(&archive, "repeated.zip");
    assert_eq!(paths, ["repeated.zip!/hidden.env"]);
    // The repeated member's bytes were read once, not once per record.
    assert_eq!(scanned, entries[0].stored.len() + hidden.len());
}

#[test]
fn a_directory_of_records_that_name_nothing_leaves_room_for_the_members() {
    // A record pointing at an offset this reader cannot follow names no
    // member at all. Counting it would let a directory of such records use
    // the allowance up before the pass that reads the members behind them.
    let hidden = other_credential_line();
    let mut unreachable = stored("ghost.txt", b"nothing here\n");
    unreachable.zip64_offset = true;
    let entries = [unreachable, stored("hidden.env", hidden.as_bytes())];
    let named = vec![0usize; super::MAX_MEMBERS];
    let archive = zip_bytes_naming(&entries, &named, b"");
    let (paths, _) = scan(&archive, "dead.zip");
    assert_eq!(paths, ["dead.zip!/hidden.env"]);
}

#[test]
fn a_member_hidden_behind_an_inner_archive_is_still_found() {
    // The walk steps over an inner archive's data in one move rather than
    // reading each signature inside it. The move has to land where that data
    // ends: a member left out of the directory and written after the inner
    // archive is the first thing a step too far would hide.
    let inner = zip_bytes(&[stored("prod.env", credential_line().as_bytes())]);
    let hidden = other_credential_line();
    let archive = zip_bytes_naming(
        &[
            stored("nested.zip", &inner),
            stored("hidden.env", hidden.as_bytes()),
        ],
        &[0],
        b"",
    );
    let (paths, scanned) = scan(&archive, "step.zip");
    assert_eq!(paths, ["step.zip!/hidden.env"]);
    assert_eq!(scanned, inner.len() + hidden.len());
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
    // record first, so the planted one is never read as the directory's
    // address and the member is scanned like any other.
    //
    // The filler after the signature is printable on purpose: a NUL in the
    // first sample window marks the member binary, and a member that never
    // decodes as text would make this case pass for the wrong reason.
    let mut member = Vec::new();
    member.extend_from_slice(b"PK\x05\x06");
    member.extend_from_slice(b"not a real record!");
    member.push(b'\n');
    member.extend_from_slice(credential_line().as_bytes());
    member.push(b'\n');
    let archive = zip_bytes(&[stored("prod.env", &member)]);
    let (paths, _) = scan(&archive, "tricky.zip");
    assert_eq!(paths, ["tricky.zip!/prod.env"]);
}

#[test]
fn a_planted_record_in_the_trailing_comment_is_walked_past() {
    // The one position a planted record is reached from before the real one
    // is the archive's own trailing comment, and a record planted at the very
    // start of a comment of its own length does satisfy the comment check.
    // What refuses it is the directory it names: that has to lie inside the
    // file and ahead of the record naming it. This one does not, so the
    // backwards search carries on and reaches the real record behind it.
    let mut planted = Vec::new();
    planted.extend_from_slice(b"PK\x05\x06");
    planted.extend_from_slice(&0u16.to_le_bytes()); // this disk
    planted.extend_from_slice(&0u16.to_le_bytes()); // disk the directory starts on
    planted.extend_from_slice(&1u16.to_le_bytes()); // records on this disk
    planted.extend_from_slice(&1u16.to_le_bytes()); // records in total
    planted.extend_from_slice(&100u32.to_le_bytes()); // directory size
    planted.extend_from_slice(&0xffff_ff00u32.to_le_bytes()); // directory offset
    planted.extend_from_slice(&0u16.to_le_bytes()); // comment length
    assert_eq!(planted.len(), 22);

    let member = credential_line();
    let archive = zip_bytes_with_comment(&[stored("prod.env", member.as_bytes())], &planted);
    let (paths, _) = scan(&archive, "planted.zip");
    assert_eq!(paths, ["planted.zip!/prod.env"]);
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
    // The local header the bytes open with is walked like any other, and what
    // follows it describes no member a reader could recover: the codec is not
    // one, and the lengths run past the end of what there is. Nothing is read
    // and nothing is charged for.
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
fn a_zip_inside_a_zip_is_not_opened_twice() {
    // The search for local headers runs over the whole archive, and a member
    // stored verbatim holds whatever bytes it holds, so an inner zip's own
    // headers sit in the outer archive's bytes. Reading them here would
    // report the inner members under the outer archive's path, which is a
    // place no one could go to remove the secret, and would charge the same
    // bytes twice. One level of nesting is read, as it is for a tar.
    let inner = zip_bytes(&[stored("prod.env", credential_line().as_bytes())]);
    let archive = zip_bytes(&[stored("nested.zip", &inner)]);
    let (paths, scanned) = scan(&archive, "outer.zip");
    assert!(paths.is_empty());
    // The inner archive was read as the one file it is.
    assert_eq!(scanned, inner.len());
}

#[test]
fn a_zip_inside_a_headless_zip_is_not_opened_twice_either() {
    // Without a directory the outer member is found through its own local
    // header instead, and the bound has to hold there too: what the first
    // header's member carries is that member's business whichever pass found
    // it.
    let inner = zip_bytes(&[stored("prod.env", credential_line().as_bytes())]);
    let whole = zip_bytes(&[stored("nested.zip", &inner)]);
    let tail = 46 + "nested.zip".len() + 22;
    let headers = &whole[..whole.len() - tail];
    assert!(super::central_directory(headers).is_none());

    let (paths, scanned) = scan(headers, "headless.zip");
    assert!(paths.is_empty());
    assert_eq!(scanned, inner.len());
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

#[test]
fn an_empty_directory_forged_in_the_comment_does_not_hide_the_members() {
    // The cheapest forgery at the one position the backwards search reaches
    // first: an end-of-directory record, planted at the start of the archive's
    // own comment, naming an empty directory at offset zero. Every bound it is
    // asked about holds - the comment length reaches the end of the file, and
    // an empty directory at offset zero lies inside the file and ahead of the
    // record naming it - so what refuses it is that an archive holding a member
    // cannot have a directory with no records in it.
    let mut forged = Vec::new();
    forged.extend_from_slice(b"PK\x05\x06");
    forged.extend_from_slice(&0u16.to_le_bytes()); // this disk
    forged.extend_from_slice(&0u16.to_le_bytes()); // disk the directory starts on
    forged.extend_from_slice(&0u16.to_le_bytes()); // records on this disk
    forged.extend_from_slice(&0u16.to_le_bytes()); // records in total
    forged.extend_from_slice(&0u32.to_le_bytes()); // directory size
    forged.extend_from_slice(&0u32.to_le_bytes()); // directory offset
    forged.extend_from_slice(&0u16.to_le_bytes()); // comment length
    assert_eq!(forged.len(), 22);

    let member = credential_line();
    let archive = zip_bytes_with_comment(&[stored("prod.env", member.as_bytes())], &forged);
    let (paths, _) = scan(&archive, "forged.zip");
    assert_eq!(paths, ["forged.zip!/prod.env"]);
}

#[test]
fn a_small_zip_cannot_spend_the_whole_scans_allowance() {
    // Two megabytes of one repeated byte deflate to about two kilobytes, and a
    // directory may name that member as often as it likes for a few dozen bytes
    // apiece. Without a bound of its own, a couple of kilobytes of archive could
    // charge the scan's whole remaining allowance and leave every file committed
    // after it unread. The allowance a zip may spend is bounded by the archive's
    // own size, the same ratio the gzip walk applies, so the member is skipped
    // and the credential beside it is still found.
    let filler = vec![b'A'; 2 * 1024 * 1024];
    assert!((filler.len() as u64) < MAX_MEMBER_BYTES);
    let member = credential_line();
    let archive = zip_bytes(&[
        deflated("filler.bin", &filler),
        stored("small.env", member.as_bytes()),
    ]);
    assert!(archive.len() * super::super::MAX_EXPANSION_RATIO < filler.len());

    let (findings, scanned) = scan_blob(
        &archive,
        "ratio.zip",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    let paths: Vec<&str> = findings.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, ["ratio.zip!/small.env"]);
    assert_eq!(scanned, member.len());
}

#[test]
fn a_member_the_directory_leaves_out_is_still_read() {
    // The cheapest way to keep a member from a reader that trusts the
    // directory is not to forge anything: leave the member's record out. The
    // data is still in the file, behind its own local header, and the
    // extractor the archive is eventually opened with still finds it.
    let named = credential_line();
    let omitted = other_credential_line();
    let archive = zip_bytes_naming(
        &[
            stored("named.env", named.as_bytes()),
            stored("hidden.env", omitted.as_bytes()),
        ],
        &[0],
        b"",
    );
    let (paths, scanned) = scan(&archive, "omitted.zip");
    assert_eq!(paths, ["omitted.zip!/named.env", "omitted.zip!/hidden.env"]);
    // The named member was reached twice and read once, so the second pass
    // spends the budget only on what the first one missed.
    assert_eq!(scanned, named.len() + omitted.len());
}

#[test]
fn an_end_record_naming_a_shorter_directory_than_there_is_hides_nothing() {
    // A record planted in the trailing comment may point at the real
    // directory and name fewer of its bytes than it holds. It begins with a
    // record like any directory does and every bound it is asked about holds,
    // so the backwards search accepts it and the records behind the cut are
    // never walked. The members those records named are read from their own
    // local headers instead.
    let first = credential_line();
    let second = other_credential_line();
    let entries = [
        stored("one.env", first.as_bytes()),
        stored("two.env", second.as_bytes()),
    ];
    // Where the directory begins, and how much of it the first record takes.
    // A comment appended after the directory moves neither.
    let directory_at: usize = entries
        .iter()
        .map(|entry| 30 + entry.name.len() + entry.stored.len())
        .sum();
    let first_record = 46 + entries[0].name.len();

    let mut forged = Vec::new();
    forged.extend_from_slice(b"PK\x05\x06");
    forged.extend_from_slice(&0u16.to_le_bytes()); // this disk
    forged.extend_from_slice(&0u16.to_le_bytes()); // disk the directory starts on
    forged.extend_from_slice(&1u16.to_le_bytes()); // records on this disk
    forged.extend_from_slice(&1u16.to_le_bytes()); // records in total
    forged.extend_from_slice(&(first_record as u32).to_le_bytes());
    forged.extend_from_slice(&(directory_at as u32).to_le_bytes());
    forged.extend_from_slice(&0u16.to_le_bytes()); // comment length
    assert_eq!(forged.len(), 22);

    let archive = zip_bytes_with_comment(&entries, &forged);
    // The forgery is the record the search accepts, so the case tests what it
    // says it does rather than passing on the real directory behind it.
    assert_eq!(
        super::central_directory(&archive).unwrap().len(),
        first_record
    );

    let (paths, _) = scan(&archive, "shortened.zip");
    assert_eq!(paths, ["shortened.zip!/one.env", "shortened.zip!/two.env"]);
}

#[test]
fn an_archive_whose_directory_is_gone_is_still_read() {
    // A zip cut short, or one carved out of a larger file, has no end record
    // and so no directory at all. That is a reason to read it with less to go
    // on, not a reason to read nothing: the members are where they always
    // were.
    let member = credential_line();
    let whole = zip_bytes(&[stored("prod.env", member.as_bytes())]);
    let tail = 46 + "prod.env".len() + 22;
    let headers = &whole[..whole.len() - tail];
    assert!(super::central_directory(headers).is_none());

    let (paths, scanned) = scan(headers, "headless.zip");
    assert_eq!(paths, ["headless.zip!/prod.env"]);
    assert_eq!(scanned, member.len());
}

#[test]
fn a_member_whose_sizes_follow_its_data_is_left_to_the_directory() {
    // A streaming writer leaves the sizes out of the local header and writes
    // them after the data. There is nothing in the header to bound the read
    // with, so the second pass passes it over; the directory knows the real
    // sizes, so the member is read on the first pass like any other.
    let member = credential_line();
    let mut entry = stored("stream.env", member.as_bytes());
    entry.flags = 1 << 3;
    let archive = zip_bytes(&[entry]);
    let (paths, scanned) = scan(&archive, "streamed.zip");
    assert_eq!(paths, ["streamed.zip!/stream.env"]);
    assert_eq!(scanned, member.len());

    // Without the record that carries those sizes, there is no claim to read
    // it under and it is left alone.
    let mut hidden = stored("stream.env", member.as_bytes());
    hidden.flags = 1 << 3;
    let omitted = zip_bytes_naming(&[hidden], &[], b"");
    let (paths, scanned) = scan(&omitted, "streamed.zip");
    assert!(paths.is_empty());
    assert_eq!(scanned, 0);
}
