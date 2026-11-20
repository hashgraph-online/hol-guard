use super::super::is_zip;
use super::super::tests::{
    credential_line, deflated, gzip_bytes, other_credential_line, scan, stored, zip_bytes,
    zip_bytes_with_comment,
};
use super::embedded_start;

/// `PK\x03\x04`, as these fixtures write it.
const LOCAL_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];

/// An executable stub, binary enough that the blob reaches the archive walk as
/// a binary rather than as text.
fn stub(len: usize) -> Vec<u8> {
    let mut bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00".to_vec();
    bytes.resize(len, 0);
    bytes
}

/// Where the end record of an archive written without a comment says its
/// directory begins.
fn directory_offset(archive: &[u8]) -> usize {
    let end = archive.len() - 22;
    u32::from_le_bytes(archive[end + 16..end + 20].try_into().unwrap()) as usize
}

/// Where the second member's local header begins.
fn second_local_header(archive: &[u8]) -> usize {
    let first = archive
        .windows(LOCAL_SIGNATURE.len())
        .position(|window| window == LOCAL_SIGNATURE)
        .unwrap();
    let after = first + LOCAL_SIGNATURE.len();
    after
        + archive[after..]
            .windows(LOCAL_SIGNATURE.len())
            .position(|window| window == LOCAL_SIGNATURE)
            .unwrap()
}

/// Rewrite an appended archive's recorded offsets the way a self-extractor
/// builder does, so they count from the start of the whole file rather than
/// from the archive's own first byte.
fn adjust_offsets_to_the_file(sfx: &mut [u8], prefix: usize) {
    let end = sfx.len() - 22;
    let directory_at = u32::from_le_bytes(sfx[end + 16..end + 20].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(sfx[end + 12..end + 16].try_into().unwrap()) as usize;
    let directory = prefix + directory_at;
    sfx[end + 16..end + 20].copy_from_slice(&(directory as u32).to_le_bytes());
    let mut at = directory;
    while at < directory + size {
        let name = u16::from_le_bytes(sfx[at + 28..at + 30].try_into().unwrap()) as usize;
        let extra = u16::from_le_bytes(sfx[at + 30..at + 32].try_into().unwrap()) as usize;
        let comment = u16::from_le_bytes(sfx[at + 32..at + 34].try_into().unwrap()) as usize;
        let local = u32::from_le_bytes(sfx[at + 42..at + 46].try_into().unwrap()) + prefix as u32;
        sfx[at + 42..at + 46].copy_from_slice(&local.to_le_bytes());
        at += 46 + name + extra + comment;
    }
}

#[test]
fn a_self_extracting_archive_is_read_from_where_its_zip_begins() {
    // The common shape of a secret leaving a repository in something no reader
    // opens: an executable with a zip appended to it. Nothing at byte zero
    // says archive, and every offset the archive records counts from where the
    // zip begins rather than from the start of the file.
    let member = credential_line();
    let archive = zip_bytes(&[deflated("prod.env", member.as_bytes())]);
    let mut sfx = stub(512);
    sfx.extend_from_slice(&archive);

    assert!(!is_zip(&sfx));
    assert_eq!(embedded_start(&sfx), Some(512));

    let (paths, scanned) = scan(&sfx, "installer.exe");
    assert_eq!(paths, ["installer.exe!/prod.env"]);
    assert_eq!(scanned, member.len());
}

#[test]
fn a_self_extracting_archive_is_read_after_inflation_too() {
    // A stub-carrying zip compressed again, which a mail gateway or a backup
    // script produces without meaning to.
    let member = credential_line();
    let archive = zip_bytes(&[stored("prod.env", member.as_bytes())]);
    let mut sfx = stub(256);
    sfx.extend_from_slice(&archive);

    let (paths, _) = scan(&gzip_bytes(&sfx), "installer.exe.gz");
    assert_eq!(paths, ["installer.exe.gz!/prod.env"]);
}

#[test]
fn a_self_extractor_with_offsets_adjusted_to_the_file_is_read_in_place() {
    // `zip -A`, and the WinZip and WinRAR self-extractor builders, rewrite the
    // archive's recorded offsets to count from the start of the whole file.
    // The file still begins with a stub, so nothing at byte zero says archive,
    // but the offsets are already the file's own and the origin is byte zero.
    let member = credential_line();
    let archive = zip_bytes(&[stored("prod.env", member.as_bytes())]);
    let mut sfx = stub(384);
    sfx.extend_from_slice(&archive);
    adjust_offsets_to_the_file(&mut sfx, 384);

    assert!(!is_zip(&sfx));
    assert_eq!(embedded_start(&sfx), Some(0));

    let (paths, scanned) = scan(&sfx, "installer.exe");
    assert_eq!(paths, ["installer.exe!/prod.env"]);
    assert_eq!(scanned, member.len());
}

#[test]
fn a_forged_end_record_in_the_comment_cannot_hide_an_earlier_member() {
    // An archive's trailing comment is the cheapest place to plant a second
    // end record, and one planted there is reached from the tail before the
    // real one. This forgery names the real directory, so it reads as an
    // archive, but counts that directory's offset from the second member's
    // local header. Were the first valid-looking record to decide alone, the
    // bytes handed to the walk would begin at the second member and the first
    // member's secret would be in neither pass.
    let first = credential_line();
    let second = other_credential_line();
    let members = [
        stored("first.env", first.as_bytes()),
        stored("second.env", second.as_bytes()),
    ];
    let honest = zip_bytes(&members);
    let directory_at = directory_offset(&honest);
    let second_at = second_local_header(&honest);

    let mut forged = Vec::new();
    forged.extend_from_slice(b"PK\x05\x06");
    forged.extend_from_slice(&0u16.to_le_bytes()); // this disk
    forged.extend_from_slice(&0u16.to_le_bytes()); // disk the directory starts on
    forged.extend_from_slice(&1u16.to_le_bytes()); // records on this disk
    forged.extend_from_slice(&1u16.to_le_bytes()); // records in total
    forged.extend_from_slice(&((honest.len() - directory_at) as u32).to_le_bytes());
    forged.extend_from_slice(&((directory_at - second_at) as u32).to_le_bytes());
    forged.extend_from_slice(&0u16.to_le_bytes()); // comment length
    assert_eq!(forged.len(), 22);

    let mut sfx = stub(512);
    sfx.extend_from_slice(&zip_bytes_with_comment(&members, &forged));

    assert_eq!(embedded_start(&sfx), Some(512));

    let (mut paths, scanned) = scan(&sfx, "installer.exe");
    paths.sort();
    assert_eq!(
        paths,
        ["installer.exe!/first.env", "installer.exe!/second.env"]
    );
    assert_eq!(scanned, first.len() + second.len());
}

#[test]
fn a_binary_carrying_no_archive_is_not_read_as_one() {
    // The searching this does over the tail of every binary blob has to end
    // somewhere. An end record that names an empty directory reaches nothing
    // behind the stub, and one whose figures do not land on an archive is an
    // end record that fell inside a binary rather than one that names a zip.
    let mut empty = stub(256);
    empty.extend_from_slice(b"PK\x05\x06");
    empty.extend_from_slice(&[0u8; 18]);
    assert_eq!(embedded_start(&empty), None);
    let (paths, scanned) = scan(&empty, "tool.bin");
    assert!(paths.is_empty());
    assert_eq!(scanned, 0);

    let mut nonsense = stub(256);
    nonsense.extend_from_slice(b"PK\x05\x06");
    nonsense.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
    nonsense.extend_from_slice(&40u32.to_le_bytes());
    nonsense.extend_from_slice(&8u32.to_le_bytes());
    nonsense.extend_from_slice(&[0, 0]);
    assert_eq!(embedded_start(&nonsense), None);
    let (paths, scanned) = scan(&nonsense, "tool.bin");
    assert!(paths.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn a_prefixed_archive_with_slack_before_its_end_record_is_left_unread() {
    // The arithmetic that finds the origin rests on the directory being
    // written immediately before the end record, which is how every archiver
    // writes one. Where something sits between them the subtraction lands in
    // the wrong place, and the result is checked against the archive before it
    // is used rather than acted on: an origin that does not reach a member's
    // own local header is no origin at all.
    let member = credential_line();
    let archive = zip_bytes(&[stored("prod.env", member.as_bytes())]);
    let (directory, end) = archive.split_at(archive.len() - 22);

    let mut padded = stub(128);
    padded.extend_from_slice(directory);
    padded.extend_from_slice(&[0u8; 16]);
    padded.extend_from_slice(end);

    assert_eq!(embedded_start(&padded), None);
    let (paths, scanned) = scan(&padded, "installer.exe");
    assert!(paths.is_empty());
    assert_eq!(scanned, 0);
}
