use std::io::Write;

use super::super::scan_blob;
use super::{MAX_EXPANSION_RATIO, MAX_MEMBER_BYTES, MAX_TOTAL_BYTES};

/// Assembled rather than written out, so no whole provider-shaped token is a
/// literal in this file.
fn credential_line() -> String {
    format!(
        "GH_TOKEN = {}{}",
        "ghp_", "Nq7RmVe2XtB4kPdW9LcZsY6JhG3uA1oF5rT8"
    )
}

fn tar_bytes(members: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, body) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        builder.append_data(&mut header, name, *body).unwrap();
    }
    builder.into_inner().unwrap()
}

fn gzip_bytes(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn a_credential_inside_a_tar_gz_is_read_under_the_member_it_came_from() {
    let member = format!("line one\n{}\n", credential_line());
    let archive = gzip_bytes(&tar_bytes(&[("config/prod.env", member.as_bytes())]));
    let (findings, scanned) = scan_blob(&archive, "backup.tar.gz", "working_tree", None, 200);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "backup.tar.gz!config/prod.env");
    assert_eq!(findings[0].rule_id, "github-token");
    assert_eq!(findings[0].line, 2);
    assert_eq!(findings[0].source, "working_tree");
    // The member's own bytes, not the compressed archive's.
    assert_eq!(scanned, member.len());
}

#[test]
fn a_credential_inside_a_plain_tar_is_read_the_same_way() {
    let member = credential_line();
    let archive = tar_bytes(&[("etc/secrets.env", member.as_bytes())]);
    let (findings, _) = scan_blob(&archive, "release.tar", "git_history", Some("cafe"), 200);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "release.tar!etc/secrets.env");
    assert_eq!(findings[0].commit.as_deref(), Some("cafe"));
}

#[test]
fn a_gzipped_file_is_read_under_the_name_it_has_uncompressed() {
    let archive = gzip_bytes(credential_line().as_bytes());
    let (findings, _) = scan_blob(&archive, "config/prod.env.gz", "working_tree", None, 200);
    assert_eq!(findings.len(), 1);
    // A lone `.gz` holds one file, so there is no member name to join on.
    assert_eq!(findings[0].path, "config/prod.env");
}

#[test]
fn a_tgz_is_read_as_the_tar_it_is() {
    let archive = gzip_bytes(&tar_bytes(&[("a/b.env", credential_line().as_bytes())]));
    let (findings, _) = scan_blob(&archive, "bundle.tgz", "working_tree", None, 200);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "bundle.tgz!a/b.env");
}

#[test]
fn a_binary_member_is_left_undecoded_like_a_binary_file() {
    let mut member = credential_line().into_bytes();
    member.push(0);
    let archive = tar_bytes(&[("assets/logo.png", member.as_slice())]);
    let (findings, _) = scan_blob(&archive, "assets.tar", "working_tree", None, 200);
    assert!(findings.is_empty());
}

#[test]
fn every_member_of_an_archive_is_read_not_only_the_first() {
    let member = credential_line();
    let archive = tar_bytes(&[
        ("one.env", member.as_bytes()),
        ("two/also.env", member.as_bytes()),
    ]);
    let (findings, _) = scan_blob(&archive, "both.tar", "working_tree", None, 200);
    let mut paths: Vec<&str> = findings.iter().map(|f| f.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(paths, vec!["both.tar!one.env", "both.tar!two/also.env"]);
}

#[test]
fn the_finding_budget_stops_the_member_walk() {
    let member = credential_line();
    let archive = tar_bytes(&[
        ("one.env", member.as_bytes()),
        ("two.env", member.as_bytes()),
        ("three.env", member.as_bytes()),
    ]);
    let (findings, _) = scan_blob(&archive, "three.tar", "working_tree", None, 2);
    assert_eq!(findings.len(), 2);
}

#[test]
fn a_member_too_large_to_be_a_credential_file_is_skipped() {
    let mut member = credential_line().into_bytes();
    member.resize(MAX_MEMBER_BYTES as usize + 1, b'.');
    let archive = tar_bytes(&[("huge.env", member.as_slice())]);
    let (findings, scanned) = scan_blob(&archive, "huge.tar", "working_tree", None, 200);
    assert!(findings.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn a_stream_that_expands_far_past_its_own_size_is_not_inflated() {
    // A gzip bomb's shape: a small stream claiming a large expansion. The
    // ratio cap refuses it before the bytes are held.
    let bomb = gzip_bytes(&vec![b'0'; 4 * 1024 * 1024]);
    assert!(bomb.len() * MAX_EXPANSION_RATIO < 4 * 1024 * 1024);
    let (findings, scanned) = scan_blob(&bomb, "bomb.gz", "working_tree", None, 200);
    assert!(findings.is_empty());
    assert_eq!(scanned, 0);
    // The absolute cap is the other half of the same defence.
    assert!(MAX_TOTAL_BYTES < u32::MAX as usize);
}

#[test]
fn a_member_naming_itself_with_the_separator_is_not_reported() {
    // A member path that carried `!` could be read back as some other
    // archive's member, so it is dropped rather than reported ambiguously.
    let archive = tar_bytes(&[("we!rd.env", credential_line().as_bytes())]);
    let (findings, _) = scan_blob(&archive, "odd.tar", "working_tree", None, 200);
    assert!(findings.is_empty());
}

#[test]
fn a_binary_file_that_is_not_an_archive_is_still_skipped() {
    let (findings, scanned) = scan_blob(b"\0not an archive", "blob.bin", "working_tree", None, 200);
    assert!(findings.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn a_truncated_archive_keeps_what_it_already_read() {
    let member = credential_line();
    let full = tar_bytes(&[
        ("one.env", member.as_bytes()),
        ("two.env", member.as_bytes()),
    ]);
    // Three 512-byte blocks: the first member's header and data, then the
    // start of the second member's header. The first member is whole.
    let truncated = &full[..1536];
    let (findings, _) = scan_blob(truncated, "cut.tar", "working_tree", None, 200);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "cut.tar!one.env");
}
