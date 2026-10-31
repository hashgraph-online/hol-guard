use std::io::Write;

use super::super::scan_blob;
use super::{ByteBudget, MAX_EXPANSION_RATIO, MAX_MEMBER_BYTES, MAX_TOTAL_BYTES};

/// Assembled rather than written out, so no whole provider-shaped token is a
/// literal in this file.
fn credential_line() -> String {
    format!(
        "GH_TOKEN = {}{}",
        "ghp_", "Nq7RmVe2XtB4kPdW9LcZsY6JhG3uA1oF5rT8"
    )
}

/// A second, different token, for the cases that need two findings told apart.
fn other_credential_line() -> String {
    format!(
        "GH_TOKEN = {}{}",
        "ghp_", "Ws4TcJx8ZbQ1nK6vD3mYpL9gH5rE7uA2fN0i"
    )
}

/// An assignment whose value is twelve mixed characters: long enough and
/// varied enough to be a credential in a file whose name says credentials
/// live there, and too short to be one anywhere else. What it proves is which
/// name the bar was read from. Assembled for the same reason as the tokens
/// above.
fn short_high_signal_line() -> String {
    format!("API_KEY = {}{}", "Ab3dEf", "6hJk9m")
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
    let (findings, scanned) = scan_blob(
        &archive,
        "backup.tar.gz",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "backup.tar.gz!/config/prod.env");
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
    let (findings, _) = scan_blob(
        &archive,
        "release.tar",
        "git_history",
        Some("cafe"),
        200,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "release.tar!/etc/secrets.env");
    assert_eq!(findings[0].commit.as_deref(), Some("cafe"));
}

#[test]
fn a_gzipped_file_is_read_under_the_archive_that_held_it() {
    // `prod.env.gz` is usually committed next to a `prod.env`. Reporting the
    // compressed copy under the plain name gave the two the same path, line
    // and value, which is exactly the key the scan dedups on: one of the two
    // findings was dropped as a repeat of the other.
    let archive = gzip_bytes(credential_line().as_bytes());
    let (findings, _) = scan_blob(
        &archive,
        "config/prod.env.gz",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "config/prod.env.gz!/prod.env");
}

#[test]
fn a_tgz_is_read_as_the_tar_it_is() {
    let archive = gzip_bytes(&tar_bytes(&[("a/b.env", credential_line().as_bytes())]));
    let (findings, _) = scan_blob(
        &archive,
        "bundle.tgz",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "bundle.tgz!/a/b.env");
}

#[test]
fn a_member_at_the_root_of_a_tar_keeps_the_name_its_bar_is_read_from() {
    // A value this short is a credential in a `.env` and noise anywhere else.
    // Joining the member straight onto the archive spelled the first member
    // `backup.tar!.env`, a name no rule recognises, so the stricter bar a
    // credential file earns was never applied to it.
    let short = short_high_signal_line();
    let archive = tar_bytes(&[
        (".env", short.as_bytes()),
        ("settings.ini", short.as_bytes()),
    ]);
    let (findings, _) = scan_blob(
        &archive,
        "backup.tar",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "backup.tar!/.env");
    assert_eq!(findings[0].rule_id, "credential-assignment");
}

#[test]
fn a_binary_member_is_left_undecoded_like_a_binary_file() {
    let mut member = credential_line().into_bytes();
    member.push(0);
    let archive = tar_bytes(&[("assets/logo.png", member.as_slice())]);
    let (findings, _) = scan_blob(
        &archive,
        "assets.tar",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert!(findings.is_empty());
}

#[test]
fn every_member_of_an_archive_is_read_not_only_the_first() {
    let member = credential_line();
    let archive = tar_bytes(&[
        ("one.env", member.as_bytes()),
        ("two/also.env", member.as_bytes()),
    ]);
    let (findings, _) = scan_blob(
        &archive,
        "both.tar",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    let mut paths: Vec<&str> = findings.iter().map(|f| f.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(paths, vec!["both.tar!/one.env", "both.tar!/two/also.env"]);
}

#[test]
fn the_finding_budget_stops_the_member_walk() {
    let member = credential_line();
    let archive = tar_bytes(&[
        ("one.env", member.as_bytes()),
        ("two.env", member.as_bytes()),
        ("three.env", member.as_bytes()),
    ]);
    let (findings, _) = scan_blob(
        &archive,
        "three.tar",
        "working_tree",
        None,
        2,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 2);
}

#[test]
fn a_member_named_twice_does_not_spend_the_budget_meant_for_another() {
    // Nothing stops a tar naming one member five hundred times. Every copy
    // produces the finding the first one did, which the scan later collapses
    // — after the budget that would have carried the archive's other
    // credential was spent on repeats of this one.
    let repeated = credential_line();
    let other = other_credential_line();
    let archive = tar_bytes(&[
        ("dup.env", repeated.as_bytes()),
        ("dup.env", repeated.as_bytes()),
        ("other.env", other.as_bytes()),
    ]);
    let (findings, _) = scan_blob(
        &archive,
        "repeats.tar",
        "working_tree",
        None,
        2,
        ByteBudget::unbounded(),
    );
    let mut paths: Vec<&str> = findings.iter().map(|f| f.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        vec!["repeats.tar!/dup.env", "repeats.tar!/other.env"]
    );
}

#[test]
fn a_member_too_large_to_be_a_credential_file_is_skipped() {
    let mut member = credential_line().into_bytes();
    member.resize(MAX_MEMBER_BYTES as usize + 1, b'.');
    let archive = tar_bytes(&[("huge.env", member.as_slice())]);
    let (findings, scanned) = scan_blob(
        &archive,
        "huge.tar",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert!(findings.is_empty());
    assert_eq!(scanned, 0);
}

#[test]
fn a_member_past_the_callers_own_file_cap_is_skipped() {
    // The caller refuses to read a file larger than its per-file cap, and a
    // member is a file. This module's own cap is the larger of the two here,
    // so only the caller's can be what stops the read.
    let member = credential_line();
    let archive = tar_bytes(&[("small.env", member.as_bytes())]);
    let (findings, scanned) = scan_blob(
        &archive,
        "capped.tar",
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
    // The caller weighed the archive's compressed length before handing it
    // over; its members are larger than that and are what the scan actually
    // reads. Without the caller's remaining allowance, one archive could
    // spend megabytes the scan had already promised to the files after it.
    let member = credential_line();
    let archive = tar_bytes(&[("small.env", member.as_bytes())]);
    let (findings, scanned) = scan_blob(
        &archive,
        "tight.tar",
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
fn a_stream_that_expands_far_past_its_own_size_is_not_inflated() {
    // A gzip bomb's shape: a small stream claiming a large expansion. The
    // ratio cap is spent on the decoder rather than tested after it, so the
    // refusal costs the few hundred kilobytes the stream's own size allows
    // rather than the absolute cap's worth of held memory.
    let bomb = gzip_bytes(&vec![b'0'; 4 * 1024 * 1024]);
    assert!(bomb.len() * MAX_EXPANSION_RATIO < 4 * 1024 * 1024);
    let (findings, scanned) = scan_blob(
        &bomb,
        "bomb.gz",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert!(findings.is_empty());
    assert_eq!(scanned, 0);
    // The absolute cap is the other half of the same defence.
    assert!(MAX_TOTAL_BYTES < u32::MAX as usize);
}

#[test]
fn a_second_gzip_stream_written_after_the_first_is_still_read() {
    // `gzip` writes one stream per input and concatenates them. A decoder
    // that stops at the first member reads the head of such a file and calls
    // the rest of it absent.
    let mut archive = gzip_bytes(b"nothing to see here\n");
    archive.extend_from_slice(&gzip_bytes(credential_line().as_bytes()));
    let (findings, _) = scan_blob(
        &archive,
        "notes.txt.gz",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "notes.txt.gz!/notes.txt");
}

#[test]
fn a_member_naming_itself_with_the_separator_is_still_read() {
    // The separator opens a path segment, so a member carrying the separator
    // character alone is still unambiguous — and refusing to read it skipped
    // a credential for the sake of a name.
    let archive = tar_bytes(&[("we!rd.env", credential_line().as_bytes())]);
    let (findings, _) = scan_blob(
        &archive,
        "odd.tar",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "odd.tar!/we!rd.env");
}

#[test]
fn a_backslash_in_a_member_name_is_left_as_the_character_it_is() {
    // On the archive format's own terms a backslash is an ordinary character
    // in a filename, not a separator. Rewriting it gave `a\b.env` and
    // `a/b.env` the same reported path.
    let archive = tar_bytes(&[("a\\b.env", credential_line().as_bytes())]);
    let (findings, _) = scan_blob(
        &archive,
        "slash.tar",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "slash.tar!/a\\b.env");
}

#[test]
fn a_binary_file_that_is_not_an_archive_is_still_skipped() {
    let (findings, scanned) = scan_blob(
        b"\0not an archive",
        "blob.bin",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
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
    let (findings, _) = scan_blob(
        truncated,
        "cut.tar",
        "working_tree",
        None,
        200,
        ByteBudget::unbounded(),
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path, "cut.tar!/one.env");
}
