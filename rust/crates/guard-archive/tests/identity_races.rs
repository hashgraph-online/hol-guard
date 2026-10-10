//! Blob identity, path handling, and mutation races.
//!
//! The inspector reads one descriptor several times. Its halt predicate is
//! polled between every read, which makes it a deterministic race-injection
//! point: a test closure can rewrite the blob (or swap its path) at exactly
//! the Nth poll. The schedules below are exhaustive over every poll, so a
//! mutation cannot hide in a gap between reads.
#![cfg(unix)]

mod common;

use std::cell::Cell;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{symlink as fs_symlink, PermissionsExt};
use std::path::Path;

use common::*;
use guard_archive::{ArchiveOutcome, ArchiveStatus};

/// Rewrite the bytes behind `path` in place (same inode, so an already-open
/// descriptor observes the change), leaving the blob read-only again.
fn overwrite(path: &Path, bytes: &[u8]) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .expect("open for rewrite");
    file.write_all(bytes).expect("rewrite");
    drop(file);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).expect("rechmod");
}

/// Number of halt polls an unmolested inspection makes.
fn poll_count(bytes: &[u8]) -> usize {
    let blob = write_blob(bytes);
    let polls = Cell::new(0usize);
    let outcome = blob.inspect_with_halt(&caps(), &|| {
        polls.set(polls.get() + 1);
        false
    });
    assert!(
        matches!(
            outcome.status,
            ArchiveStatus::Clean | ArchiveStatus::Blocked
        ),
        "{outcome:?}"
    );
    polls.get()
}

/// Run an inspection where the blob holds `shown` from poll `mutate_at` up to
/// (not including) poll `restore_at`, then holds `original` again.
fn flicker(
    original: &[u8],
    shown: &[u8],
    mutate_at: usize,
    restore_at: Option<usize>,
) -> ArchiveOutcome {
    let blob = write_blob(original);
    let polls = Cell::new(0usize);
    let path = blob.path.clone();
    blob.inspect_with_halt(&caps(), &|| {
        let index = polls.get();
        polls.set(index + 1);
        if index == mutate_at {
            overwrite(&path, shown);
        } else if Some(index) == restore_at {
            overwrite(&path, original);
        }
        false
    })
}

fn malicious_originals() -> Vec<(&'static str, Vec<u8>, &'static str)> {
    // Same-length benign twin so a size check cannot be the thing that saves us.
    let slip = archive(&[file("../escape.sh", b"echo owned")]);
    let benign_twin = archive(&[file("..-escape.sh", b"echo owned")]);
    assert_eq!(slip.len(), benign_twin.len());
    let install = archive(&[package_json_member(
        br#"{"name":"x","scripts":{"postinstall":"x"}}"#,
    )]);
    let quiet = archive(&[package_json_member(
        br#"{"name":"x","scripts":{"postinstal_":"x"}}"#,
    )]);
    assert_eq!(install.len(), quiet.len());
    vec![
        ("zip-slip", slip, "tarball_zip_slip"),
        ("install-script", install, "tarball_install_script"),
        ("benign-twin-of-slip", benign_twin, ""),
        ("benign-twin-of-install", quiet, ""),
    ]
}

#[test]
fn a_blob_that_flickers_between_passes_is_never_clean() {
    // The flicker: policy passes see benign bytes, the digest passes see the
    // original malicious bytes. Every (mutate, restore) poll pair is tried.
    let cases = malicious_originals();
    let mut schedules = 0usize;
    for (label, original, code) in cases.iter().filter(|case| !case.2.is_empty()) {
        let twin = if *label == "zip-slip" {
            &cases[2].1
        } else {
            &cases[3].1
        };
        let polls = poll_count(original);
        assert!(
            polls >= 6,
            "{label}: only {polls} polls; the schedule space is too small"
        );
        for mutate_at in 0..polls {
            for restore_at in (mutate_at + 1..=polls + 1)
                .map(Some)
                .chain(std::iter::once(None))
            {
                let outcome = flicker(original, twin, mutate_at, restore_at);
                schedules += 1;
                assert!(
                    outcome.status != ArchiveStatus::Clean,
                    "{label}: Clean with mutate_at={mutate_at} restore_at={restore_at:?}"
                );
                // Either the original's own verdict, or a refusal because the
                // bytes the pass consumed were not the bound bytes.
                assert!(
                    outcome.code == *code
                        || outcome.code == "external_archive_digest_mismatch"
                        || outcome.code == "external_archive_inspection_incomplete",
                    "{label}: unexpected {outcome:?}"
                );
            }
        }
    }
    eprintln!("{schedules} flicker schedules, none Clean");
}

#[test]
fn flicker_across_multi_chunk_streams_is_never_clean() {
    // Large enough that every pass spans several 64 KiB reads, so mutations
    // land between chunks of the same pass, not only between passes.
    let filler: Vec<u8> = (0..140_000usize).map(|i| (i * 31 % 251) as u8).collect();
    let original = archive(&[file("a/filler.bin", &filler), file("../escape", b"x")]);
    let mut twin = archive(&[file("a/filler.bin", &filler), file("..-escape", b"x")]);
    twin.resize(original.len(), 0);
    let polls = poll_count(&original);
    assert!(polls >= 12, "only {polls} polls");
    let points: Vec<usize> = (0..polls).step_by((polls / 10).max(1)).collect();
    for &mutate_at in &points {
        for restore_at in points
            .iter()
            .filter(|&&point| point > mutate_at)
            .map(|&point| Some(point))
            .chain([None])
        {
            let outcome = flicker(&original, &twin, mutate_at, restore_at);
            assert!(
                outcome.status != ArchiveStatus::Clean,
                "Clean with mutate_at={mutate_at} restore_at={restore_at:?}: {outcome:?}"
            );
        }
    }
}

#[test]
fn a_gzip_expansion_bomb_hidden_from_the_preflight_is_never_clean() {
    // Original: expands far past the ratio cap. The twin: a tiny valid gzip.
    // If the preflight saw the twin, the bomb would reach the parse pass.
    let original = gz_repeat(&file("a", b"x"), 0, 8 * MIB);
    let twin = gz(&archive(&[file("a", b"x")]));
    let polls = poll_count_blocked(&original);
    let points: Vec<usize> = (0..polls).step_by((polls / 12).max(1)).collect();
    for &mutate_at in &points {
        for restore_at in points
            .iter()
            .filter(|&&point| point > mutate_at)
            .map(|&point| Some(point))
            .chain([None])
        {
            let outcome = flicker(&original, &twin, mutate_at, restore_at);
            assert!(
                outcome.status != ArchiveStatus::Clean,
                "bomb Clean with mutate_at={mutate_at} restore_at={restore_at:?}: {outcome:?}"
            );
        }
    }
}

fn poll_count_blocked(bytes: &[u8]) -> usize {
    let blob = write_blob(bytes);
    let polls = Cell::new(0usize);
    let outcome = blob.inspect_with_halt(&caps(), &|| {
        polls.set(polls.get() + 1);
        false
    });
    assert_eq!(outcome.status, ArchiveStatus::Blocked, "{outcome:?}");
    polls.get()
}

#[test]
fn rewriting_the_blob_during_inspection_is_never_clean() {
    let original = archive(&[file("package/index.js", b"module.exports = 1;\n")]);
    let polls = poll_count(&original);
    let mut replacements: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("longer", [original.clone(), vec![b'z'; 4096]].concat()),
        ("shorter", original[..original.len() - 700].to_vec()),
        ("garbage", vec![0xa5; original.len()]),
    ];
    let mut head_flip = original.clone();
    head_flip[0] ^= 0x01;
    replacements.push(("first-byte-flip", head_flip));
    let mut tail_flip = original.clone();
    let last = tail_flip.len() - 1;
    tail_flip[last] ^= 0x01;
    replacements.push(("last-byte-flip", tail_flip));
    let baseline = write_blob(&original).inspect(&caps());
    assert_eq!(baseline.status, ArchiveStatus::Clean);
    let mut late_clean = 0usize;
    for (label, shown) in &replacements {
        for mutate_at in 0..polls {
            let outcome = flicker(&original, shown, mutate_at, None);
            if outcome.status == ArchiveStatus::Clean {
                // Clean is only acceptable when every pass consumed exactly
                // the bound bytes (the mutation landed after the last read of
                // the last pass): the result must equal the unmolested run.
                assert_eq!(outcome, baseline, "{label}: mutate_at={mutate_at}");
                late_clean += 1;
            }
        }
    }
    eprintln!(
        "{late_clean} late-mutation clean schedules of {}",
        replacements.len() * polls
    );
}

#[test]
fn a_blob_grown_past_the_cap_mid_hash_is_never_clean() {
    let original = archive(&[file("a", b"x")]);
    let mut limit = caps();
    limit.max_archive_bytes = 64 * KIB;
    let blob = write_blob(&original);
    let path = blob.path.clone();
    let polls = Cell::new(0usize);
    let outcome = blob.inspect_with_halt(&limit, &|| {
        polls.set(polls.get() + 1);
        if polls.get() == 1 {
            overwrite(&path, &vec![b'g'; 8 * MIB as usize]);
        }
        false
    });
    assert_ne!(outcome.status, ArchiveStatus::Clean, "{outcome:?}");
}

#[test]
fn mutation_before_inspection_is_a_digest_mismatch() {
    let original = archive(&[file("a", b"x")]);
    let blob = write_blob(&original);
    overwrite(&blob.path, &archive(&[file("b", b"y")]));
    let outcome = blob.inspect(&caps());
    assert_outcome(&outcome, "blocked", "external_archive_digest_mismatch");
}

#[test]
fn mutation_after_inspection_does_not_change_the_reported_identity() {
    let original = archive(&[file("a", b"x")]);
    let blob = write_blob(&original);
    let outcome = blob.inspect(&caps());
    assert_outcome(&outcome, "clean", "external_archive_inspection_clean");
    assert_eq!(outcome.sha256.as_deref(), Some(blob.sha256.as_str()));
    overwrite(&blob.path, &archive(&[file("../escape", b"y")]));
    // The recorded identity still names the inspected bytes, and a second
    // inspection against the same binding refuses the new content.
    assert_eq!(
        outcome.sha256.as_deref(),
        Some(sha256_hex(&original).as_str())
    );
    assert_outcome(
        &blob.inspect(&caps()),
        "blocked",
        "external_archive_digest_mismatch",
    );
}

// ----------------------------------------------------------- path handling

fn clean_blob_bytes() -> Vec<u8> {
    archive(&[file("package/index.js", b"module.exports = 1;\n")])
}

#[test]
fn swapping_the_path_after_open_does_not_redirect_inspection() {
    let original = clean_blob_bytes();
    let blob = write_blob(&original);
    let evil = archive(&[file("../escape", b"x")]);
    let path = blob.path.clone();
    let moved = blob.dir.join("moved.tar");
    let polls = Cell::new(0usize);
    let outcome = blob.inspect_with_halt(&caps(), &|| {
        polls.set(polls.get() + 1);
        if polls.get() == 3 {
            std::fs::rename(&path, &moved).expect("move blob away");
            std::fs::write(&path, &evil).expect("plant replacement");
        }
        false
    });
    // The descriptor, not the name, is what was inspected.
    assert_outcome(&outcome, "clean", "external_archive_inspection_clean");
    assert_eq!(
        outcome.sha256.as_deref(),
        Some(sha256_hex(&original).as_str())
    );
}

#[test]
fn replacing_the_leaf_with_a_symlink_after_open_does_not_redirect_inspection() {
    let original = clean_blob_bytes();
    let blob = write_blob(&original);
    let target = blob.dir.join("elsewhere.tar");
    std::fs::write(&target, archive(&[file("../escape", b"x")])).expect("write target");
    let path = blob.path.clone();
    let polls = Cell::new(0usize);
    let outcome = blob.inspect_with_halt(&caps(), &|| {
        polls.set(polls.get() + 1);
        if polls.get() == 2 {
            std::fs::remove_file(&path).expect("unlink");
            fs_symlink(&target, &path).expect("plant symlink");
        }
        false
    });
    assert_outcome(&outcome, "clean", "external_archive_inspection_clean");
}

#[test]
fn replacing_the_parent_directory_after_open_does_not_redirect_inspection() {
    let original = clean_blob_bytes();
    let blob = write_blob(&original);
    let parent = blob.dir.clone();
    let decoy = unique_dir("decoy");
    std::fs::write(decoy.join("blob.tar"), archive(&[file("../escape", b"x")])).expect("decoy");
    let parked = parent.with_extension("parked");
    let polls = Cell::new(0usize);
    let outcome = blob.inspect_with_halt(&caps(), &|| {
        polls.set(polls.get() + 1);
        if polls.get() == 2 {
            std::fs::rename(&parent, &parked).expect("park parent");
            fs_symlink(&decoy, &parent).expect("symlink parent");
        }
        false
    });
    // Put everything back so `Blob::drop` cleans the right directory.
    std::fs::remove_file(&parent).ok();
    std::fs::rename(&parked, &parent).ok();
    std::fs::remove_dir_all(&decoy).ok();
    assert_outcome(&outcome, "clean", "external_archive_inspection_clean");
}

#[test]
fn symlinked_ancestor_directories_are_accepted() {
    // Root aliases (`/tmp` -> `/private/tmp`, `/var` -> `/private/var`) must
    // keep working: only the leaf may not be a link.
    let bytes = clean_blob_bytes();
    let real = unique_dir("real");
    let blob_path = real.join("blob.tar");
    std::fs::write(&blob_path, &bytes).unwrap();
    std::fs::set_permissions(&blob_path, std::fs::Permissions::from_mode(0o444)).unwrap();
    let alias_root = unique_dir("alias");
    let first = alias_root.join("first");
    let second = alias_root.join("second");
    fs_symlink(&real, &first).unwrap();
    fs_symlink(&first, &second).unwrap();
    for path in [first.join("blob.tar"), second.join("blob.tar")] {
        let outcome = guard_archive::inspect_path(
            &path,
            &sha256_hex(&bytes),
            &caps(),
            std::time::Instant::now() + std::time::Duration::from_secs(30),
            &|| false,
        );
        assert_outcome(&outcome, "clean", "external_archive_inspection_clean");
    }
    std::fs::set_permissions(&blob_path, std::fs::Permissions::from_mode(0o644)).ok();
    std::fs::remove_dir_all(&alias_root).ok();
    std::fs::remove_dir_all(&real).ok();
}

fn inspect_path_with(path: &Path, sha: &str) -> ArchiveOutcome {
    guard_archive::inspect_path(
        path,
        sha,
        &caps(),
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        &|| false,
    )
}

#[test]
fn leaf_symlinks_roots_and_non_regular_paths_are_refused() {
    let bytes = clean_blob_bytes();
    let blob = write_blob(&bytes);
    let link = blob.dir.join("link.tar");
    fs_symlink(&blob.path, &link).unwrap();
    assert_outcome(
        &inspect_path_with(&link, &blob.sha256),
        "blocked",
        "external_archive_blob_rejected",
    );
    for path in [Path::new("/"), blob.dir.as_path(), Path::new("/dev/null")] {
        let outcome = inspect_path_with(path, &blob.sha256);
        assert_ne!(
            outcome.status,
            ArchiveStatus::Clean,
            "{path:?}: {outcome:?}"
        );
    }
    for path in [
        Path::new(""),
        Path::new("relative/blob.tar"),
        Path::new("/nonexistent/blob.tar"),
    ] {
        let outcome = inspect_path_with(path, &blob.sha256);
        assert_ne!(
            outcome.status,
            ArchiveStatus::Clean,
            "{path:?}: {outcome:?}"
        );
    }
}

#[test]
fn trailing_components_that_alias_the_leaf_are_refused() {
    let bytes = clean_blob_bytes();
    let blob = write_blob(&bytes);
    let sneaky = blob.dir.join("blob.tar").join(".");
    let outcome = inspect_path_with(&sneaky, &blob.sha256);
    assert_ne!(outcome.status, ArchiveStatus::Clean, "{outcome:?}");
    let parent_hop = blob
        .dir
        .join("..")
        .join(blob.dir.file_name().unwrap())
        .join("blob.tar");
    // `..` hops resolve to the same regular file; that is an accepted root
    // alias, not a bypass, because the leaf is still checked.
    let outcome = inspect_path_with(&parent_hop, &blob.sha256);
    assert!(matches!(
        outcome.status,
        ArchiveStatus::Clean | ArchiveStatus::Incomplete | ArchiveStatus::Blocked
    ));
}
