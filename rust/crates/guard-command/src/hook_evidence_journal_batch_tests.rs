//! Durable batch ordering, selective removal and failure rollback on real files.

use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn batch_append_and_settlement_preserve_order_privacy_and_unsettled_previews() {
    let home = TempDir::new("batch-roundtrip");
    let path = home.journal();
    let journal = journal();
    let records = [
        activity("first", Some("git status")),
        activity("middle", Some("ls -al")),
        activity("last", None),
    ];
    assert!(journal
        .append_journal_batch(&path, &records.iter().collect::<Vec<_>>())
        .iter()
        .all(Result::is_ok));
    let (recovered, invalid) = journal.recover_journal_records(&path, MAX_BYTES).unwrap();
    assert_eq!(invalid, 0);
    assert_eq!(
        recovered
            .iter()
            .map(|v| v["record_id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["first", "middle", "last"]
    );
    assert!(!fs::read_to_string(&path).unwrap().contains("git status"));
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        journal
            .rewrite_journal_batch(&path, &["first".to_owned(), "last".to_owned()], MAX_BYTES)
            .unwrap(),
        0
    );
    let (recovered, invalid) = journal.recover_journal_records(&path, MAX_BYTES).unwrap();
    assert_eq!(invalid, 0);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0]["record_id"], "middle");
    assert_eq!(recovered[0]["invocation_preview"], "ls -al");
    journal
        .rewrite_journal_batch(&path, &["middle".to_owned()], MAX_BYTES)
        .unwrap();
    assert!(!preview_sidecar_path(&path).exists());
    assert!(fs::read(&path).unwrap().is_empty());
}

#[test]
fn a_failed_final_sync_rolls_back_both_files_to_their_previous_prefixes() {
    let home = TempDir::new("batch-rollback");
    let path = home.journal();
    let journal = journal();
    journal
        .append_journal(&path, &activity("original", Some("git status")))
        .unwrap();
    let before = fs::read(&path).unwrap();
    let sidecar = preview_sidecar_path(&path);
    let preview_before = fs::read(&sidecar).unwrap();
    let next = [activity("next", Some("ls -al")), activity("last", None)];
    let error = journal
        .append_records_then(&path, &next.iter().collect::<Vec<_>>(), |file| {
            assert!(file.metadata().unwrap().len() > before.len() as u64);
            assert!(fs::metadata(&sidecar).unwrap().len() > preview_before.len() as u64);
            Err(io::Error::other("injected final sync failure"))
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "injected final sync failure");
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read(&sidecar).unwrap(), preview_before);
    journal
        .append_journal_batch(&path, &next.iter().collect::<Vec<_>>())
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        journal
            .recover_journal_records(&path, MAX_BYTES)
            .unwrap()
            .0
            .len(),
        3
    );
}

#[test]
fn an_unsafe_preview_destination_refuses_the_entire_batch_before_append() {
    let home = TempDir::new("batch-unsafe-preview");
    let path = home.journal();
    let journal = journal();
    journal
        .append_journal(&path, &activity("original", None))
        .unwrap();
    let before = fs::read(&path).unwrap();
    let outside = home.0.join("synthetic-outside");
    fs::write(&outside, b"unchanged synthetic bytes").unwrap();
    symlink(&outside, preview_sidecar_path(&path)).unwrap();
    let next = [
        activity("without-preview", None),
        activity("with-preview", Some("ls -al")),
    ];
    let outcomes = journal.append_journal_batch(&path, &next.iter().collect::<Vec<_>>());
    assert_eq!(outcomes.len(), 2);
    assert!(outcomes.iter().all(Result::is_err));
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(fs::read(&outside).unwrap(), b"unchanged synthetic bytes");
}

#[test]
fn concurrent_batches_remain_contiguous_under_the_existing_private_lock() {
    let home = TempDir::new("batch-concurrent");
    let path = home.journal();
    let mut threads = Vec::new();
    for label in ["first", "second"] {
        let path = path.clone();
        threads.push(std::thread::spawn(move || {
            let records = (0..25)
                .map(|index| activity(&format!("{label}-{index}"), None))
                .collect::<Vec<_>>();
            journal()
                .append_journal_batch(&path, &records.iter().collect::<Vec<_>>())
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }
    let (records, invalid) = journal().recover_journal_records(&path, MAX_BYTES).unwrap();
    assert_eq!(invalid, 0);
    assert_eq!(records.len(), 50);
    let first = records[0]["record_id"]
        .as_str()
        .unwrap()
        .split('-')
        .next()
        .unwrap();
    for (index, record) in records.iter().take(25).enumerate() {
        assert_eq!(record["record_id"], format!("{first}-{index}"));
    }
    let second = if first == "first" { "second" } else { "first" };
    for (index, record) in records.iter().skip(25).enumerate() {
        assert_eq!(record["record_id"], format!("{second}-{index}"));
    }
}
