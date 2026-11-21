#[cfg(unix)]
use super::publish_without_replacing;
use super::{create_final_key, provision_verifier_key, VerifierKeyProvision};
use guard_policy_snapshot::derive_verifier_key;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::time::Duration;
use tempfile::TempDir;

/// A state directory only this test can name, removed however the test ends.
///
/// A process id and a counter both repeat across runs, so a directory a
/// failed assertion left behind could be read as a later run's own state and
/// turn a `Created` into a `Verified` or a key mismatch. Keep the handle
/// alive for the whole test: dropping it removes the directory.
fn root() -> (TempDir, PathBuf) {
    let holder = TempDir::new().unwrap();
    // Provisioning creates its own state base, so name one that is not there.
    let state_base = holder.path().join("state");
    (holder, state_base)
}

fn key_path(state_base: &std::path::Path) -> PathBuf {
    state_base.join("policy-verifier.key")
}

#[test]
fn provisioning_writes_the_derived_key_once() {
    let (_root, state_base) = root();
    let master = [7u8; 32];
    assert_eq!(
        provision_verifier_key(&state_base, &master),
        Ok(VerifierKeyProvision::Created)
    );
    let written = fs::read(key_path(&state_base)).unwrap();
    assert_eq!(written, derive_verifier_key(&master).to_vec());
    // The master itself must never reach the filesystem.
    assert_ne!(written, master.to_vec());
    assert_eq!(
        provision_verifier_key(&state_base, &master),
        Ok(VerifierKeyProvision::Verified)
    );
}

#[test]
fn provisioning_leaves_no_temporary_behind() {
    let (_root, state_base) = root();
    provision_verifier_key(&state_base, &[9u8; 32]).unwrap();
    let names: Vec<String> = fs::read_dir(&state_base)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["policy-verifier.key".to_owned()]);
}

#[test]
fn a_changed_master_never_replaces_the_existing_key() {
    let (_root, state_base) = root();
    let first = [1u8; 32];
    provision_verifier_key(&state_base, &first).unwrap();
    assert_eq!(
        provision_verifier_key(&state_base, &[2u8; 32]),
        Err("native_policy_verifier_key_mismatch".to_owned())
    );
    // The original key survives a rejected master.
    assert_eq!(
        fs::read(key_path(&state_base)).unwrap(),
        derive_verifier_key(&first).to_vec()
    );
}

#[test]
fn a_master_of_the_wrong_length_is_refused_before_any_write() {
    let (_root, state_base) = root();
    assert_eq!(
        provision_verifier_key(&state_base, &[3u8; 16]),
        Err("native_policy_verifier_master_invalid".to_owned())
    );
    assert!(!state_base.exists());
}

#[test]
fn an_oversized_key_file_is_reported_without_waiting() {
    let (_root, state_base) = root();
    provision_verifier_key(&state_base, &[4u8; 32]).unwrap();
    // Longer than a key: not a partial write, so no retry window applies.
    fs::write(key_path(&state_base), [5u8; 40]).unwrap();
    assert_eq!(
        provision_verifier_key(&state_base, &[4u8; 32]),
        Err("native_policy_verifier_key_invalid".to_owned())
    );
}

#[test]
fn a_create_failure_with_no_key_present_reports_the_write_failure() {
    let (_root, state_base) = root();
    // Nothing exists under this parent, so the exclusive create fails and
    // leaves nothing behind. Confirming a key here would answer a write
    // failure with "no key", which reads as a missing install.
    let path = state_base.join("gone").join("policy-verifier.key");
    assert_eq!(
        create_final_key(
            &state_base,
            &path,
            &derive_verifier_key(&[8u8; 32]),
            &state_base
        ),
        Err("native_resident_state_write_failed".to_owned())
    );
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn a_link_failure_that_is_not_missing_link_support_is_reported() {
    // Windows publishes through `publish_new_windows_private_file`, which
    // already reports every error it gets. Only the Unix link arm can mistake
    // a one-off failure for a filesystem that cannot link at all, and then
    // create the final path on a disk that just refused the write.
    let (_root, state_base) = root();
    fs::create_dir_all(&state_base).unwrap();
    let temporary = state_base.join("policy-verifier.key.tmp");
    fs::write(&temporary, [6u8; 32]).unwrap();
    assert_eq!(
        publish_without_replacing(
            &temporary,
            &state_base.join("gone").join("policy-verifier.key"),
            &state_base
        ),
        Err(Some("native_policy_verifier_key_write_failed".to_owned()))
    );
}

#[test]
fn a_key_that_stays_short_is_reported_as_tampering() {
    let (_root, state_base) = root();
    provision_verifier_key(&state_base, &[10u8; 32]).unwrap();
    // Shorter than a key with no writer behind it: the bounded retry window
    // elapses and the file is answered as invalid rather than rewritten.
    fs::write(key_path(&state_base), [11u8; 5]).unwrap();
    assert_eq!(
        provision_verifier_key(&state_base, &[10u8; 32]),
        Err("native_policy_verifier_key_invalid".to_owned())
    );
    // A key that could not be read is never replaced.
    assert_eq!(fs::read(key_path(&state_base)).unwrap(), vec![11u8; 5]);
}

#[test]
fn a_short_key_another_writer_completes_is_confirmed() {
    let (_root, state_base) = root();
    let master = [12u8; 32];
    provision_verifier_key(&state_base, &master).unwrap();
    let path = key_path(&state_base);
    // The shape a provisioner leaves behind on a filesystem without links:
    // the final path exists before the whole key is in it.
    fs::write(&path, [0u8; 5]).unwrap();
    let writer = {
        let path = path.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            // A reader holding the file open can refuse this write on
            // Windows, which is the same contention a real second
            // provisioner meets. Retry inside the reader's own window.
            for attempt in 0..40 {
                if fs::write(&path, derive_verifier_key(&master)).is_ok() {
                    return;
                }
                assert!(attempt < 39, "the key was never completed");
                std::thread::sleep(Duration::from_millis(25));
            }
        })
    };
    assert_eq!(
        provision_verifier_key(&state_base, &master),
        Ok(VerifierKeyProvision::Verified)
    );
    writer.join().unwrap();
}

#[test]
fn concurrent_provisioners_publish_one_key() {
    let (_root, state_base) = root();
    let master = [13u8; 32];
    let start = Arc::new(Barrier::new(16));
    // Every thread is spawned before any is joined: a lazily joined iterator
    // would run them one at a time and never reach the barrier.
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let state_base = state_base.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                provision_verifier_key(&state_base, &master)
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();

    // Exactly one call publishes; every other one reads what it published
    // instead of writing a second key over it.
    let created = results
        .iter()
        .filter(|result| **result == Ok(VerifierKeyProvision::Created))
        .count();
    assert_eq!(created, 1, "{results:?}");
    for result in &results {
        assert!(result.is_ok(), "{results:?}");
    }
    assert_eq!(
        fs::read(key_path(&state_base)).unwrap(),
        derive_verifier_key(&master).to_vec()
    );
    // No provisioner leaves its temporary behind, however it lost the race.
    let names: Vec<String> = fs::read_dir(&state_base)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["policy-verifier.key".to_owned()]);
}
