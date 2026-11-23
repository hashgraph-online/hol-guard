use super::*;
use std::sync::atomic::AtomicUsize;

#[test]
fn watcher_samples_fingerprint_after_observed_lock() {
    let unique = crate::unique_nanos::unique_nanos();
    let path = std::env::temp_dir().join(format!(
        "hol-guard-authority-watch-{}-{unique}.json",
        std::process::id()
    ));
    fs::write(&path, b"old-authority").unwrap();

    let observed = Arc::new(Mutex::new(authority_fingerprint(&path)));
    let changed = Arc::new(AtomicBool::new(false));
    let samples = Arc::new(AtomicUsize::new(0));
    let hook_samples = Arc::clone(&samples);
    let (sampled_tx, sampled_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    start_authority_watcher_with_sample_hook(
        path.clone(),
        Arc::clone(&observed),
        Arc::downgrade(&changed),
        move || {
            let sample = hook_samples.fetch_add(1, Ordering::SeqCst) + 1;
            let _ = sampled_tx.send(sample);
            if sample == 1 {
                resume_rx.recv().unwrap();
            }
        },
    );

    assert_eq!(sampled_rx.recv().unwrap(), 1);
    assert!(matches!(
        observed.try_lock(),
        Err(std::sync::TryLockError::WouldBlock)
    ));
    resume_tx.send(()).unwrap();

    let sample_floor = {
        let mut expected = observed.lock().unwrap();
        fs::write(&path, b"new-authority").unwrap();
        *expected = authority_fingerprint(&path);
        changed.store(false, Ordering::SeqCst);
        samples.load(Ordering::SeqCst)
    };
    while sampled_rx.recv().unwrap() <= sample_floor {}
    drop(observed.lock().unwrap());
    assert!(!changed.load(Ordering::SeqCst));

    drop(changed);
    let _ = fs::remove_file(path);
}

#[test]
fn authority_check_samples_fingerprint_after_observed_lock() {
    let unique = crate::unique_nanos::unique_nanos();
    let path = std::env::temp_dir().join(format!(
        "hol-guard-authority-check-{}-{unique}.json",
        std::process::id()
    ));
    fs::write(&path, b"old-authority").unwrap();
    let observed = Arc::new(Mutex::new(authority_fingerprint(&path)));

    // A push holds the record while it replaces the file.
    let mut record = observed.lock().unwrap();
    let (sampled_tx, sampled_rx) = std::sync::mpsc::channel();
    let check = {
        let observed = Arc::clone(&observed);
        let path = path.clone();
        std::thread::spawn(move || {
            sampled_under_lock(&observed, || {
                let _ = sampled_tx.send(());
                authority_fingerprint(&path)
            })
        })
    };
    // Sampling now would pair the old file with the record the push is
    // about to write.
    assert!(sampled_rx
        .recv_timeout(std::time::Duration::from_millis(100))
        .is_err());
    fs::write(&path, b"replacement-authority").unwrap();
    *record = authority_fingerprint(&path);
    drop(record);

    assert!(check.join().unwrap());
    assert!(sampled_rx.recv().is_ok());
    let _ = fs::remove_file(&path);
}
