use super::*;
use std::sync::atomic::AtomicUsize;

#[test]
fn watcher_samples_fingerprint_after_observed_lock() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
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
