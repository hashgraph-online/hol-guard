use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use super::ManagedReads;

#[test]
fn a_burst_of_hooks_shares_a_few_store_reads() {
    let reads = Arc::new(ManagedReads::new());
    let count = Arc::new(AtomicUsize::new(0));
    let hooks = 256;
    let start = Arc::new(Barrier::new(hooks));
    let handles: Vec<_> = (0..hooks)
        .map(|_| {
            let (reads, count, start) =
                (Arc::clone(&reads), Arc::clone(&count), Arc::clone(&start));
            thread::spawn(move || {
                start.wait();
                let arrived = Instant::now();
                reads.unmanaged("codex", arrived, || {
                    count.fetch_add(1, Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(50));
                    true
                })
            })
        })
        .collect();
    for handle in handles {
        assert!(handle.join().expect("hook thread"));
    }
    // One read for the hooks that arrived first, one for those that arrived
    // while it ran, and at most one more for stragglers past the barrier.
    let reads_run = count.load(Ordering::SeqCst);
    assert!(reads_run <= 3, "{reads_run} store reads for {hooks} hooks");
}

#[test]
fn a_hook_after_a_read_finished_reads_the_store_again() {
    let reads = ManagedReads::new();
    assert!(!reads.unmanaged("codex", Instant::now(), || false));
    // The install changed after that read; a later hook must see it.
    assert!(reads.unmanaged("codex", Instant::now(), || true));
}

#[test]
fn a_hook_reuses_a_read_that_began_after_it_arrived() {
    let reads = ManagedReads::new();
    let arrived = Instant::now();
    thread::sleep(Duration::from_millis(2));
    assert!(reads.unmanaged("codex", Instant::now(), || true));
    assert!(reads.unmanaged("codex", arrived, || panic!("must reuse the newer read")));
}

#[test]
fn apps_keep_their_own_reads() {
    let reads = ManagedReads::new();
    let arrived = Instant::now();
    assert!(reads.unmanaged("codex", arrived, || true));
    assert!(!reads.unmanaged("cursor", arrived, || false));
}
