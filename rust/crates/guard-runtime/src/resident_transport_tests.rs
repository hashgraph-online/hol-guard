use super::*;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

struct NullStream;

impl Read for NullStream {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

impl Write for NullStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ResidentStream for NullStream {
    fn set_resident_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_resident_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_resident_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn admit_connection_does_not_block_accept_on_full_auth_queue() {
    let (primary, primary_rx) = sync_channel(1);
    primary
        .try_send(Box::new(NullStream) as BoxedResidentStream)
        .expect("seed occupancy");
    let overflow_primary = primary.clone();
    let (overflow, overflow_rx) = sync_channel(1);
    thread::spawn(move || retry_overflow_admissions(overflow_primary, overflow_rx));
    let admission = ResidentAdmission {
        primary,
        overflow,
        workers: Vec::new(),
    };
    let started = Instant::now();
    admit_connection(&admission, Box::new(NullStream)).expect("overflow handoff");
    assert!(
        started.elapsed() < Duration::from_millis(20),
        "accept must keep moving when auth workers are busy"
    );
    let worker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(30));
        let occupied = primary_rx.recv().expect("drain occupancy");
        let admitted = primary_rx.recv().expect("overflow retry");
        (occupied, admitted)
    });
    drop(worker.join().expect("overflow delivered"));
    drop(admission);
}

#[test]
fn spawn_workers_run_queued_jobs_in_parallel() {
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (sender, receiver) = sync_channel(4);
    spawn_workers(4, receiver, {
        let started = Arc::clone(&started);
        move |_item: u8| {
            started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            while started.load(std::sync::atomic::Ordering::SeqCst) < 4 {
                thread::sleep(Duration::from_millis(1));
            }
            thread::sleep(Duration::from_millis(40));
        }
    });
    let started_at = Instant::now();
    for _ in 0..4 {
        sender.send(1).expect("enqueue parallel job");
    }
    drop(sender);
    let deadline = Instant::now() + Duration::from_millis(400);
    while started.load(std::sync::atomic::Ordering::SeqCst) < 4 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 4);
    while started_at.elapsed() < Duration::from_millis(40) {
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        started_at.elapsed() < Duration::from_millis(160),
        "queued auth/eval work must overlap instead of running one job at a time"
    );
}
