//! After a reboot a recorded daemon pid can be the id of a thread in an
//! unrelated program. Linux answers a signal probe for that id, so the probe
//! alone would keep calling the old daemon live and block every new start.

use std::fs;
use std::sync::mpsc;

use super::host::{pid_is_proven_dead, pid_is_running};

fn current_thread_id() -> i64 {
    let link = fs::read_link("/proc/thread-self").unwrap();
    link.file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.parse().ok())
        .unwrap()
}

#[test]
fn a_thread_of_another_process_is_not_a_running_daemon() {
    let (sent, received) = mpsc::channel();
    let (release, wait) = mpsc::channel::<()>();
    let worker = std::thread::spawn(move || {
        sent.send(current_thread_id()).unwrap();
        let _ = wait.recv();
    });
    let tid = received.recv().unwrap();
    let own = i64::from(std::process::id());
    assert_ne!(tid, own);
    let probe = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(i32::try_from(tid).unwrap()),
        None,
    );
    assert!(
        probe.is_ok(),
        "the kernel answers a signal probe for a thread id"
    );
    assert!(pid_is_running(own));
    assert!(!pid_is_running(tid));
    assert!(pid_is_proven_dead(tid));
    release.send(()).unwrap();
    worker.join().unwrap();
}
