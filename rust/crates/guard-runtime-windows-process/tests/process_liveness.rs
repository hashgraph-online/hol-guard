#![cfg(windows)]

use guard_runtime_windows_process::process_liveness;

#[test]
fn process_liveness_matches_windows_process_liveness() {
    assert_eq!(process_liveness(std::process::id()), Some(true));
    let mut child = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "exit 0"])
        .spawn()
        .unwrap();
    let pid = child.id();
    assert!(child.wait().unwrap().success());
    // The child's handle is still open, so the pid names its signaled
    // process object rather than a reused one.
    assert_eq!(process_liveness(pid), Some(false));
    drop(child);
    // PID 0 is the System Idle Process, which Python reads as not running.
    assert_eq!(process_liveness(0), Some(false));
}
