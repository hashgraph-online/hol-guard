use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn regular_file_replaced_by_fifo_is_rejected_without_a_writer() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let folder = std::env::temp_dir().join(format!(
        "guard-claude-file-race-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&folder).unwrap();
    fs::set_permissions(&folder, fs::Permissions::from_mode(0o700)).unwrap();
    let path = folder.join("bound-file");
    fs::write(&path, b"immutable original").unwrap();
    let before = fs::symlink_metadata(&path).unwrap();
    fs::remove_file(&path).unwrap();
    nix::unistd::mkfifo(
        &path,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let (send, receive) = mpsc::channel();
    let target = path.clone();
    let worker = std::thread::spawn(move || {
        send.send(open_unchanged(&target, &before).map(|_| ()))
            .unwrap();
    });
    let result = receive.recv_timeout(Duration::from_secs(1));
    // Release a regressed blocking open so a failed test never leaves a worker.
    let unblock = if result.is_err() {
        Some(
            OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&path)
                .unwrap(),
        )
    } else {
        None
    };
    worker.join().unwrap();
    drop(unblock);
    fs::remove_file(&path).unwrap();
    fs::remove_dir(&folder).unwrap();
    assert_eq!(
        result
            .expect("FIFO open blocked waiting for a writer")
            .unwrap_err()
            .value["detail"],
        "claude_pilot_file_changed"
    );
}
