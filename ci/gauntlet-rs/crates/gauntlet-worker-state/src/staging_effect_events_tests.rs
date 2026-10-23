use super::*;

fn event(mask: u64, pidfd: i32) -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&32u32.to_ne_bytes());
    raw.push(libc::FANOTIFY_METADATA_VERSION);
    raw.push(0);
    raw.extend_from_slice(&24u16.to_ne_bytes());
    raw.extend_from_slice(&mask.to_ne_bytes());
    raw.extend_from_slice(&4i32.to_ne_bytes());
    raw.extend_from_slice(&42i32.to_ne_bytes());
    raw.push(libc::FAN_EVENT_INFO_TYPE_PIDFD);
    raw.push(0);
    raw.extend_from_slice(&8u16.to_ne_bytes());
    raw.extend_from_slice(&pidfd.to_ne_bytes());
    raw
}

#[test]
fn parser_refuses_overflow_and_incomplete_identity() {
    assert_eq!(
        parse_event(&event(libc::FAN_CLOSE_WRITE, 5)).unwrap().1.pid,
        42
    );
    assert_eq!(
        parse_event(&event(libc::FAN_CLOSE_WRITE, -1))
            .unwrap()
            .1
            .pidfd,
        -1
    );
    assert!(parse_event(&event(libc::FAN_Q_OVERFLOW, -1)).is_err());
    assert!(parse_event(&event(libc::FAN_MODIFY, 5)).is_err());
    assert!(parse_event(&event(libc::FAN_CLOSE_WRITE, -2)).is_err());
    assert!(parse_event(&event(libc::FAN_CLOSE_WRITE, 5)[..31]).is_err());
}

/// Explicitly invoked only on the dedicated ARM64 VM. Container Root
/// normally lacks CAP_SYS_ADMIN, and this test makes no benchmark claim.
#[test]
#[ignore]
fn root_vm_captures_close_write_inode_and_live_writer() {
    use std::os::unix::fs::MetadataExt;
    let mut monitor = StagingEffectEvents::start(Path::new("/home")).unwrap();
    let directory = tempfile::tempdir_in("/home").unwrap();
    let path = directory.path().join("effect.txt");
    std::fs::write(&path, b"synthetic-effect").unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    for _ in 0..20 {
        monitor.drain().unwrap();
        if monitor
            .events()
            .unwrap()
            .iter()
            .any(|event| event.device == metadata.dev() && event.inode == metadata.ino())
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let mut finished = monitor.finish().unwrap();
    let event = finished
        .events()
        .iter()
        .find(|event| event.device == metadata.dev() && event.inode == metadata.ino())
        .unwrap();
    assert_eq!(event.owner, 0);
    assert_eq!(event.writer.as_ref().unwrap().pid, std::process::id());
    assert!(event.writer.as_ref().unwrap().start_ticks > 0);
    let expected_cgroup = event.writer.as_ref().unwrap().cgroup.clone();
    let held = File::open(&path).unwrap();
    let correlated = finished.correlate_file(&held, &expected_cgroup).unwrap();
    assert_eq!(correlated.close_writes, 1);
    assert_eq!(correlated.writers[0].pid, std::process::id());
    assert!(finished
        .correlate_file(&held, "/system.slice/unrelated.service")
        .is_err());
    finished.events.push(CloseWriteEvent {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: 0,
        file_handle: Some(sample_file_handle(&held).unwrap()),
        reported_pid: 42,
        pidfd_available: false,
        writer: None,
    });
    assert!(finished.correlate_file(&held, &expected_cgroup).is_err());
}
