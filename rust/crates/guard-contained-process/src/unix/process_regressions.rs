use super::*;
use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

const MODE: &str = "HOL_GUARD_UNIX_PROCESS_REGRESSION";
const HIGH_FD: i32 = 2048;
type Hook = Box<dyn FnOnce()>;

thread_local! {
    static BEFORE_FORK: RefCell<Option<Hook>> = RefCell::new(None);
    static INITIALIZED: RefCell<Option<Hook>> = RefCell::new(None);
}

pub(super) fn before_fork() {
    let hook = BEFORE_FORK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

pub(super) fn initialized() {
    let hook = INITIALIZED.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

fn isolated(name: &str, body: impl FnOnce()) {
    if std::env::var(MODE).as_deref() == Ok(name) {
        body();
        return;
    }
    // Descriptor, hard-limit and signal mutations happen in a dedicated exec,
    // never in the shared parallel test harness or its parent standard input.
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env(MODE, name)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("isolated regression timed out: {name}: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{name}: {output:?}");
}

fn shell_command(root: &Path, script: &str) -> PinnedCommand {
    let root = fs::canonicalize(root).unwrap();
    PinnedCommand::new(
        &fs::canonicalize("/bin/sh").unwrap(),
        &[OsStr::new("-c"), OsStr::new(script)],
        &root,
        &[(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))],
    )
    .unwrap()
}

fn self_command(root: &Path, test: &str, mode: &str) -> PinnedCommand {
    let root = fs::canonicalize(root).unwrap();
    PinnedCommand::new(
        &fs::canonicalize(std::env::current_exe().unwrap()).unwrap(),
        &[
            OsStr::new("--exact"),
            OsStr::new(test),
            OsStr::new("--nocapture"),
            OsStr::new("--test-threads=1"),
        ],
        &root,
        &[(OsString::from(MODE), OsString::from(mode))],
    )
    .unwrap()
}

fn assert_not_launched(root: &Path) {
    assert_eq!(
        fs::symlink_metadata(root.join("launched"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotFound,
    );
}

#[test]
fn closed_parent_stdin_delivers_actual_input() {
    isolated(
        "unix::process_regressions::closed_parent_stdin_delivers_actual_input",
        || {
            let root = tempfile::tempdir().unwrap();
            let command = shell_command(root.path(), "IFS= read -r line; printf '<%s>' \"$line\"");
            assert_eq!(unsafe { libc::close(0) }, 0);
            let output = command
                .capture(
                    b"actual input\n",
                    4096,
                    Instant::now() + Duration::from_secs(5),
                    &AtomicBool::new(false),
                    Isolation::default(),
                )
                .unwrap();
            assert_eq!(output.stdout, b"<actual input>");
            assert_eq!(output.exit_code, Some(0));
            assert!(!output.timed_out && !output.cancelled && !output.output_limited);
        },
    );
}

#[test]
fn high_descriptor_is_closed_below_lowered_limits() {
    const NAME: &str = "unix::process_regressions::high_descriptor_is_closed_below_lowered_limits";
    if std::env::var(MODE).as_deref() == Ok("descriptor-probe") {
        assert_eq!(unsafe { libc::fcntl(HIGH_FD, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        return;
    }
    isolated(NAME, || {
        let root = tempfile::tempdir().unwrap();
        let command = self_command(root.path(), NAME, "descriptor-probe");
        let held = fs::File::create(root.path().join("protected-handle")).unwrap();
        let mut limits: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) },
            0
        );
        assert!(limits.rlim_max > HIGH_FD as libc::rlim_t);
        if limits.rlim_cur <= HIGH_FD as libc::rlim_t {
            limits.rlim_cur = HIGH_FD as libc::rlim_t + 1;
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
        }
        let high = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_DUPFD, HIGH_FD) };
        assert_eq!(high, HIGH_FD);
        let _high = unsafe { OwnedFd::from_raw_fd(high) };
        assert_eq!(unsafe { libc::fcntl(high, libc::F_SETFD, 0) }, 0);
        limits.rlim_cur = 128;
        limits.rlim_max = 128;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limits) }, 0);
        let output = command
            .capture(
                b"",
                4096,
                Instant::now() + Duration::from_secs(30),
                &AtomicBool::new(false),
                Isolation::default(),
            )
            .unwrap();
        assert_eq!(output.exit_code, Some(0), "{output:?}");
    });
}

#[cfg(target_os = "linux")]
#[test]
fn unavailable_complete_closure_refuses_launch() {
    isolated(
        "unix::process_regressions::unavailable_complete_closure_refuses_launch",
        || {
            let root = tempfile::tempdir().unwrap();
            let command = shell_command(root.path(), "printf started > launched");
            let mut instructions = [
                libc::sock_filter {
                    code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                libc::sock_filter {
                    code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 1,
                    k: libc::SYS_close_range as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
                },
                libc::sock_filter {
                    code: (libc::BPF_RET | libc::BPF_K) as u16,
                    jt: 0,
                    jf: 0,
                    k: libc::SECCOMP_RET_ALLOW,
                },
            ];
            let program = libc::sock_fprog {
                len: instructions.len() as u16,
                filter: instructions.as_mut_ptr(),
            };
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
                0
            );
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER,
                        &program,
                        0,
                        0,
                    )
                },
                0,
            );
            let error = command
                .capture(
                    b"",
                    4096,
                    Instant::now() + Duration::from_secs(5),
                    &AtomicBool::new(false),
                    Isolation::default(),
                )
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert_not_launched(root.path());
        },
    );
}

#[test]
fn autoreaping_sigchld_refuses_launch() {
    isolated(
        "unix::process_regressions::autoreaping_sigchld_refuses_launch",
        || {
            let root = tempfile::tempdir().unwrap();
            for flags in [0, libc::SA_NOCLDWAIT] {
                let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
                action.sa_sigaction = if flags == 0 {
                    libc::SIG_IGN
                } else {
                    libc::SIG_DFL
                };
                action.sa_flags = flags;
                assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) },
                    0
                );
                let error = shell_command(root.path(), "printf started > launched")
                    .capture(
                        b"",
                        4096,
                        Instant::now() + Duration::from_secs(5),
                        &AtomicBool::new(false),
                        Isolation::default(),
                    )
                    .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::Unsupported);
                assert_not_launched(root.path());
            }
        },
    );
}

#[test]
fn echild_revokes_signals_including_drop() {
    isolated(
        "unix::process_regressions::echild_revokes_signals_including_drop",
        || {
            // Our own live process is a real, non-waitable numerical identity.
            // A buggy Drop would SIGKILL this isolated test process after ECHILD.
            let pid = unsafe { libc::getpid() };
            let mut owner = ChildOwner::new(pid);
            assert_eq!(owner.wait().unwrap_err().raw_os_error(), Some(libc::ECHILD));
            assert!(!owner.has_custody());
            owner.kill_tree().unwrap();
            drop(owner);
            let mut owner = ChildOwner::new(pid);
            assert_eq!(owner.reap().unwrap_err().raw_os_error(), Some(libc::ECHILD));
            assert!(!owner.has_custody());
            drop(owner);
            assert_eq!(unsafe { libc::kill(pid, 0) }, 0);
        },
    );
}

#[test]
fn cancellation_after_parent_setup_refuses_fork() {
    let root = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let trigger = Arc::clone(&cancel);
    BEFORE_FORK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || trigger.store(true, Ordering::Release)));
    });
    let error = shell_command(root.path(), "printf started > launched")
        .capture(
            b"",
            4096,
            Instant::now() + Duration::from_secs(5),
            &cancel,
            Isolation::default(),
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_not_launched(root.path());
}

#[test]
fn original_deadline_after_parent_setup_refuses_fork() {
    let root = tempfile::tempdir().unwrap();
    let command = shell_command(root.path(), "printf started > launched");
    let deadline = Instant::now() + Duration::from_secs(1);
    BEFORE_FORK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            std::thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
            );
        }));
    });
    let error = command
        .capture(
            b"",
            4096,
            deadline,
            &AtomicBool::new(false),
            Isolation::default(),
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_not_launched(root.path());
}

#[test]
fn cancellation_after_child_initialization_prevents_exec() {
    let root = tempfile::tempdir().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let trigger = Arc::clone(&cancel);
    INITIALIZED.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || trigger.store(true, Ordering::Release)));
    });
    let output = shell_command(root.path(), "printf started > launched")
        .capture(
            b"",
            4096,
            Instant::now() + Duration::from_secs(5),
            &cancel,
            Isolation::default(),
        )
        .unwrap();
    assert!(output.cancelled && !output.timed_out);
    assert_not_launched(root.path());
}

#[test]
fn original_deadline_after_child_initialization_prevents_exec() {
    let root = tempfile::tempdir().unwrap();
    let command = shell_command(root.path(), "printf started > launched");
    let deadline = Instant::now() + Duration::from_secs(1);
    INITIALIZED.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            std::thread::sleep(
                deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(10),
            );
        }));
    });
    let output = command
        .capture(
            b"",
            4096,
            deadline,
            &AtomicBool::new(false),
            Isolation::default(),
        )
        .unwrap();
    assert!(output.timed_out && !output.cancelled);
    assert_not_launched(root.path());
}

#[test]
fn stopped_drain_does_not_consume_ready_bytes() {
    for cancelled in [false, true] {
        let (read, write) = pipe().unwrap();
        nonblocking(&read).unwrap();
        assert_eq!(
            write_without_sigpipe(write.as_raw_fd(), b"unconsumed").unwrap(),
            10
        );
        let cancel = AtomicBool::new(cancelled);
        let window = RequestWindow {
            deadline: if cancelled {
                Instant::now() + Duration::from_secs(5)
            } else {
                Instant::now()
            },
            cancel: &cancel,
        };
        let mut read = Some(read);
        let mut output = Vec::new();
        let mut limited = false;
        drain(&mut read, &mut output, 32, &mut limited, Some(&window)).unwrap();
        let mut preserved = [0u8; 10];
        assert_eq!(
            unsafe {
                libc::read(
                    read.as_ref().unwrap().as_raw_fd(),
                    preserved.as_mut_ptr().cast(),
                    preserved.len(),
                )
            },
            10,
        );
        assert_eq!(&preserved, b"unconsumed");
        assert_eq!(output, b"");
        assert!(!limited);
    }
}
