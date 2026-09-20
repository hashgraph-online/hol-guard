use super::*;
use std::cell::{Cell, RefCell};
use std::env;
use std::fs;
use std::io::Read;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct DropWriter(Rc<Cell<bool>>);

impl Write for DropWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for DropWriter {
    fn drop(&mut self) {
        self.0.set(true);
    }
}

#[test]
fn every_failed_wait_closes_stdin_then_cleans_up_once_and_preserves_failure() {
    for kind in [io::ErrorKind::TimedOut, io::ErrorKind::PermissionDenied] {
        for cleanup_fails in [false, true] {
            let closed = Rc::new(Cell::new(false));
            let calls = Cell::new(0);
            let result = finish_supervisor_wait(
                DropWriter(Rc::clone(&closed)),
                Err(io::Error::new(kind, "injected wait failure")),
                || {
                    assert!(closed.get(), "cleanup began before stdin was closed");
                    calls.set(calls.get() + 1);
                    if cleanup_fails {
                        Err(io::Error::other("injected cleanup failure"))
                    } else {
                        Ok(())
                    }
                },
                || panic!("failed wait must not be classified as a normal exit"),
            );
            let expected = if kind == io::ErrorKind::TimedOut {
                "native_resident_supervisor_wait_timed_out"
            } else {
                "native_resident_supervisor_wait_failed"
            };
            let error = result.unwrap_err();
            assert!(error.starts_with(expected));
            assert_eq!(
                error.contains("native_resident_child_cleanup_failed"),
                cleanup_fails
            );
            assert_eq!(calls.get(), 1);
        }
    }
}

#[test]
fn observed_exits_close_stdin_without_forced_cleanup() {
    for success in [false, true] {
        let closed = Rc::new(Cell::new(false));
        let result = finish_supervisor_wait(
            DropWriter(Rc::clone(&closed)),
            Ok(success),
            || panic!("an observed exit must use the Job retirement path"),
            || {
                assert!(closed.get());
                Ok(true)
            },
        );
        assert!(closed.get());
        assert_eq!(result.is_ok(), success);
        if !success {
            assert_eq!(result.unwrap_err(), "native_resident_managed_exit_failed");
        }
    }
}

#[test]
fn forced_or_unobserved_descendant_retirement_is_never_a_normal_exit() {
    for success in [false, true] {
        let error = finish_observed_exit(success, Ok(false)).unwrap_err();
        assert!(error.contains("native_resident_descendant_cleanup_required"));
        assert_eq!(
            error.contains("native_resident_managed_exit_failed"),
            !success
        );
        assert!(finish_observed_exit(success, Err(io::Error::other("query failed"))).is_err());
    }
}

const TIMEOUT_DIRECTORY_ENV: &str = "HOL_GUARD_TEST_SUPERVISOR_TIMEOUT_DIRECTORY";
const TIMEOUT_MODE_ENV: &str = "HOL_GUARD_TEST_SUPERVISOR_TIMEOUT_MODE";

fn exact_probe_name(name: &str) -> String {
    let (_, module) = module_path!().split_once("::").unwrap();
    format!("{module}::{name}")
}

fn probe_directory() -> Option<std::path::PathBuf> {
    // Ordinary parallel workspace tests must not execute the child probe merely
    // because this test's private environment variable is temporarily present.
    if !env::args().any(|argument| argument == "--exact") {
        return None;
    }
    env::var_os(TIMEOUT_DIRECTORY_ENV).map(std::path::PathBuf::from)
}

fn wait_for_file(path: &Path) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe did not start",
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[test]
fn supervisor_wait_failures_terminate_the_actual_child_and_its_descendant() {
    for scenario in ["timeout", "wait-error", "normal-root", "abrupt-supervisor"] {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            env::temp_dir().join(format!("guard-managed-wait-{}-{nonce}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        env::set_var(TIMEOUT_DIRECTORY_ENV, &directory);
        env::set_var(TIMEOUT_MODE_ENV, scenario);
        let pids = RefCell::new(None);
        let result = supervise_managed_child_with_wait(
            &env::current_exe().unwrap(),
            &[
                OsString::from("--exact"),
                OsString::from(exact_probe_name("managed_timeout_child_probe")),
                OsString::from("--nocapture"),
            ],
            &[0x5a; 32],
            |child| {
                wait_for_file(&directory.join("started"))?;
                let descendant: u32 = fs::read_to_string(directory.join("descendant"))?
                    .parse()
                    .map_err(|_| io::Error::other("invalid probe PID"))?;
                *pids.borrow_mut() = Some((child.id(), descendant));
                match scenario {
                    "wait-error" => Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "injected wait failure",
                    )),
                    "normal-root" | "abrupt-supervisor" => {
                        child.wait_success_with_timeout(Duration::from_secs(5))
                    }
                    _ => child.wait_success_with_timeout(Duration::from_millis(25)),
                }
            },
        );
        env::remove_var(TIMEOUT_DIRECTORY_ENV);
        env::remove_var(TIMEOUT_MODE_ENV);
        let observed_pids = *pids.borrow();
        let observed_exits = observed_pids.map(|(child, descendant)| {
            [child, descendant].map(|pid| {
                guard_runtime_windows_process::wait_for_process_exit(pid, Duration::from_secs(2))
            })
        });
        let _ = fs::remove_dir_all(directory);
        let expected = match scenario {
            "wait-error" => "native_resident_supervisor_wait_failed",
            "normal-root" => "native_resident_descendant_cleanup_required",
            "abrupt-supervisor" => "native_resident_managed_exit_failed",
            _ => "native_resident_supervisor_wait_timed_out",
        };
        assert_eq!(result.unwrap_err(), expected);
        for exited in observed_exits.expect("both actual processes started") {
            assert!(
                exited.unwrap(),
                "a contained process survived supervisor failure"
            );
        }
    }
}

#[test]
fn managed_timeout_child_probe() {
    let Some(directory) = probe_directory() else {
        return;
    };
    let mut auth = [0u8; 65];
    io::stdin().read_exact(&mut auth).unwrap();
    if env::var(TIMEOUT_MODE_ENV).as_deref() == Ok("abrupt-supervisor") {
        let executable = env::current_exe().unwrap();
        let probe = OsString::from(exact_probe_name("managed_timeout_descendant_probe"));
        let _descendant = spawn_managed_child(
            &executable,
            &[
                OsStr::new("--exact"),
                probe.as_os_str(),
                OsStr::new("--nocapture"),
            ],
        )
        .unwrap();
        wait_for_file(&directory.join("descendant")).unwrap();
        fs::write(directory.join("started"), b"ready").unwrap();
        // Bypass Rust destructors: only the kernel's close-kill Job policy can
        // retire this sleeping descendant when the supervisor abruptly exits.
        std::process::exit(43);
    }
    let mut descendant = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            &exact_probe_name("managed_timeout_descendant_probe"),
            "--nocapture",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_file(&directory.join("descendant")).unwrap();
    fs::write(directory.join("started"), b"ready").unwrap();
    if env::var(TIMEOUT_MODE_ENV).as_deref() == Ok("normal-root") {
        // Keep an explicit waiter without joining it: this root must return
        // successfully while its live descendant still needs outer Job cleanup.
        drop(thread::spawn(move || {
            let _ = descendant.wait();
        }));
        return;
    }
    thread::sleep(Duration::from_secs(30));
    // Bound a failing regression test independently of the production cleanup.
    let _ = descendant.kill();
    let _ = descendant.wait();
}

#[test]
fn managed_timeout_descendant_probe() {
    let Some(directory) = probe_directory() else {
        return;
    };
    fs::write(directory.join("descendant"), std::process::id().to_string()).unwrap();
    thread::sleep(Duration::from_secs(30));
}
