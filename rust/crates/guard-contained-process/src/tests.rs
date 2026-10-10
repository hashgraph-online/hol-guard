//! Requires Linux or macOS, a real /bin/sh, and a local filesystem supporting
//! no-follow opens. No sandbox capability is fabricated here: these tests cover
//! the handle-bound process kernel, not installed Guard/backend health.
//!
//! Retirement map:
//! - test_guard_containment_executor::test_executable_drift_fails_before_spawn
//!   -> pinned_executable_*; its test_input_drift_fails_before_spawn ->
//!   contained_execution_tests::{request_hash_*,snapshot_*}.
//! - test_macos_backend_leaves_no_background_descendant -> real_capture_kills_*.
//!   The execution/reaping portion of test_timeout_retains_enforcement_attestation
//!   -> deadline_*; backend enforcement attestation is not claimed covered.
//! - test_guard_contained_workspace_write_contract::test_output_discovery_stops_at_entry_budget
//!   -> directory_entry_budget_* (real entries, not a fake scandir iterator).
//! - Resource/output limits -> resource_* and output_* / per_stream_output_*.
//!   File-size/descriptor fixtures require host allowances >=4 KiB and >=8 FDs;
//!   CPU/memory/process limits are inherited, not falsely claimed exercised.

use super::*;
use std::fs;
use std::os::unix::fs::symlink;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tempfile::TempDir;

fn fixture() -> (TempDir, PathBuf) {
    let temporary = tempfile::tempdir().expect("private native process fixture");
    let root = fs::canonicalize(temporary.path()).expect("canonical fixture root");
    (temporary, root)
}

fn shell() -> PathBuf {
    fs::canonicalize("/bin/sh").expect("these Unix regressions require /bin/sh")
}

fn command(executable: &Path, cwd: &Path, script: &str) -> PinnedCommand {
    PinnedCommand::new(
        executable,
        &[OsStr::new("-c"), OsStr::new(script)],
        cwd,
        &[
            (OsString::from("VISIBLE"), OsString::from("fixture-value")),
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        ],
    )
    .expect("pin a real native executable and cwd")
}

fn run(command: PinnedCommand, input: &[u8], cap: usize) -> CapturedOutput {
    command
        .capture(
            input,
            cap,
            Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false),
            Isolation::default(),
        )
        .expect("capture a real child process")
}

fn assert_absent(path: &Path) {
    assert_eq!(
        fs::symlink_metadata(path).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
}

fn assert_reaped(pid: libc::pid_t) {
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn leader(output: &CapturedOutput) -> libc::pid_t {
    std::str::from_utf8(&output.stdout)
        .expect("shell PID framing")
        .lines()
        .next()
        .expect("child printed its PID")
        .parse()
        .expect("numeric shell PID")
}

#[test]
fn real_capture_preserves_stdin_stdout_stderr_and_nonzero_exit() {
    let (_temporary, root) = fixture();
    let output = run(command(&shell(), &root,
        "IFS= read -r value; printf 'out:<%s>' \"$value\"; printf 'err:<%s>' \"$VISIBLE\" >&2; exit 7"),
        b"fixture-input\n", 4096);
    assert_eq!(
        output.stdout, b"out:<fixture-input>",
        "child output: {output:?}"
    );
    assert_eq!(output.stderr, b"err:<fixture-value>");
    assert_eq!(output.exit_code, Some(7));
    assert!(!output.timed_out && !output.cancelled && !output.output_limited);
}

#[test]
fn real_capture_reaps_a_normally_exited_leader() {
    let (_temporary, root) = fixture();
    let output = run(
        command(&shell(), &root, "printf '%s\n' $$; exit 0"),
        b"",
        4096,
    );
    assert_eq!(output.exit_code, Some(0));
    assert_reaped(leader(&output));
}

#[test]
fn pinned_executable_byte_drift_cannot_start_a_child() {
    let (_temporary, root) = fixture();
    let executable = root.join("shell");
    fs::copy(shell(), &executable).unwrap();
    let pinned = command(&executable, &root, "printf started > launched");
    fs::write(&executable, b"replaced native executable bytes").unwrap();
    let error = pinned
        .capture(
            b"",
            4096,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            Isolation::default(),
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_absent(&root.join("launched"));
}

#[test]
fn pinned_executable_same_bytes_new_inode_cannot_start_a_child() {
    let (_temporary, root) = fixture();
    let executable = root.join("shell");
    fs::copy(shell(), &executable).unwrap();
    let pinned = command(&executable, &root, "printf started > launched");
    let before = bound_fs::identity(pinned.executable_handle()).unwrap();
    fs::rename(&executable, root.join("original-shell")).unwrap();
    fs::copy(shell(), &executable).unwrap();
    let mut replacement = bound_fs::open_executable(&executable).unwrap();
    assert_eq!(
        bound_fs::digest_executable(&mut replacement, 256 * 1024 * 1024).unwrap(),
        pinned.executable_digest
    );
    assert!(!before.same_object(&bound_fs::identity(&replacement).unwrap()));
    let error = pinned
        .capture(
            b"",
            4096,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            Isolation::default(),
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_absent(&root.join("launched"));
}

#[test]
fn pinned_cwd_replacement_cannot_run_in_the_new_directory() {
    let (_temporary, root) = fixture();
    let cwd = root.join("cwd");
    fs::create_dir(&cwd).unwrap();
    let pinned = command(&shell(), &cwd, "printf started > launched");
    fs::rename(&cwd, root.join("original-cwd")).unwrap();
    fs::create_dir(&cwd).unwrap();
    let error = pinned
        .capture(
            b"",
            4096,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            Isolation::default(),
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_absent(&cwd.join("launched"));
    assert_absent(&root.join("original-cwd/launched"));
}

#[test]
fn output_limit_bounds_the_combined_streams_and_reaps_the_producer() {
    let (_temporary, root) = fixture();
    for script in [
        "printf '%s\n' $$; while :; do printf 'oooooooooooooooo'; done",
        "printf '%s\n' $$; while :; do printf 'eeeeeeeeeeeeeeee' >&2; done",
    ] {
        let output = run(command(&shell(), &root, script), b"", 128);
        assert!(output.output_limited);
        assert!(!output.timed_out && !output.cancelled);
        assert_eq!(output.stdout.len() + output.stderr.len(), 128);
        assert_reaped(leader(&output));
    }
}

#[test]
fn zero_output_budget_is_rejected_before_child_execution() {
    let (_temporary, root) = fixture();
    let error = command(&shell(), &root, "printf started > launched")
        .capture(
            b"",
            0,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            Isolation::default(),
        )
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_absent(&root.join("launched"));
}

#[test]
fn deadline_kills_a_real_running_process_and_reaps_its_leader() {
    let (_temporary, root) = fixture();
    let output = command(&shell(), &root, "printf '%s\n' $$; while :; do :; done")
        .capture(
            b"",
            4096,
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
            Isolation::default(),
        )
        .unwrap();
    assert!(output.timed_out);
    assert!(!output.cancelled && !output.output_limited);
    assert_reaped(leader(&output));
}

#[test]
fn real_capture_kills_a_background_descendant_after_leader_exit() {
    let (_temporary, root) = fixture();
    let output = run(
        command(&shell(), &root, "sleep 30 & printf '%s %s\n' $$ $!; exit 0"),
        b"",
        4096,
    );
    assert_eq!(output.exit_code, Some(0));
    let ids: Vec<libc::pid_t> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .split_whitespace()
        .map(|part| part.parse().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    assert_reaped(ids[0]);
    // A killed orphan can remain a zombie until the system reaper runs. It
    // must not remain executable; unlike the leader, it is not our waitpid child.
    #[cfg(target_os = "linux")]
    {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match fs::read_to_string(format!("/proc/{}/stat", ids[1])) {
                Ok(stat) if stat.rsplit_once(") ").unwrap().1.starts_with('Z') => break,
                Ok(_) => assert!(
                    Instant::now() < deadline,
                    "descendant remains executable after native cleanup"
                ),
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::NotFound);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let deadline = Instant::now() + Duration::from_secs(2);
        while unsafe { libc::kill(ids[1], 0) } == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(unsafe { libc::kill(ids[1], 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }
}

#[test]
fn cancellation_stops_a_started_process_and_reaps_it() {
    let (_temporary, root) = fixture();
    let cancel = AtomicBool::new(false);
    let started = root.join("started");
    let pinned = command(
        &shell(),
        &root,
        "printf '%s\n' $$; printf ready > started; while :; do :; done",
    );
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            pinned.capture(
                b"",
                4096,
                Instant::now() + Duration::from_secs(10),
                &cancel,
                Isolation::default(),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !started.is_file() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let observed_start = started.is_file();
        cancel.store(true, Ordering::Release);
        let output = worker.join().unwrap().unwrap();
        assert!(
            observed_start,
            "the child, not a test callback, signals its start"
        );
        assert!(output.cancelled);
        assert!(!output.timed_out && !output.output_limited);
        assert_reaped(leader(&output));
    });
}

#[test]
fn bound_reads_enforce_bytes_and_reject_symlinks_and_hardlinks() {
    let (_temporary, root) = fixture();
    let directory = bound_fs::Directory::open(&root).unwrap();
    directory
        .create(Path::new("source"), b"data", false)
        .unwrap();
    assert_eq!(
        directory.read(Path::new("source"), 4).unwrap().bytes,
        b"data"
    );
    assert_eq!(
        directory.read(Path::new("source"), 3).err().unwrap().kind(),
        io::ErrorKind::InvalidData
    );
    symlink("source", root.join("alias")).unwrap();
    assert!(directory.read(Path::new("alias"), 4).is_err());
    fs::hard_link(root.join("source"), root.join("linked")).unwrap();
    assert_eq!(
        directory.read(Path::new("source"), 4).err().unwrap().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn directory_entry_budget_rejects_overflow_without_consuming_future_scans() {
    let (_temporary, root) = fixture();
    let directory = bound_fs::Directory::open(&root).unwrap();
    for name in ["a", "b", "c"] {
        directory.create(Path::new(name), b"", false).unwrap();
    }
    assert_eq!(
        directory.entries(Path::new("."), 2).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    let expected: Vec<OsString> = ["a", "b", "c"].into_iter().map(OsString::from).collect();
    assert_eq!(directory.entries(Path::new("."), 3).unwrap(), expected);
    assert_eq!(directory.entries(Path::new("."), 3).unwrap(), expected);
}

#[test]
fn directory_replacement_rejects_reads_from_the_replacement_root() {
    let (_temporary, root) = fixture();
    fs::create_dir(root.join("source")).unwrap();
    let pinned = bound_fs::Directory::open(&root.join("source")).unwrap();
    pinned
        .create(Path::new("file"), b"approved", false)
        .unwrap();
    fs::rename(root.join("source"), root.join("old-source")).unwrap();
    fs::create_dir(root.join("source")).unwrap();
    fs::write(root.join("source/file"), b"approved").unwrap();
    assert_eq!(
        pinned.read(Path::new("file"), 64).err().unwrap().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(fs::read(root.join("source/file")).unwrap(), b"approved");
}

fn inherited_resource_limits() -> ResourceLimits {
    let mut values = [0u64; 5];
    for (kind, value) in [
        libc::RLIMIT_CPU,
        libc::RLIMIT_AS,
        libc::RLIMIT_FSIZE,
        libc::RLIMIT_NOFILE,
        libc::RLIMIT_NPROC,
    ]
    .into_iter()
    .zip(values.iter_mut())
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(unsafe { libc::getrlimit(kind, &mut limit) }, 0);
        *value = limit.rlim_cur;
    }
    ResourceLimits {
        cpu_seconds: values[0],
        memory_bytes: values[1],
        file_bytes: values[2],
        open_files: values[3],
        processes: values[4],
    }
}

#[test]
fn resource_file_size_cap_stops_actual_child_writes() {
    let (_temporary, root) = fixture();
    let mut resources = inherited_resource_limits();
    resources.file_bytes = resources.file_bytes.min(4096);
    assert_eq!(
        resources.file_bytes, 4096,
        "fixture requires a host file-size allowance of at least 4 KiB"
    );
    let output = command(
        &shell(),
        &root,
        "printf '%s\n' $$; while :; do printf '0123456789abcdef' || exit 23; done > limited.bin",
    )
    .capture(
        b"",
        4096,
        Instant::now() + Duration::from_secs(10),
        &AtomicBool::new(false),
        Isolation {
            resources: Some(resources),
            ..Isolation::default()
        },
    )
    .unwrap();
    assert!(!output.timed_out && !output.cancelled && !output.output_limited);
    assert_ne!(output.exit_code, Some(0));
    let bytes = fs::read(root.join("limited.bin")).unwrap();
    assert_eq!(bytes.len(), 4096);
    assert!(bytes
        .chunks_exact(16)
        .all(|chunk| chunk == b"0123456789abcdef"));
    assert_reaped(leader(&output));
}

#[test]
fn resource_open_file_cap_prevents_an_actual_extra_descriptor() {
    let (_temporary, root) = fixture();
    let mut resources = inherited_resource_limits();
    resources.open_files = resources.open_files.min(8);
    assert_eq!(
        resources.open_files, 8,
        "fixture requires a host descriptor allowance of at least eight"
    );
    let output = command(&shell(), &root,
        "printf 'before\n'; exec 3>fd3; exec 4>fd4; exec 5>fd5; exec 6>fd6; exec 7>fd7; exec 8>fd8; printf 'after\n'")
        .capture(b"", 4096, Instant::now() + Duration::from_secs(10),
            &AtomicBool::new(false), Isolation { resources: Some(resources), ..Isolation::default() }).unwrap();
    assert_eq!(output.stdout, b"before\n");
    assert_ne!(output.exit_code, Some(0));
    assert!(!output.timed_out && !output.cancelled && !output.output_limited);
}

#[test]
fn per_stream_output_budget_preserves_both_real_streams_at_their_boundary() {
    let (_temporary, root) = fixture();
    let output = command(
        &shell(),
        &root,
        "i=0; while [ \"$i\" -lt 64 ]; do printf o; printf e >&2; i=$((i+1)); done",
    )
    .capture(
        b"",
        64,
        Instant::now() + Duration::from_secs(10),
        &AtomicBool::new(false),
        Isolation {
            output_per_stream: true,
            ..Isolation::default()
        },
    )
    .unwrap();
    assert_eq!(output.stdout, vec![b'o'; 64]);
    assert_eq!(output.stderr, vec![b'e'; 64]);
    assert_eq!(output.exit_code, Some(0));
    assert!(!output.timed_out && !output.cancelled && !output.output_limited);
}
