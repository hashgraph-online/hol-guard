use super::*;
use std::io::{Read, Write};
use std::sync::Arc;

const CHILD_TEST: &str = "windows::capture::tests::child_process";
fn environment(mode: &str) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    let mut env = Vec::new();
    for name in ["SystemRoot", "TEMP", "TMP", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(name) {
            env.push((name.into(), value));
        }
    }
    env.push(("GUARD_CAPTURE_TEST_MODE".into(), mode.into()));
    env
}

#[test]
#[ignore = "subprocess fixture selected by capture lifecycle cases"]
fn child_process() {
    let mode = std::env::var("GUARD_CAPTURE_TEST_MODE").unwrap();
    if mode == "pressure" {
        let out = std::thread::spawn(|| {
            let mut output = std::io::stdout().lock();
            for _ in 0..64 {
                output.write_all(&[b'A'; 4096]).unwrap();
            }
        });
        let err = std::thread::spawn(|| {
            let mut output = std::io::stderr().lock();
            for _ in 0..64 {
                output.write_all(&[b'B'; 4096]).unwrap();
            }
        });
        let mut input = Vec::new();
        std::io::stdin().read_to_end(&mut input).unwrap();
        out.join().unwrap();
        err.join().unwrap();
        println!(
            "INPUT_SUM={}",
            input.iter().map(|byte| *byte as u64).sum::<u64>()
        );
    } else if mode == "reject-input" {
        println!("INPUT_REJECTED");
        eprintln!("child declined stdin");
        std::process::exit(7);
    } else if mode == "hold" {
        println!("READY");
        std::io::stdout().flush().unwrap();
        if let Some(path) = std::env::var_os("GUARD_CAPTURE_TEST_READY") {
            std::fs::write(path, b"ready").unwrap();
        }
        std::thread::sleep(Duration::from_secs(30));
    } else if mode == "orphan" {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
            .env("GUARD_CAPTURE_TEST_MODE", "hold")
            .spawn()
            .unwrap();
        println!("DESCENDANT={}", child.id());
        std::io::stdout().flush().unwrap();
        // The capture owner, not this intentionally exiting fixture, must
        // terminate the descendant through its owned job.
        std::process::exit(0);
    } else {
        panic!("invalid fixture mode");
    }
}

fn run(
    mode: &str,
    input: &[u8],
    limit: usize,
    cancellation: &AtomicBool,
) -> io::Result<CapturedOutput> {
    capture(
        CaptureCommand {
            executable: &std::env::current_exe()?,
            args: &[
                OsStr::new("--exact"),
                OsStr::new(CHILD_TEST),
                OsStr::new("--ignored"),
                OsStr::new("--nocapture"),
            ],
            cwd: &std::env::current_dir()?,
            environment: &environment(mode),
        },
        input,
        limit,
        Instant::now() + Duration::from_secs(5),
        cancellation,
    )
}

#[test]
fn concurrent_stdin_stdout_stderr_does_not_deadlock_or_lose_bytes() {
    let input = vec![7_u8; 512 * 1024];
    let output = run("pressure", &input, 1024 * 1024, &AtomicBool::new(false)).unwrap();
    assert_eq!(output.exit_code, Some(0));
    assert!(!output.timed_out && !output.output_limited && !output.cancelled);
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'A').count(),
        64 * 4096
    );
    assert_eq!(
        output.stderr.iter().filter(|byte| **byte == b'B').count(),
        64 * 4096
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("INPUT_SUM=3670016"));
}

#[test]
fn early_child_exit_preserves_output_and_status_with_unread_stdin() {
    let output = run(
        "reject-input",
        &vec![7_u8; 512 * 1024],
        64 * 1024,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert_eq!(output.exit_code, Some(7));
    assert!(!output.timed_out && !output.output_limited && !output.cancelled);
    assert!(String::from_utf8_lossy(&output.stdout).contains("INPUT_REJECTED"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("child declined stdin"));
}

#[test]
fn output_overflow_stops_a_child_while_stdin_is_under_pressure() {
    let output = run(
        "pressure",
        &vec![7_u8; 512 * 1024],
        1024,
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(output.output_limited);
    assert_eq!(output.exit_code, None);
    assert_eq!(output.stdout.len() + output.stderr.len(), 1024);
}

#[test]
fn root_exit_kills_descendants_that_hold_capture_pipes() {
    let output = run("orphan", &[], 64 * 1024, &AtomicBool::new(false)).unwrap();
    assert_eq!(output.exit_code, Some(0));
    assert!(!output.timed_out);
    let text = String::from_utf8(output.stdout).unwrap();
    let line = text
        .lines()
        .find(|line| line.starts_with("DESCENDANT="))
        .unwrap();
    let pid: u32 = line.trim_start_matches("DESCENDANT=").parse().unwrap();
    match open_process(pid, winapi::um::winnt::SYNCHRONIZE) {
        Ok(process) => assert_eq!(
            unsafe { WaitForSingleObject(process.as_raw_handle() as HANDLE, 0) },
            WAIT_OBJECT_0
        ),
        Err(error) => assert_eq!(
            error.raw_os_error(),
            Some(winapi::shared::winerror::ERROR_INVALID_PARAMETER as i32)
        ),
    }
}

#[test]
fn explicit_cancellation_has_no_success_exit_status() {
    let marker = std::env::temp_dir().join(format!(
        "guard-capture-ready-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let cancel = Arc::new(AtomicBool::new(false));
    let stop = cancel.clone();
    let ready = marker.clone();
    let setter = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(4);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let started = ready.exists();
        stop.store(true, Ordering::Release);
        started
    });
    let mut env = environment("hold");
    env.push((
        "GUARD_CAPTURE_TEST_READY".into(),
        marker.clone().into_os_string(),
    ));
    let result = capture(
        CaptureCommand {
            executable: &std::env::current_exe().unwrap(),
            args: &[
                OsStr::new("--exact"),
                OsStr::new(CHILD_TEST),
                OsStr::new("--ignored"),
                OsStr::new("--nocapture"),
            ],
            cwd: &std::env::current_dir().unwrap(),
            environment: &env,
        },
        &[],
        64 * 1024,
        Instant::now() + Duration::from_secs(5),
        &cancel,
    );
    let started = setter.join().unwrap();
    let _ = std::fs::remove_file(marker);
    assert!(started, "cancellation must exercise a running child");
    let output = result.unwrap();
    assert!(output.cancelled);
    assert_eq!(output.exit_code, None);
}
