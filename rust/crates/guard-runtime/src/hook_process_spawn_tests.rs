//! Capture failure, the hook environment allowlist and the Windows job
//! ordering of the hook launch kernel, ported from the Python launch-runtime
//! tests that this kernel replaced.

use super::*;
use std::io;

/// Three good bytes, then a read error: the capture holds a prefix only.
struct Failing {
    sent: bool,
}

impl io::Read for Failing {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.sent {
            return Err(io::Error::other("the pipe broke"));
        }
        self.sent = true;
        buf[..3].copy_from_slice(b"raw");
        Ok(3)
    }
}

fn drained<R: io::Read + Send + 'static>(stream: R) -> (Vec<u8>, bool, bool) {
    let target = Arc::new(Mutex::new(Vec::new()));
    let bound = Arc::new(OutputBound {
        count: AtomicU64::new(0),
        limit: 1024,
        exceeded: AtomicBool::new(false),
        capture_error: AtomicBool::new(false),
    });
    let done = Arc::new(AtomicBool::new(false));
    drain_stream(stream, target.clone(), bound.clone(), done.clone())
        .join()
        .unwrap();
    let captured = target.lock().unwrap().clone();
    (
        captured,
        bound.capture_error.load(Ordering::SeqCst),
        done.load(Ordering::SeqCst),
    )
}

#[test]
fn a_read_failure_marks_the_capture_incomplete_and_keeps_the_bytes() {
    let (captured, incomplete, done) = drained(Failing { sent: false });
    assert_eq!(captured, b"raw");
    assert!(incomplete);
    assert!(done, "the reader still reports that it stopped");
    let (captured, incomplete, done) = drained(io::Cursor::new(b"\xff raw".to_vec()));
    assert_eq!(captured, b"\xff raw");
    assert!(!incomplete);
    assert!(done);
}

#[test]
fn the_hook_environment_keeps_exactly_the_documented_names_in_any_case() {
    let documented = [
        "CODEX_HOME",
        "COMSPEC",
        "HOME",
        "HOL_GUARD_HOOK_FAILURE_KIND",
        "HOL_GUARD_NATIVE",
        "HOL_GUARD_NATIVE_BINARY",
        "HOL_GUARD_NATIVE_SOURCE_COMPILER",
        "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER",
        "HOL_GUARD_TEST_MODE",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "HOL_GUARD_RESIDENT_TEST_SEAMS",
        "LANG",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    ];
    let mut pinned = HOOK_ENVIRONMENT_KEYS.to_vec();
    pinned.sort_unstable();
    let mut expected = documented.to_vec();
    expected.sort_unstable();
    assert_eq!(pinned, expected);

    let mut source = BTreeMap::new();
    for name in documented {
        source.insert(name.to_lowercase(), format!("lower-{name}"));
        source.insert(name.to_owned(), format!("upper-{name}"));
    }
    source.insert("LC_MESSAGES".to_owned(), "C".to_owned());
    source.insert("lc_time".to_owned(), "C".to_owned());
    for name in [
        "AWS_SECRET_ACCESS_KEY",
        "LD_PRELOAD",
        "PYTHONPATH",
        "HOL_GUARD_ANYTHING_ELSE",
        "HOL_GUARD_DESKTOP_HOOK_PROXY",
        "LCX",
    ] {
        source.insert(name.to_owned(), "x".to_owned());
    }
    let kept = isolated_hook_environment(&source);
    for name in documented {
        assert_eq!(kept[name], format!("upper-{name}"), "{name}");
        assert_eq!(
            kept[&name.to_lowercase()],
            format!("lower-{name}"),
            "{name}"
        );
    }
    assert!(kept.contains_key("LC_MESSAGES") && kept.contains_key("lc_time"));
    assert_eq!(kept.len(), documented.len() * 2 + 2);
}

#[cfg(windows)]
mod windows_job {
    use super::*;
    use std::time::Instant;

    fn launch(script: &str, seconds: f64) -> (BoundedHookProcessResult, Duration) {
        let environment: BTreeMap<String, String> =
            isolated_hook_environment(&std::env::vars().collect::<BTreeMap<String, String>>());
        let command = ["cmd.exe", "/d", "/c", script].map(str::to_owned).to_vec();
        let started = Instant::now();
        let result = run_isolated_hook_process(
            &command,
            "",
            &std::env::temp_dir(),
            &environment,
            Some(seconds),
            None,
            None,
            None,
        );
        (result, started.elapsed())
    }

    #[test]
    fn a_clean_exit_drains_its_output_and_leaves_the_job_alone() {
        let (result, _) = launch("echo done& echo problem 1>&2", 30.0);
        assert_eq!(result.returncode, Some(0));
        assert!(result.stdout.contains("done"), "{result:?}");
        assert!(result.stderr.contains("problem"), "{result:?}");
        assert!(!result.timed_out && !result.containment_failed);
    }

    #[test]
    fn a_hook_past_its_deadline_is_ended_with_its_whole_job() {
        let (result, elapsed) = launch("ping -n 120 127.0.0.1 >nul", 1.0);
        assert!(result.timed_out, "{result:?}");
        assert!(!result.containment_failed, "{result:?}");
        assert!(elapsed < Duration::from_secs(30), "{elapsed:?}");
    }

    #[test]
    fn a_descendant_holding_the_pipes_does_not_outlive_the_job() {
        // The parent exits at once; the descendant keeps stdout and stderr
        // open for two minutes unless the job is closed behind the parent.
        let (result, elapsed) = launch("start /b ping -n 120 127.0.0.1& exit /b 0", 60.0);
        assert!(!result.containment_failed, "{result:?}");
        assert!(elapsed < Duration::from_secs(45), "{elapsed:?}");
    }
}
