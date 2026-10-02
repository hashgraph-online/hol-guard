use super::bounded_transport::{classify_lookup, run_helper, Completed, DEFAULT_TIMEOUT};
use super::{SECURE_STATE_INVALID, SECURE_STATE_UNAVAILABLE};
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn shell(script: &str, input: Option<&[u8]>, max_bytes: usize) -> Result<Completed, String> {
    run_helper(
        Path::new("/bin/sh"),
        &["-c", script],
        input,
        max_bytes,
        DEFAULT_TIMEOUT,
    )
}

fn unique_path(suffix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "hol-guard-approval-platform-{}-{nonce}-{suffix}",
        std::process::id()
    ))
}

#[test]
fn oversized_stdout_is_rejected_without_unbounded_capture() {
    let result = shell("printf 0123456789", None, 4);
    assert!(matches!(
        result,
        Err(error) if error == SECURE_STATE_INVALID
    ));
}

#[test]
fn oversized_stderr_is_rejected_without_persisting_diagnostics() {
    let result = shell("head -c 16385 /dev/zero >&2; exit 2", None, 64);
    assert!(matches!(
        result,
        Err(error) if error == SECURE_STATE_UNAVAILABLE
    ));
}

#[test]
fn unsuccessful_lookup_is_not_treated_as_absence_when_helper_reports_error() {
    let completed = shell("printf failure >&2; exit 1", None, 64).unwrap();
    assert!(matches!(
        classify_lookup(completed, 64),
        Err(error) if error == SECURE_STATE_UNAVAILABLE
    ));
}

#[test]
fn status_one_without_output_is_the_only_lookup_absence() {
    let completed = shell("exit 1", None, 64).unwrap();
    assert_eq!(classify_lookup(completed, 64), Ok(None));
}

#[test]
fn lookup_allows_a_max_sized_secret_with_one_trailing_newline() {
    let completed = shell("printf '1234\\n'", None, 5).unwrap();
    assert_eq!(classify_lookup(completed, 4), Ok(Some("1234".to_owned())));
}

#[test]
fn missing_helper_is_unavailable_not_absence() {
    let result = run_helper(
        Path::new("/definitely/missing/secret-tool"),
        &[],
        None,
        64,
        DEFAULT_TIMEOUT,
    );
    assert!(matches!(
        result,
        Err(error) if error == SECURE_STATE_UNAVAILABLE
    ));
}

#[test]
fn stdin_is_closed_after_the_last_write() {
    let completed = shell("cat >/dev/null", Some(b"test"), 64).unwrap();
    assert!(completed.status.success());
}

#[test]
fn helper_that_does_not_read_stdin_is_timed_out_and_cleaned_up() {
    let survivor_path = unique_path("survivor");
    let survivor = survivor_path.to_string_lossy().into_owned();
    let script = format!("(sleep 0.3; printf alive > '{survivor}') & sleep 1");
    let input = vec![b'x'; 64 * 1024];
    let started_at = Instant::now();
    let result = run_helper(
        Path::new("/bin/sh"),
        &["-c", &script],
        Some(&input),
        64,
        Duration::from_millis(100),
    );
    assert!(matches!(
        result,
        Err(error) if error == SECURE_STATE_UNAVAILABLE
    ));
    assert!(started_at.elapsed() < Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(500));
    assert!(!survivor_path.exists());
    let _ = fs::remove_file(survivor_path);
}

#[test]
fn descendant_holding_output_pipe_cannot_defeat_timeout_cleanup() {
    let survivor_path = unique_path("pipe-survivor");
    let survivor = survivor_path.to_string_lossy().into_owned();
    let script = format!("(sleep 0.3; printf alive > '{survivor}') & printf ready; exit 0");
    let started_at = Instant::now();
    let result = run_helper(
        Path::new("/bin/sh"),
        &["-c", &script],
        None,
        64,
        Duration::from_millis(100),
    );
    assert!(matches!(
        result,
        Err(error) if error == SECURE_STATE_UNAVAILABLE
    ));
    assert!(started_at.elapsed() < Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(500));
    assert!(!survivor_path.exists());
    let _ = fs::remove_file(survivor_path);
}
