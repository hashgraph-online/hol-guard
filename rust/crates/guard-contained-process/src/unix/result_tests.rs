use super::*;
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

fn shell(script: &str) -> PinnedCommand {
    PinnedCommand::new(
        Path::new("/bin/sh"),
        &[OsStr::new("-c"), OsStr::new(script)],
        &std::env::current_dir().unwrap(),
        &[],
    )
    .unwrap()
}

#[test]
fn completion_overflow_is_a_protocol_error_not_a_user_output_limit() {
    let script = format!("printf %s '{}' >&5; printf ok", "x".repeat(8193));
    let error = shell(&script)
        .capture(
            &[],
            1024,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            Isolation {
                completion_report: true,
                ..Isolation::default()
            },
        )
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("protocol byte budget"));
}

#[test]
fn timeout_and_output_limit_have_no_program_exit_code() {
    let timeout = shell("while :; do :; done")
        .capture(
            &[],
            1024,
            Instant::now() + Duration::from_millis(200),
            &AtomicBool::new(false),
            Isolation::default(),
        )
        .unwrap();
    assert!(timeout.timed_out);
    assert_eq!(timeout.exit_code, None);
    let limit = shell("while :; do printf abcdefgh; done")
        .capture(
            &[],
            32,
            Instant::now() + Duration::from_secs(5),
            &AtomicBool::new(false),
            Isolation::default(),
        )
        .unwrap();
    assert!(limit.output_limited);
    assert_eq!(limit.exit_code, None);
}
