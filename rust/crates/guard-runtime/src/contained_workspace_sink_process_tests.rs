use super::*;

#[test]
fn replayed_output_is_display_safe() {
    assert_eq!(display_text(b"a\r\nb\x1b[0m\tc\n"), "a\nb\u{fffd}[0m\tc\n");
    assert_eq!(display_text(b"\xff"), "\u{fffd}");
}

#[test]
fn a_captured_command_reports_its_output_and_exit() {
    let scratch = tempfile::tempdir().unwrap();
    let command = [
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        "echo out; echo err >&2; exit 3".to_owned(),
    ];
    let environment = BTreeMap::from([("PATH".to_owned(), "/usr/bin:/bin".to_owned())]);
    let captured = run_captured(
        &command,
        &environment,
        scratch.path(),
        scratch.path(),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(captured.code, 3);
    assert_eq!(captured.stdout, b"out\n");
    assert_eq!(captured.stderr, b"err\n");
    let slow = ["/bin/sh".to_owned(), "-c".to_owned(), "sleep 5".to_owned()];
    assert!(run_captured(
        &slow,
        &environment,
        scratch.path(),
        scratch.path(),
        Duration::from_millis(100),
    )
    .is_none());
}
