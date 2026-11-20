use super::*;

fn stream(bytes: &[u8]) -> File {
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(bytes).unwrap();
    file
}

#[test]
fn replayed_output_is_display_safe() {
    assert_eq!(display_text(b"a\r\nb\x1b[0m\tc\n"), "a\nb\u{fffd}[0m\tc\n");
    assert_eq!(display_text(b"\xff"), "\u{fffd}");
}

#[test]
fn a_stream_is_read_up_to_its_limit() {
    assert_eq!(read(stream(b"abcdef"), 4), (b"abcd".to_vec(), true));
    assert_eq!(read(stream(b"abcd"), 4), (b"abcd".to_vec(), false));
}

#[test]
fn a_filter_chain_reads_the_whole_raw_stream() {
    let mut written = b"x\n".repeat(OUTPUT_LIMIT);
    written.extend_from_slice(b"\x1b[0mend\r\n");
    let shaping = Shaping::default();
    assert!(shaping.enter(false, true));
    let checked = shaping.replay_out(stream(&written));
    let (captured, cut) = shaping.leave();
    assert!(!cut);
    // The denial check still reads the first `OUTPUT_LIMIT` bytes.
    assert_eq!(checked.len(), OUTPUT_LIMIT);
    assert_eq!(captured, written);
    let last = super::super::filters::lines(&captured);
    assert_eq!(
        super::super::filters::keep(&last, "tail", 1),
        [&b"\x1b[0mend\r\n"[..]]
    );
}

#[test]
fn a_chain_result_is_limited_and_made_display_text() {
    let shaping = Shaping::default();
    assert!(shaping.enter(false, true));
    shaping.show(b"\x1b[0mend\r\n", false);
    assert_eq!(shaping.leave().0, "\u{fffd}[0mend\n".as_bytes());
    assert!(shaping.enter(false, true));
    shaping.show(&b"y".repeat(OUTPUT_LIMIT + 1), false);
    let (shown, _) = shaping.leave();
    assert_eq!(shown.len(), OUTPUT_LIMIT + TRUNCATED.len());
    assert!(shown.ends_with(TRUNCATED.as_bytes()));
}

#[test]
fn a_cut_capture_is_noted_after_the_chain_not_in_its_input() {
    let shaping = Shaping::default();
    assert!(shaping.enter(true, true));
    shaping.replay_out(stream(&b"x".repeat(CAPTURE_LIMIT + 1)));
    shaping.replay_err(stream(b"FAILED\n"));
    let (captured, cut) = shaping.leave();
    assert!(cut);
    assert_eq!(captured.len(), CAPTURE_LIMIT + b"FAILED\n".len());
    assert!(captured.ends_with(b"xFAILED\n"));
    // A filter that keeps nothing still shows the notice.
    assert!(shaping.enter(false, true));
    shaping.show(b"", cut);
    assert_eq!(shaping.leave().0, TRUNCATED.as_bytes());
}
