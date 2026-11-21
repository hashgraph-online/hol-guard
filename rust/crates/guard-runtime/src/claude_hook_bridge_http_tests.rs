//! `http.client` behaviour the loopback connection reproduces.

use super::*;

fn head(lines: &[&str]) -> Vec<(String, String)> {
    let lines: Vec<Vec<u8>> = lines.iter().map(|line| line.as_bytes().to_vec()).collect();
    parse_header_block(&lines)
}

#[test]
fn int_parses_like_python() {
    assert_eq!(py_int(" 42\n"), Some(42));
    assert_eq!(py_int("+1_000"), Some(1000));
    assert_eq!(py_int("-7"), Some(-7));
    for invalid in ["", "_1", "1_", "1__0", "0x10", "1.0", "-"] {
        assert_eq!(py_int(invalid), None, "{invalid:?}");
    }
}

#[test]
fn request_target_refuses_controls_and_non_ascii() {
    assert_eq!(validate_request_target("/v1/hooks/claude-code?a=1"), Ok(()));
    assert_eq!(
        validate_request_target("/v1?a b"),
        Err(BridgeError::Value(
            "URL can't contain control characters. '/v1?a b' (found at least ' ')".to_owned()
        ))
    );
    assert_eq!(
        validate_request_target("/\u{e9}"),
        Err(BridgeError::Value(
            "'ascii' codec can't encode character '\\xe9' in position 6: ordinal not in range(128)"
                .to_owned()
        ))
    );
    assert_eq!(
        validate_request_target("/\u{e9}\u{e9}"),
        Err(BridgeError::Value(
            "'ascii' codec can't encode characters in position 6-7: ordinal not in range(128)"
                .to_owned()
        ))
    );
}

#[test]
fn header_block_folds_continuations_and_stops_at_non_headers() {
    let headers = head(&[
        "Content-Length: 5\r\n",
        "X-Long: a\r\n",
        " b\r\n",
        "not a header\r\n",
        "After: x\r\n",
    ]);
    assert_eq!(
        headers,
        [
            ("Content-Length".to_owned(), "5".to_owned()),
            ("X-Long".to_owned(), "a\r\n b".to_owned()),
        ]
    );
}

#[test]
fn response_framing_follows_http_client() {
    let framed = frame_response(200, true, &head(&["Content-Length: 12\r\n"])).unwrap();
    assert_eq!((framed.length, framed.will_close), (Some(12), false));
    let closing = frame_response(200, true, &head(&["Connection: close\r\n"])).unwrap();
    assert_eq!((closing.length, closing.will_close), (None, true));
    let old = frame_response(200, false, &head(&["Content-Length: 1\r\n"])).unwrap();
    assert!(old.will_close);
    let empty = frame_response(204, true, &[]).unwrap();
    assert_eq!(empty.length, Some(0));
    assert_eq!(
        frame_response(200, true, &head(&["Transfer-Encoding: chunked\r\n"])).unwrap_err(),
        BridgeError::Transport("chunked daemon responses are not supported".to_owned())
    );
}

#[test]
fn os_errors_render_like_python() {
    assert_eq!(
        os_error(&io::Error::from(io::ErrorKind::TimedOut)),
        "timed out"
    );
    let refused = os_error(&io::Error::from_raw_os_error(libc::ECONNREFUSED));
    assert!(
        refused.starts_with(&format!("[Errno {}] ", libc::ECONNREFUSED)),
        "{refused}"
    );
    assert!(!refused.contains("(os error"), "{refused}");
}
