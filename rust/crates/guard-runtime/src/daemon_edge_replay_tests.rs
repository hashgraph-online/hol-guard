use super::*;

#[test]
fn head_end_is_after_the_blank_line() {
    assert_eq!(find_head_end(b"GET / HTTP/1.0\r\n\r\nbody"), Some(18));
    assert_eq!(find_head_end(b"GET / HTTP/1.0\r\n"), None);
}

#[test]
fn content_length_needs_exactly_one_number() {
    let head = b"POST /v1/x HTTP/1.0\r\ncontent-length: 12\r\n\r\n";
    assert_eq!(content_length(head), Some(12));
    let doubled = b"POST /v1/x HTTP/1.0\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n";
    assert_eq!(content_length(doubled), None);
    assert_eq!(content_length(b"GET / HTTP/1.0\r\n\r\n"), None);
    let bad = b"POST / HTTP/1.0\r\nContent-Length: x\r\n\r\n";
    assert_eq!(content_length(bad), None);
}

#[test]
fn replay_names_the_home_and_port() {
    assert_eq!(
        replay_args("/h", 5474),
        [
            "desktop",
            "daemon-replay",
            "--guard-home",
            "/h",
            "--port",
            "5474"
        ]
    );
}

#[test]
fn the_unavailable_answer_declares_its_body() {
    let head_len = find_head_end(UNAVAILABLE).unwrap();
    assert_eq!(
        content_length(&UNAVAILABLE[..head_len]),
        Some(UNAVAILABLE.len() - head_len)
    );
}
