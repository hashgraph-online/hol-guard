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
fn a_garbled_request_is_a_bad_request() {
    let answer = own_answer(b"\x01\x02\r\n\r\n", None).unwrap();
    assert!(answer.starts_with(b"HTTP/1.0 400 "));
}

#[test]
fn an_unsupported_method_is_not_implemented() {
    let answer = own_answer(b"PUT /v1/x HTTP/1.0\r\n\r\n", None).unwrap();
    assert!(answer.starts_with(b"HTTP/1.0 501 "));
    assert!(own_answer(b"GET /v1/x HTTP/1.0\r\n\r\n", None).is_none());
    assert!(empty_response(404, None, &[]).starts_with(b"HTTP/1.0 404 Not Found\r\n"));
}

#[test]
fn a_preflight_needs_an_origin() {
    let answer = own_answer(b"OPTIONS /v1/x HTTP/1.0\r\n\r\n", None).unwrap();
    assert!(answer.starts_with(b"HTTP/1.0 400 "));
    let refused = own_answer(
        b"OPTIONS /v1/x HTTP/1.0\r\nOrigin: https://evil.example\r\n\r\n",
        None,
    )
    .unwrap();
    assert!(refused.starts_with(b"HTTP/1.0 403 "));
}
