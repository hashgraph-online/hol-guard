use super::browser_url_for_review;

fn opened(browser: &str, review: &str) -> String {
    browser_url_for_review(Some(browser), Some(review)).expect("link")
}

#[test]
fn a_missing_link_falls_back_to_the_other() {
    assert_eq!(browser_url_for_review(None, None), None);
    assert_eq!(
        browser_url_for_review(None, Some("http://r")).as_deref(),
        Some("http://r")
    );
    assert_eq!(
        browser_url_for_review(Some("http://b"), None).as_deref(),
        Some("http://b")
    );
}

#[test]
fn the_session_token_follows_a_loopback_alias_on_the_same_port() {
    assert_eq!(
        opened(
            "http://127.0.0.1:5474#guard-token=session-token",
            "http://localhost:5474/requests/req-localhost"
        ),
        "http://localhost:5474/requests/req-localhost#guard-token=session-token"
    );
    assert_eq!(
        opened(
            "http://0.0.0.0:5474#guard-token=t",
            "http://127.0.0.1:5474/requests/r?x=1#guard-token=old&tab=a+b"
        ),
        "http://127.0.0.1:5474/requests/r?x=1#tab=a+b&guard-token=t"
    );
    assert_eq!(
        opened("http://[::1]:5474#t=1", "http://localhost:5474/r"),
        "http://localhost:5474/r#t=1"
    );
    assert_eq!(
        opened("http://localhost#t=1", "http://127.0.0.1/r"),
        "http://127.0.0.1/r#t=1"
    );
    assert_eq!(
        opened(
            "http://localhost:05474#t=a%20b",
            "http://127.0.0.1:5474/r#u=1"
        ),
        "http://127.0.0.1:5474/r#u=1&t=a+b"
    );
}

#[test]
fn the_same_origin_carries_the_token_anywhere() {
    assert_eq!(
        opened("http://example.com#t=1", "http://example.com/r"),
        "http://example.com/r#t=1"
    );
}

#[test]
fn another_port_or_a_remote_host_opens_the_review_link_as_is() {
    for (browser, review) in [
        (
            "http://127.0.0.1:5474#guard-token=t",
            "http://127.0.0.1:5475/requests/r",
        ),
        ("http://localhost:99999#t=1", "http://127.0.0.1:99999/r"),
        ("http://localhost:x#t=1", "http://127.0.0.1:x/r"),
        ("http://example.com:80#t=1", "http://localhost:80/r"),
        ("127.0.0.1:5474#t=1", "http://127.0.0.1:5474/r"),
    ] {
        assert_eq!(opened(browser, review), review, "{browser} {review}");
    }
}

#[test]
fn an_unusable_link_keeps_the_browser_link() {
    for (browser, review) in [
        ("http://[::1:5474#t=1", "http://127.0.0.1:5474/r"),
        ("http://127.0.0.1:5474#t=1", "http://[::1/r"),
        ("http://127.0.0.1:5474#t=1", "/requests/r"),
    ] {
        assert_eq!(opened(browser, review), browser, "{browser} {review}");
    }
}

#[test]
fn the_rebuilt_link_drops_empty_parts_like_urlunparse() {
    assert_eq!(
        opened("HTTP://127.0.0.1:5474#t=1", "HTTP://127.0.0.1:5474/r;#"),
        "http://127.0.0.1:5474/r#t=1"
    );
    assert_eq!(
        opened("http://127.0.0.1:5474#t=1", "http://127.0.0.1:5474/r;p?#"),
        "http://127.0.0.1:5474/r;p#t=1"
    );
}
