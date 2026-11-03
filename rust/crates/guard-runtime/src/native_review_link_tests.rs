use serde_json::Value;

use super::*;

const VECTORS: &str =
    include_str!("../testdata/native_review_link/native_review_link_vectors.json");

fn document() -> Value {
    serde_json::from_str(VECTORS).expect("vectors parse")
}

fn text<'a>(vector: &'a Value, key: &str) -> &'a str {
    vector[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is text"))
}

fn micros(vector: &Value) -> i64 {
    vector["now_micros"].as_i64().expect("now_micros")
}

#[test]
fn session_tokens_match_the_daemon() {
    let document = document();
    let sessions = document["sessions"].as_array().expect("sessions");
    assert!(!sessions.is_empty());
    for vector in sessions {
        let token = session_token(
            text(vector, "auth_token"),
            text(vector, "surface"),
            micros(vector),
        );
        assert_eq!(token.as_deref(), vector["expected"].as_str());
    }
}

#[test]
fn review_reasons_match_the_daemon() {
    let document = document();
    let reasons = document["reasons"].as_array().expect("reasons");
    assert!(!reasons.is_empty());
    for vector in reasons {
        let reason = native_review_reason(
            text(vector, "harness"),
            text(vector, "reason"),
            text(vector, "approval_url"),
            vector["auth_token"].as_str(),
            micros(vector),
        );
        assert_eq!(
            reason.as_deref(),
            vector["expected"].as_str(),
            "{} {:?} {}",
            text(vector, "harness"),
            text(vector, "reason"),
            text(vector, "approval_url"),
        );
    }
}

#[test]
fn links_it_cannot_reproduce_are_left_unlinked() {
    for url in [
        "http://127.0.0.1:4781/requests/r1?x=1",
        "http://127.0.0.1:4781/requests/r1#guard-token=old",
        "http://127.0.0.1:4781/requests/r1;p",
        "http://user@127.0.0.1:4781/requests/r1",
        "http://127.0.0.1:/requests/r1",
        "http://[::2]:4781/requests/r1",
        "http://127.0.0.1:4781/requests/r%201",
        "HTTP://127.0.0.1:4781/requests/r1",
        "ftp://127.0.0.1/requests/r1",
        "http:///requests/r1",
        " http://127.0.0.1:4781/requests/r1",
    ] {
        let reason = native_review_reason("codex", "Review.", url, Some("key"), 0);
        assert_eq!(reason, None, "{url}");
    }
}

#[test]
fn codex_loopback_links_need_the_key() {
    let url = "http://127.0.0.1:4781/requests/r1";
    let unsigned = native_review_reason("codex", "Review.", url, None, 0).expect("reason");
    assert!(unsigned.ends_with(SIGNED_LINK_UNAVAILABLE));
    assert!(!unsigned.contains(url));
    let signed = native_review_reason("codex", "Review.", url, Some("key"), 0).expect("reason");
    assert!(signed.contains(&format!("{url}#guard-token={SESSION_PREFIX}.")));
}

#[test]
fn loopback_links_the_client_would_sign_are_never_shown_unsigned() {
    for url in [
        "http://127.0.0.1:4781/approvals/a?b=c",
        "http://localhost:4781/approvals/a#guard-token=old",
        "HTTP://127.0.0.1:4781/approvals/a",
        "http://user@[::1]:4781/approvals/a%20b",
        " \x01http://127.0.0.1:4781/approvals/a",
    ] {
        assert_eq!(live_review_url(url, Some("key"), 0), None, "{url}");
        assert_eq!(live_review_url(url, None, 0).as_deref(), Some(url), "{url}");
    }
    for url in [
        "https://guard.example/approvals/a?b=c",
        "http://[::2]:4781/approvals/a?b=c",
        "ftp://127.0.0.1/approvals/a",
    ] {
        assert_eq!(
            live_review_url(url, Some("key"), 0).as_deref(),
            Some(url),
            "{url}"
        );
    }
    let signed = live_review_url("http://127.0.0.1:4781/approvals/a", Some("key"), 0).unwrap();
    assert!(signed.starts_with("http://127.0.0.1:4781/approvals/a#guard-token=gld1."));
}

/// The strip the Python fail-closed fallback replays, recorded in
/// `tests/fixtures/guard-review-link-strip.v1.json` and read by
/// `tests/test_review_link_strip_parity.py` as well. The fallback composes the
/// agent's deny text without the resident, so the two must not drift.
mod review_link_strip_parity {
    use serde_json::Value;

    use crate::native_review_link::without_raw_url;

    const STRIP_VECTORS: &str =
        include_str!("../../../../tests/fixtures/guard-review-link-strip.v1.json");

    fn field<'a>(case: &'a Value, key: &str) -> &'a str {
        case[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} is text"))
    }

    #[test]
    fn without_raw_url_matches_the_recorded_strip() {
        let document: Value = serde_json::from_str(STRIP_VECTORS).expect("strip vectors parse");
        assert_eq!(document["schema"], "guard-review-link-strip-parity.v1");
        let cases = document["cases"].as_array().expect("cases is a list");
        assert!(!cases.is_empty(), "the fixture records at least one case");
        for case in cases {
            let name = field(case, "name");
            assert_eq!(
                without_raw_url(field(case, "reason"), field(case, "approval_url")),
                field(case, "stripped"),
                "{name}"
            );
        }
    }
}

#[test]
fn a_loopback_approval_link_opens_only_once_it_is_signed() {
    let document = document();
    let vector = &document["sessions"][0];
    let url = "http://127.0.0.1:5475/requests/req-1";
    let auth_token = text(vector, "auth_token");
    let surface = text(vector, "surface");
    let expected = session_token(auth_token, surface, micros(vector))
        .map(|session| format!("{url}#guard-token={session}"));
    assert!(expected.is_some());
    assert_eq!(
        approval_browser_url(url, || Some(auth_token.to_owned()), surface, micros(vector)),
        expected
    );
    // No daemon auth token: there is no signed link to open, and the
    // unsigned one is never handed to the browser.
    assert_eq!(
        approval_browser_url(url, || None, surface, micros(vector)),
        None
    );
}
