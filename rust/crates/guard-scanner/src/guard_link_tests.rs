use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{is_guard_link, LINKED_SURFACES, SESSION_PAYLOAD_PREFIX};
use crate::scan_text;
use guard_rules::MAX_SCAN_BYTES;

const PAYLOAD_START: &str =
    r#"{"aud":"guard-local-daemon","version":"guard-local-daemon-session.v1","surface":""#;

/// An approval-center session token.
fn session_token() -> String {
    surface_token("approval-center")
}

/// A dashboard session token for `surface`, signed the way Guard signs one
/// and assembled at run time so the repository holds no token-shaped text.
fn surface_token(surface: &str) -> String {
    let payload = format!(
        r#"{PAYLOAD_START}{surface}","expires_at":"2026-10-18T12:00:00+00:00","session_started_at":"2026-10-18T00:00:00+00:00"}}"#
    );
    let encoded = Base64UrlUnpadded::encode_string(payload.as_bytes());
    let mut mac = <Hmac<Sha256>>::new_from_slice(b"test-only").expect("hmac key");
    mac.update(encoded.as_bytes());
    let signature = Base64UrlUnpadded::encode_string(&mac.finalize().into_bytes());
    format!("gld1.{encoded}.{signature}")
}

/// Guard's reason for a held tool call, linking to `page`.
fn block_reason(page: &str, token: &str) -> String {
    format!(
        "HOL Guard needs fresh approval for this connected tool. \
         Open HOL Guard to approve or keep this blocked: {page}#guard-token={token}."
    )
}

fn credential_assignment(text: &str) -> bool {
    [true, false].into_iter().any(|local_content| {
        scan_text(text, local_content, true, MAX_SCAN_BYTES, None)
            .matches
            .iter()
            .any(|matched| matched.classifier == "credential-assignment")
    })
}

#[test]
fn the_prefixes_are_the_start_of_guard_session_payloads() {
    assert_eq!(PAYLOAD_START.len() % 3, 0);
    assert_eq!(
        Base64UrlUnpadded::encode_string(PAYLOAD_START.as_bytes()),
        SESSION_PAYLOAD_PREFIX
    );
    for (surface, encoded) in ["approval-center", "protection-repair"]
        .into_iter()
        .zip(LINKED_SURFACES)
    {
        let start = format!(r#"{PAYLOAD_START}{surface}","expires_at":""#);
        let whole = &start.as_bytes()[..start.len() / 3 * 3];
        assert_eq!(
            Base64UrlUnpadded::encode_string(whole),
            format!("{SESSION_PAYLOAD_PREFIX}{encoded}"),
            "{surface}"
        );
    }
}

#[test]
fn guards_own_approval_link_is_not_a_credential() {
    let token = session_token();
    for page in [
        "http://127.0.0.1:4781/requests/req-1",
        "http://localhost:4781/approvals/a1",
        "http://[::1]:4781/requests/req-1",
        "https://127.0.0.1/requests/req-1",
    ] {
        let reason = block_reason(page, &token);
        assert!(!credential_assignment(&reason), "{page}");
        // Oh My Pi returns the reason as the tool's output, quoted in JSON.
        let output = serde_json::json!({ "error": reason }).to_string();
        assert!(!credential_assignment(&output), "{page} as JSON");
    }
    let bare = format!(
        "{}#guard-token={token}",
        "http://127.0.0.1:4781/requests/req-1"
    );
    assert!(!credential_assignment(&bare));
    // A tampered-protection block links to the repair page the same way.
    let repair = format!(
        "HOL Guard blocked this action because trusted protection settings need repair. \
         Open this local page and press Repair protection: \
         http://127.0.0.1:4781/protection/repair#guard-token={}.",
        surface_token("protection-repair")
    );
    assert!(!credential_assignment(&repair));
}

#[test]
fn the_token_anywhere_but_a_loopback_link_still_counts() {
    let token = session_token();
    for page in [
        "http://nas.local:4781/requests/req-1",
        "http://127.0.0.1.example.test/requests/req-1",
        "http://user@127.0.0.1:4781/requests/req-1",
        "http://127.0.0.1:4781/requests/req-1?next=x",
        "ftp://127.0.0.1/requests/req-1",
        "http://evil.example/?next=http://127.0.0.1/requests/req-1",
        "http://evil.example/http://127.0.0.1/requests/req-1",
        "xhttp://127.0.0.1/requests/req-1",
    ] {
        assert!(credential_assignment(&block_reason(page, &token)), "{page}");
    }
    assert!(credential_assignment(&format!("guard-token={token}")));
    assert!(credential_assignment(&format!(
        "http://127.0.0.1:4781/requests/req-1?guard-token={token}"
    )));
}

#[test]
fn other_values_in_a_loopback_link_still_count() {
    let page = "http://127.0.0.1:4781/requests/req-1";
    let token = session_token();
    let (head, signature) = token.rsplit_once('.').expect("signature");
    let payload = head.split_once('.').expect("prefix").1;
    let literal = ["hunter2", "-production", "-value"].concat();
    for value in [
        literal.clone(),
        format!("gld1.{literal}.{signature}"),
        format!("gld1.{payload}.{}", &signature[1..]),
        format!("gld2.{payload}.{signature}"),
        format!("{token}.extra"),
        surface_token("settings"),
        surface_token("approval-center-x"),
    ] {
        assert!(
            credential_assignment(&block_reason(page, &value)),
            "{value}"
        );
    }
    let api = format!("{page}#api_token={literal}");
    assert!(credential_assignment(&api));
}

#[test]
fn only_a_guard_token_fragment_is_considered() {
    let token = session_token();
    let page = "http://127.0.0.1:4781/requests/req-1#";
    assert!(is_guard_link(&format!("guard-token={token}"), page));
    assert!(is_guard_link(&format!("guard-token={token}."), page));
    assert!(!is_guard_link(&format!("auth_token={token}"), page));
    assert!(!is_guard_link(&format!("Guard-Token={token}"), page));
    assert!(!is_guard_link(
        &format!("guard-token={token}"),
        &page[..page.len() - 1]
    ));
}

#[test]
fn a_multibyte_character_before_the_link_is_read_whole() {
    let token = session_token();
    let page = "http://127.0.0.1:4781/requests/req-1";
    // A no-break space separates the link like any other whitespace.
    let spaced = format!("Open HOL Guard:\u{a0}{page}#guard-token={token}.");
    assert!(!credential_assignment(&spaced));
    // A letter or arrow glued to the scheme does not start a URL.
    for glued in ["é", "→"] {
        let text = format!("Open HOL Guard {glued}{page}#guard-token={token}.");
        assert!(credential_assignment(&text), "{glued}");
    }
}
