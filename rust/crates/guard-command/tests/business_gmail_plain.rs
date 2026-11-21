use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use guard_command::{
    business_gmail_plain::{GmailPlainErrorV1 as Error, GmailPlainInputV1},
    business_gmail_wire::GmailSendWireInputV1,
};
use guard_contracts::BusinessRecipientKindV1 as Kind;

fn wire(mime: &[u8], thread: Option<&str>) -> GmailSendWireInputV1 {
    let mut body = serde_json::json!({"raw": URL_SAFE_NO_PAD.encode(mime)});
    if let Some(thread) = thread {
        body["threadId"] = thread.into();
    }
    GmailSendWireInputV1::from_owned_json(
        br#"{"userId":"me"}"#.to_vec(),
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}
fn prepare(mime: &[u8]) -> Result<GmailPlainInputV1, Error> {
    GmailPlainInputV1::from_owned_wire(wire(mime, None))
}
fn rejects(mime: &[u8], expected: Error) {
    assert!(matches!(prepare(mime), Err(actual) if actual == expected));
}
const BASIC: &[u8] = b"From: sender@example.test\r\nTo: recipient@example.test\r\nSubject: Local fixture\r\n\r\nPrivate fixture body";

#[test]
fn private_wire_and_complete_recipient_roles_survive_extraction() {
    let mime = b"From: sender@example.test\r\nTo: a@example.test, b@example.test\r\nCc: a@example.test\r\nBcc: hidden@example.test\r\n\r\nprivate";
    let input = prepare(mime).unwrap();
    assert_eq!(input.sender(), "sender@example.test");
    assert_eq!(input.wire_input().mime_bytes(), mime);
    assert_eq!(input.body_bytes(), b"private");
    let recipients: Vec<_> = input
        .recipients()
        .iter()
        .map(|r| (r.address(), r.kind()))
        .collect();
    assert_eq!(
        recipients,
        [
            ("a@example.test", Kind::To),
            ("b@example.test", Kind::To),
            ("a@example.test", Kind::Cc),
            ("hidden@example.test", Kind::Bcc)
        ]
    );
}

#[test]
fn bcc_only_send_and_empty_body_keep_explicit_audience() {
    let input = prepare(b"From: s@example.test\r\nBcc: h@example.test\r\n\r\n").unwrap();
    assert_eq!(input.recipients().len(), 1);
    assert_eq!(input.recipients()[0].kind(), Kind::Bcc);
    assert!(input.body_bytes().is_empty());
    rejects(
        b"From: s@example.test\r\nSubject: fixture\r\n\r\nbody",
        Error::Invalid,
    );
    rejects(b"To: a@example.test\r\n\r\nbody", Error::Invalid);
}

#[test]
fn body_charset_and_encoding_must_be_explicit_and_agree() {
    let header = "From: s@example.test\r\nTo: a@example.test\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\nContent-Transfer-Encoding: 8bit\r\n\r\n";
    let mime = format!("{header}Café");
    assert_eq!(
        prepare(mime.as_bytes()).unwrap().body_bytes(),
        "Café".as_bytes()
    );
    rejects(
        "From: s@example.test\r\nTo: a@example.test\r\n\r\nCafé".as_bytes(),
        Error::Unsupported,
    );
    rejects(mime.replace("8bit", "7bit").as_bytes(), Error::Unsupported);
    rejects(
        mime.replace("UTF-8", "us-ascii").as_bytes(),
        Error::Unsupported,
    );
    for control in ['\u{0080}', '\u{0085}', '\u{009f}', '\u{2028}', '\u{2029}'] {
        let unicode_control = format!("{header}ok{control}still-control");
        rejects(unicode_control.as_bytes(), Error::Unsupported);
    }
    let mut invalid = BASIC.to_vec();
    invalid.push(255);
    rejects(&invalid, Error::Invalid);
    let mut nul = BASIC.to_vec();
    nul.push(0);
    rejects(&nul, Error::Invalid);
    for body in [b"one\ntwo".as_slice(), b"one\rtwo"] {
        let mime = [
            b"From: s@example.test\r\nTo: a@example.test\r\n\r\n".as_slice(),
            body,
        ]
        .concat();
        rejects(&mime, Error::Invalid);
    }
    let lines = b"From: s@example.test\r\nTo: a@example.test\r\n\r\none\r\n\ttwo\r\n";
    assert_eq!(prepare(lines).unwrap().body_bytes(), b"one\r\n\ttwo\r\n");
    rejects(&[BASIC, &[27]].concat(), Error::Unsupported);
    let long = format!(
        "From: s@example.test\r\nTo: a@example.test\r\n\r\n{}",
        "x".repeat(999)
    );
    rejects(long.as_bytes(), Error::BoundsExceeded);
}

#[test]
fn duplicate_headers_and_ambiguous_framing_never_choose_first_value() {
    for key in [
        "From",
        "To",
        "Cc",
        "Bcc",
        "Subject",
        "Content-Type",
        "Content-Transfer-Encoding",
    ] {
        let mime = format!(
            "From: s@example.test\r\nTo: a@example.test\r\n{key}: first\r\n{}: second\r\n\r\nbody",
            key.to_lowercase()
        );
        rejects(mime.as_bytes(), Error::Invalid);
    }
    rejects(
        b"From: s@example.test\nTo: a@example.test\n\nbody",
        Error::Invalid,
    );
    rejects(
        b"From: s@example.test\r\nTo : a@example.test\r\n\r\nbody",
        Error::Invalid,
    );
    rejects(
        b"From: s@example.test\r\nTo: a@example.test\nBcc: h@example.test\r\n\r\nbody",
        Error::Unsupported,
    );
}

#[test]
fn attachments_multipart_html_and_unknown_transfer_encodings_are_unsupported() {
    for header in [
        "Content-Type: multipart/mixed; boundary=fixture",
        "Content-Type: text/html",
        "Content-Type: text/plain; charset=utf-8; charset=us-ascii",
        "Content-Disposition: attachment; filename=fixture.txt",
        "Content-Transfer-Encoding: unknown",
        "MIME-Version: 2.0",
        "X-Unknown-Routing: fixture",
    ] {
        let mime = format!("From: s@example.test\r\nTo: a@example.test\r\n{header}\r\n\r\nbody");
        rejects(mime.as_bytes(), Error::Unsupported);
    }
}

#[test]
fn groups_display_words_obsolete_forms_and_invalid_mailboxes_are_unsupported() {
    for address in [
        "",
        "group: a@example.test;",
        "Name <a@example.test>",
        "=?UTF-8?B?YSxi?= <a@example.test>",
        "a(comment)@example.test",
        "a@local",
        "a..b@example.test",
        ".a@example.test",
        "a@-example.test",
        "a@example..test",
        "a@example.test,",
        "a@@example.test",
        "a@example.test\r\n b@example.test",
        "\"quoted local\"@example.test",
    ] {
        let mime = format!("From: s@example.test\r\nTo: {address}\r\n\r\nbody");
        assert!(
            prepare(mime.as_bytes()).is_err(),
            "unsupported fixture accepted"
        );
    }
    rejects(
        b"From: a@example.test, b@example.test\r\nTo: a@example.test\r\n\r\nbody",
        Error::Invalid,
    );
}

#[test]
fn reply_thread_and_resend_headers_cannot_hide_extra_semantics() {
    assert!(matches!(
        GmailPlainInputV1::from_owned_wire(wire(BASIC, Some("thread-fixture"))),
        Err(Error::Unsupported)
    ));
    for name in [
        "Reply-To",
        "In-Reply-To",
        "References",
        "Resent-To",
        "Resent-Bcc",
        "Sender",
        "Return-Path",
    ] {
        let mime = format!(
            "From: s@example.test\r\nTo: a@example.test\r\n{name}: hidden@example.test\r\n\r\nbody"
        );
        rejects(mime.as_bytes(), Error::Unsupported);
    }
}

#[test]
fn limits_apply_before_address_parsing_and_keep_combined_recipient_count() {
    let line = format!(
        "From: s@example.test\r\nTo: a@example.test\r\nSubject: {}\r\n\r\nbody",
        "s".repeat(1000)
    );
    rejects(line.as_bytes(), Error::BoundsExceeded);
    // Each individual header fits its line cap; the total repeats count, too.
    let values = vec!["a@b.c"; 86].join(",");
    let mime = format!(
        "From: s@example.test\r\nTo: {values}\r\nCc: {values}\r\nBcc: {values}\r\n\r\nbody"
    );
    rejects(mime.as_bytes(), Error::BoundsExceeded);
    let values = vec!["a@b.c"; 85].join(",");
    let mime = format!(
        "From: s@example.test\r\nTo: {values}\r\nCc: {values}\r\nBcc: {values},a@b.c\r\n\r\nbody"
    );
    assert_eq!(prepare(mime.as_bytes()).unwrap().recipients().len(), 256);
}

#[test]
fn every_private_wire_byte_changes_the_profile_commitment() {
    let a = prepare(BASIC).unwrap();
    let b = prepare(&[BASIC, b"!"].concat()).unwrap();
    assert_ne!(a.input_binding(), b.input_binding());
    assert_eq!(a.input_binding().len(), 64);
    assert_eq!(format!("{:?}", Error::Unsupported), "Unsupported");
}
