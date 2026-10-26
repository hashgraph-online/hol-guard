use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use guard_command::{
    business_gmail_plain::{GmailPlainErrorV1 as Error, GmailPlainInputV1},
    business_gmail_wire::GmailSendWireInputV1,
};

fn prepare(encoding: &str, charset: &str, encoded: &[u8]) -> Result<GmailPlainInputV1, Error> {
    let mut mime = format!("From: sender@example.test\r\nTo: to@example.test\r\nCc: cc@example.test\r\nBcc: bcc@example.test\r\nContent-Type: text/plain; charset={charset}\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n").into_bytes();
    mime.extend_from_slice(encoded);
    let wire = GmailSendWireInputV1::from_owned_json(
        br#"{"userId":"me"}"#.to_vec(),
        serde_json::to_vec(&serde_json::json!({"raw": URL_SAFE_NO_PAD.encode(&mime)})).unwrap(),
    )
    .unwrap();
    GmailPlainInputV1::from_owned_wire(wire)
}

fn rejects(encoding: &str, body: &[u8], expected: Error) {
    assert!(matches!(prepare(encoding, "utf-8", body), Err(actual) if actual == expected));
}

#[test]
fn encoded_private_text_is_decoded_without_losing_original_bytes_or_roles() {
    let fixtures: &[(&str, &[u8])] = &[
        ("base64", b"Q2Fmw6kNCmxvY2FsIGZpeHR1cmU="),
        ("quoted-printable", b"Caf=C3=A9\r\nlocal=20fixture"),
    ];
    for (encoding, encoded) in fixtures {
        let input = prepare(encoding, "utf-8", encoded).unwrap();
        assert_eq!(input.body_bytes(), "Café\r\nlocal fixture".as_bytes());
        assert!(input.wire_input().mime_bytes().ends_with(encoded));
        assert_eq!(input.recipients().len(), 3);
    }
}

#[test]
fn canonical_base64_line_wrapping_and_qp_soft_breaks_have_exact_semantics() {
    assert_eq!(
        prepare("base64", "us-ascii", b"YQ==\r\n")
            .unwrap()
            .body_bytes(),
        b"a"
    );
    assert_eq!(
        prepare("base64", "us-ascii", b"YWJj\r\nZGVm")
            .unwrap()
            .body_bytes(),
        b"abcdef"
    );
    assert_eq!(
        prepare(
            "quoted-printable",
            "us-ascii",
            b"local=\r\nfixture=3Dvalue\r\n"
        )
        .unwrap()
        .body_bytes(),
        b"localfixture=value\r\n"
    );
    for encoding in ["base64", "quoted-printable"] {
        assert!(prepare(encoding, "us-ascii", b"")
            .unwrap()
            .body_bytes()
            .is_empty());
    }
}

#[test]
fn malformed_base64_never_skips_bytes_or_guesses_padding() {
    for body in [
        b"YQ".as_slice(),
        b"YR==",
        b"YQ==garbage",
        b"YQ==\t",
        b"YQ==\n",
        b"YQ==\r",
        b"\r\nYQ==",
        b"YQ==\r\nYg==",
        b"YQ==\r\n\r\n",
        b"YQ-_",
        b"YQ== ",
    ] {
        rejects("base64", body, Error::Invalid);
    }
    rejects("base64", &[b'A'; 80], Error::BoundsExceeded);
}

#[test]
fn malformed_qp_never_discards_trailing_whitespace_or_escapes() {
    for body in [
        b"=".as_slice(),
        b"=0",
        b"=GG",
        b"=c3=A9",
        b"=\n",
        b"=\r",
        b"raw\nline",
        b"raw\rline",
        b"raw \r\n",
        b"raw\t",
        &[128],
    ] {
        rejects("quoted-printable", body, Error::Invalid);
    }
    rejects("quoted-printable", &[b'a'; 77], Error::BoundsExceeded);
}

#[test]
fn validation_applies_to_decoded_content_and_charset_not_only_encoded_ascii() {
    for encoding in ["base64", "quoted-printable"] {
        let nul: &[u8] = if encoding == "base64" {
            b"AA=="
        } else {
            b"=00"
        };
        rejects(encoding, nul, Error::Invalid);
        let control: &[u8] = if encoding == "base64" {
            b"woU="
        } else {
            b"=C2=85"
        };
        rejects(encoding, control, Error::Unsupported);
        let utf8: &[u8] = if encoding == "base64" {
            b"w6k="
        } else {
            b"=C3=A9"
        };
        assert!(matches!(
            prepare(encoding, "us-ascii", utf8),
            Err(Error::Unsupported)
        ));
        let bare_lf: &[u8] = if encoding == "base64" {
            b"Cg=="
        } else {
            b"=0A"
        };
        rejects(encoding, bare_lf, Error::Invalid);
        let invalid_utf8: &[u8] = if encoding == "base64" {
            b"/w=="
        } else {
            b"=FF"
        };
        rejects(encoding, invalid_utf8, Error::Invalid);
    }
    let encoded = STANDARD.encode(vec![b'a'; 999]);
    let wrapped = encoded
        .as_bytes()
        .chunks(76)
        .map(|chunk| [chunk, b"\r\n"].concat())
        .collect::<Vec<_>>()
        .concat();
    rejects("base64", &wrapped, Error::BoundsExceeded);
}

#[test]
fn equivalent_decoded_text_keeps_distinct_original_wire_commitments() {
    let literal = prepare("7bit", "us-ascii", b"a").unwrap();
    let base64 = prepare("base64", "us-ascii", b"YQ==").unwrap();
    let qp = prepare("quoted-printable", "us-ascii", b"=61").unwrap();
    assert_eq!(literal.body_bytes(), base64.body_bytes());
    assert_eq!(literal.body_bytes(), qp.body_bytes());
    assert_ne!(literal.input_binding(), base64.input_binding());
    assert_ne!(literal.input_binding(), qp.input_binding());
    assert_ne!(base64.input_binding(), qp.input_binding());
}

#[test]
fn every_encoded_single_octet_obeys_the_same_text_profile() {
    for byte in 0u8..=255 {
        let expected_error = match byte {
            0 | 10 | 13 | 128..=255 => Some(Error::Invalid),
            1..=8 | 11..=12 | 14..=31 | 127 => Some(Error::Unsupported),
            _ => None,
        };
        let base64 = STANDARD.encode([byte]);
        let qp = format!("={byte:02X}");
        for (encoding, encoded) in [
            ("base64", base64.as_bytes()),
            ("quoted-printable", qp.as_bytes()),
        ] {
            let result = prepare(encoding, "utf-8", encoded);
            match expected_error {
                Some(expected) => assert!(matches!(result, Err(actual) if actual == expected)),
                None => assert_eq!(result.unwrap().body_bytes(), &[byte]),
            }
        }
    }
}
