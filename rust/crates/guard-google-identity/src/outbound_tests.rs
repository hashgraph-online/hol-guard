use super::worker_input_tests::{command, credential};
use crate::outbound::OutboundInspectionError;
use base64ct::{Base64, Base64UrlUnpadded, Encoding};

// Existing native scanner synthetic canary; never a real provider credential.
const CANARY: &str = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz012345";

fn encoded_command(subject: &str, encoding: &str, body: &str) -> String {
    let mime = format!("From: sender@work.example\r\nTo: recipient@work.example\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n{body}");
    let raw = Base64UrlUnpadded::encode_string(mime.as_bytes());
    format!("gws gmail users messages send --params '{{\"userId\":\"me\"}}' --json '{{\"raw\":\"{raw}\"}}'")
}

#[test]
fn outbound_canary_is_refused_in_headers_plain_and_decoded_transfer_bodies() {
    let sources = [
        command("sender@work.example", CANARY),
        encoded_command(CANARY, "7bit", "ordinary body"),
        encoded_command(
            "ordinary",
            "base64",
            &Base64::encode_string(CANARY.as_bytes()),
        ),
        encoded_command("ordinary", "quoted-printable", &CANARY.replace('_', "=5F")),
    ];
    for source in sources {
        let input = credential("subject-one").prepare_command(source).unwrap();
        assert_eq!(
            input.inspect_outbound().err(),
            Some(OutboundInspectionError::CredentialDetected)
        );
    }
}

#[test]
fn ordinary_security_discussion_retains_owned_input_and_versioned_inspection() {
    let source = command(
        "sender@work.example",
        "Please explain credential rotation without sharing any token.",
    );
    let inspected = credential("subject-one")
        .prepare_command(source.clone())
        .unwrap()
        .inspect_outbound()
        .unwrap();
    assert!(inspected.input().is_current());
    assert_eq!(inspected.inspection_binding().len(), 64);
    assert!(!inspected.detector_version().is_empty());
    let same = credential("subject-one")
        .prepare_command(source)
        .unwrap()
        .inspect_outbound()
        .unwrap();
    assert_eq!(inspected.inspection_binding(), same.inspection_binding());
    let changed = credential("subject-one")
        .prepare_command(command("sender@work.example", "changed text"))
        .unwrap()
        .inspect_outbound()
        .unwrap();
    assert_ne!(inspected.inspection_binding(), changed.inspection_binding());
}

#[test]
fn encoded_header_words_cannot_bypass_credential_inspection() {
    for subject in [
        format!("=?UTF-8?B?{}?=", Base64::encode_string(CANARY.as_bytes())),
        format!("=?UTF-8?Q?{}?=", CANARY.replace('_', "=5F")),
        "=?UTF-8?B?b3JkaW5hcnk=?=".into(),
    ] {
        let input = credential("subject-one")
            .prepare_command(encoded_command(&subject, "7bit", "body"))
            .unwrap();
        assert_eq!(
            input.inspect_outbound().err(),
            Some(OutboundInspectionError::UnsupportedEncoding)
        );
    }
}
