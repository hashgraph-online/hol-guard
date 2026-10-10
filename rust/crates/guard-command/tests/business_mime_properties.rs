//! Seeded generated-input checks for the plain MIME profile of a Gmail send.

#[path = "support/business_properties.rs"]
mod business_properties;

use business_properties::{plain, Rng, CASES};
use guard_command::business_gmail_plain::GmailPlainErrorV1;
use guard_contracts::BusinessRecipientKindV1;

struct Message {
    headers: Vec<String>,
    recipients: Vec<(String, BusinessRecipientKindV1)>,
}

fn generated_message(rng: &mut Rng) -> Message {
    let mut headers = vec!["From: sender@example.test".to_owned()];
    let mut recipients = Vec::new();
    let mut next = 0;
    for (name, kind) in [
        ("To", BusinessRecipientKindV1::To),
        ("Cc", BusinessRecipientKindV1::Cc),
        ("Bcc", BusinessRecipientKindV1::Bcc),
    ] {
        if name != "To" && rng.below(2) == 0 {
            continue;
        }
        let mut addresses = Vec::new();
        for _ in 0..1 + rng.below(6) {
            let address = format!("user{next}@example.test");
            next += 1;
            recipients.push((address.clone(), kind));
            addresses.push(address);
        }
        headers.push(format!("{name}: {}", addresses.join(", ")));
    }
    if rng.below(2) == 0 {
        headers.push("Subject: generated fixture".to_owned());
    }
    if rng.below(2) == 0 {
        headers.push("MIME-Version: 1.0".to_owned());
    }
    // Header order is free, so shuffle every header; recipients must come back
    // in header source order, then source order within each header.
    for i in (1..headers.len()).rev() {
        headers.swap(i, rng.below(i + 1));
    }
    let order: Vec<&str> = headers
        .iter()
        .map(|h| h.split(':').next().unwrap())
        .collect();
    recipients.sort_by_key(|(_, kind)| {
        order
            .iter()
            .position(|name| match kind {
                BusinessRecipientKindV1::To => *name == "To",
                BusinessRecipientKindV1::Cc => *name == "Cc",
                _ => *name == "Bcc",
            })
            .unwrap()
    });
    Message {
        headers,
        recipients,
    }
}

fn render(headers: &[String], body: &str) -> Vec<u8> {
    format!("{}\r\n\r\n{body}", headers.join("\r\n")).into_bytes()
}

#[test]
fn generated_plain_messages_extract_every_recipient_in_order() {
    for case in 0..CASES {
        let mut rng = Rng::for_case(10, case);
        let message = generated_message(&mut rng);
        let input = plain(&render(&message.headers, "line one\r\nline two"))
            .unwrap_or_else(|error| panic!("case {case}: {error:?} {:?}", message.headers));
        assert_eq!(input.sender(), "sender@example.test");
        let actual: Vec<_> = input
            .recipients()
            .iter()
            .map(|r| (r.address().to_owned(), r.kind()))
            .collect();
        assert_eq!(actual, message.recipients, "case {case}");
        assert_eq!(input.body_bytes(), b"line one\r\nline two");
    }
}

#[test]
fn repeated_unknown_and_folded_headers_fail_closed() {
    for case in 0..CASES {
        let mut rng = Rng::for_case(11, case);
        let message = generated_message(&mut rng);
        let mut headers = message.headers.clone();
        let (header, expected) = match rng.below(4) {
            0 => {
                let original = rng.pick(&message.headers).clone();
                let (name, value) = original.split_once(':').unwrap();
                let name = if rng.below(2) == 0 {
                    name.to_ascii_uppercase()
                } else {
                    name.to_ascii_lowercase()
                };
                (format!("{name}:{value}"), GmailPlainErrorV1::Invalid)
            }
            1 => (
                (*rng.pick(&[
                    "Reply-To: other@example.test",
                    "Resent-To: other@example.test",
                    "Sender: other@example.test",
                    "X-Forward: other@example.test",
                    "Content-Disposition: attachment",
                ]))
                .to_owned(),
                GmailPlainErrorV1::Unsupported,
            ),
            2 => (
                " folded@example.test".to_owned(),
                GmailPlainErrorV1::Invalid,
            ),
            _ => {
                // Replace the existing To header in place so the only defect is
                // an address form outside the bare-mailbox profile, not a
                // duplicate header.
                let at = headers.iter().position(|h| h.starts_with("To:")).unwrap();
                let address = *rng.pick(&[
                    "Name <n@example.test>",
                    "<n@example.test>",
                    "\"q\"@example.test",
                    "n@example.test (comment)",
                    "group: n@example.test;",
                ]);
                headers[at] = format!("To: {address}");
                (String::new(), GmailPlainErrorV1::Unsupported)
            }
        };
        if !header.is_empty() {
            let at = rng.below(headers.len() + 1);
            headers.insert(at, header);
        }
        let result = plain(&render(&headers, "body"));
        assert_eq!(result.err(), Some(expected), "case {case}: {headers:?}");
    }
}

#[test]
fn mutated_mime_never_panics_and_accepted_results_keep_invariants() {
    let mut accepted = 0;
    for case in 0..CASES * 4 {
        let mut rng = Rng::for_case(12, case);
        let message = generated_message(&mut rng);
        let mut mime = render(&message.headers, "body text");
        for _ in 0..1 + rng.below(3) {
            let at = rng.below(mime.len() + 1);
            match rng.below(3) {
                0 => mime.insert(at, *rng.pick(b"\r\n\0\t ,:<>\"=?\x7f\xff")),
                1 if at < mime.len() => {
                    mime.remove(at);
                }
                _ => {
                    let fragment = *rng.pick(&[
                        "=?utf-8?q?x?=",
                        "\r\nBcc: hidden@example.test",
                        "\r\n\r\n",
                        "é",
                        "\u{2028}",
                        "\r\nContent-Transfer-Encoding: base64",
                        "\r\nContent-Type: multipart/mixed",
                    ]);
                    mime.splice(at..at, fragment.bytes());
                }
            }
        }
        let Ok(input) = plain(&mime) else {
            continue;
        };
        accepted += 1;
        assert_eq!(input.wire_input().mime_bytes(), mime, "case {case}");
        assert!(!input.recipients().is_empty(), "case {case}");
        assert!(input.recipients().len() <= 256, "case {case}");
        for recipient in input.recipients() {
            assert!(recipient.address().is_ascii(), "case {case}");
            assert!(!recipient.address().contains([',', '<', '>', ' ']));
        }
        assert!(!input.body_bytes().contains(&0), "case {case}");
        assert!(
            std::str::from_utf8(input.body_bytes()).is_ok(),
            "case {case}"
        );
        let again = plain(&mime).unwrap();
        assert_eq!(again.input_binding(), input.input_binding(), "case {case}");
    }
    assert!(accepted > 0);
}

#[test]
fn recipient_and_header_counts_are_bounded() {
    let to: Vec<String> = (0..257).map(|n| format!("a{n}@x.io")).collect();
    // Split across To/Cc so each header line stays under the line bound while
    // the combined recipient list exceeds the action item bound.
    let headers = vec![
        "From: sender@example.test".to_owned(),
        format!("To: {}", to[..86].join(", ")),
        format!("Cc: {}", to[86..172].join(", ")),
        format!("Bcc: {}", to[172..].join(", ")),
    ];
    assert!(headers.iter().all(|h| h.len() <= 998));
    assert_eq!(
        plain(&render(&headers, "body")).err(),
        Some(GmailPlainErrorV1::BoundsExceeded)
    );
    let mut headers = vec![
        "From: sender@example.test".to_owned(),
        "To: r@example.test".to_owned(),
    ];
    headers.push(format!("Subject: {}", "s".repeat(999)));
    assert_eq!(
        plain(&render(&headers, "body")).err(),
        Some(GmailPlainErrorV1::BoundsExceeded)
    );
}
