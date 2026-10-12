//! Seeded generated-input checks for Content-Transfer-Encoding decoding in the
//! plain MIME profile.

#[path = "support/business_properties.rs"]
mod business_properties;

use base64::{engine::general_purpose::STANDARD, Engine};
use business_properties::{plain, Rng, CASES};
use guard_command::business_gmail_plain::{GmailPlainErrorV1, GmailPlainInputV1};

/// Fragments that exercise ASCII, whitespace, the QP escape octet and
/// multi-byte UTF-8 in decoded text.
const TEXT: &[&str] = &[
    "a",
    "Z",
    "0",
    " ",
    "\t",
    "=",
    ".",
    "~",
    "\u{e9}",
    "\u{6f22}",
    "\u{1f600}",
    "\u{df}",
];

fn generated_text(rng: &mut Rng) -> String {
    let lines: Vec<String> = (0..1 + rng.below(5))
        .map(|_| (0..1 + rng.below(40)).map(|_| *rng.pick(TEXT)).collect())
        .collect();
    lines.join("\r\n")
}

fn crlf_lines(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let (mut start, mut index) = (0, 0);
    while index + 1 < bytes.len() {
        if &bytes[index..index + 2] == b"\r\n" {
            lines.push(&bytes[start..index]);
            index += 2;
            start = index;
        } else {
            index += 1;
        }
    }
    lines.push(&bytes[start..]);
    lines
}

/// Canonical quoted-printable: uppercase escapes, escaped line-final
/// whitespace and soft breaks that keep every encoded line within 76 octets.
fn quoted_printable(bytes: &[u8]) -> String {
    let mut lines = Vec::new();
    for line in crlf_lines(bytes) {
        let mut encoded = String::new();
        let mut width = 0;
        for (index, byte) in line.iter().enumerate() {
            let literal = ((33..=126).contains(byte) && *byte != b'=')
                || (matches!(byte, b' ' | b'\t') && index + 1 != line.len());
            let token = if literal {
                char::from(*byte).to_string()
            } else {
                format!("={byte:02X}")
            };
            if width + token.len() > 75 {
                encoded.push_str("=\r\n");
                width = 0;
            }
            width += token.len();
            encoded.push_str(&token);
        }
        lines.push(encoded);
    }
    lines.join("\r\n")
}

fn wrapped_base64(bytes: &[u8]) -> String {
    let encoded = STANDARD.encode(bytes);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(76)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    lines.join("\r\n")
}

fn encoded(encoding: &str, body: &[u8]) -> Result<GmailPlainInputV1, GmailPlainErrorV1> {
    let mut mime = format!(
        "From: sender@example.test\r\nTo: to@example.test\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Transfer-Encoding: {encoding}\r\n\r\n"
    )
    .into_bytes();
    mime.extend_from_slice(body);
    plain(&mime)
}

fn longest_line(text: &str) -> usize {
    text.split("\r\n").map(str::len).max().unwrap_or(0)
}

#[test]
fn generated_text_round_trips_through_every_transfer_encoding() {
    for case in 0..CASES {
        let mut rng = Rng::for_case(14, case);
        let text = generated_text(&mut rng);
        let b64 = wrapped_base64(text.as_bytes());
        for (encoding, body) in [
            ("8bit", text.clone()),
            ("quoted-printable", quoted_printable(text.as_bytes())),
            ("base64", b64.clone()),
            ("base64", format!("{b64}\r\n")),
        ] {
            let input = encoded(encoding, body.as_bytes())
                .unwrap_or_else(|error| panic!("case {case} {encoding}: {error:?} {body:?}"));
            assert_eq!(
                input.body_bytes(),
                text.as_bytes(),
                "case {case} {encoding}"
            );
            assert_eq!(
                encoded(encoding, body.as_bytes()).unwrap().input_binding(),
                input.input_binding(),
                "case {case} {encoding}"
            );
        }
        let seven = encoded("7bit", text.as_bytes());
        if text.is_ascii() {
            assert_eq!(seven.unwrap().body_bytes(), text.as_bytes(), "case {case}");
        } else {
            assert_eq!(
                seven.err(),
                Some(GmailPlainErrorV1::Unsupported),
                "case {case}"
            );
        }
    }
}

#[test]
fn malformed_transfer_encodings_fail_closed() {
    for case in 0..CASES {
        let mut rng = Rng::for_case(15, case);
        let text = generated_text(&mut rng);
        let b64 = wrapped_base64(text.as_bytes());
        let qp = quoted_printable(text.as_bytes());
        let mut corrupt: Vec<(&str, String)> = Vec::new();

        let mut inserted = b64.clone();
        inserted.insert(
            rng.below(b64.len() + 1),
            *rng.pick(&['-', '_', ' ', '.', '!', '\t']),
        );
        corrupt.push(("base64", inserted));
        let data: Vec<usize> = b64
            .char_indices()
            .filter(|(_, ch)| !matches!(ch, '\r' | '\n'))
            .map(|(index, _)| index)
            .collect();
        let mut deleted = b64.clone();
        deleted.remove(data[rng.below(data.len())]);
        corrupt.push(("base64", deleted));
        if b64.ends_with('=') {
            corrupt.push(("base64", b64.trim_end_matches('=').to_owned()));
        }
        if b64.contains("\r\n") {
            corrupt.push(("base64", b64.replacen("\r\n", "\n", 1)));
            assert_eq!(
                encoded("base64", b64.replace("\r\n", "").as_bytes()).err(),
                Some(GmailPlainErrorV1::BoundsExceeded),
                "case {case}"
            );
        }

        corrupt.push(("quoted-printable", format!("{qp}=")));
        corrupt.push(("quoted-printable", format!("{qp} ")));
        let mut raw = qp.clone();
        raw.insert(rng.below(qp.len() + 1), '\u{e9}');
        corrupt.push(("quoted-printable", raw));
        let bytes = qp.as_bytes();
        if let Some(index) = (0..bytes.len().saturating_sub(2)).find(|&index| {
            let pair = &bytes[index + 1..index + 3];
            bytes[index] == b'='
                && pair.iter().all(u8::is_ascii_hexdigit)
                && pair.iter().any(u8::is_ascii_uppercase)
        }) {
            let mut lower = qp.clone();
            lower.replace_range(
                index + 1..index + 3,
                &qp[index + 1..index + 3].to_lowercase(),
            );
            corrupt.push(("quoted-printable", lower));
        }
        if qp.contains("\r\n") {
            corrupt.push(("quoted-printable", qp.replacen("\r\n", "\n", 1)));
        }
        let unwrapped = qp.replace("=\r\n", "");
        let result = encoded("quoted-printable", unwrapped.as_bytes());
        if longest_line(&unwrapped) > 76 {
            assert_eq!(
                result.err(),
                Some(GmailPlainErrorV1::BoundsExceeded),
                "case {case}"
            );
        } else {
            assert_eq!(result.unwrap().body_bytes(), text.as_bytes(), "case {case}");
        }

        for (encoding, body) in corrupt {
            assert!(
                matches!(
                    encoded(encoding, body.as_bytes()),
                    Err(GmailPlainErrorV1::Invalid | GmailPlainErrorV1::BoundsExceeded)
                ),
                "case {case} {encoding}: {body:?}"
            );
        }
    }
}

#[test]
fn encodings_never_smuggle_text_the_plain_profile_rejects() {
    let forbidden: &[(&[u8], GmailPlainErrorV1)] = &[
        (b"\0", GmailPlainErrorV1::Invalid),
        (b"\xff", GmailPlainErrorV1::Invalid),
        (b"\n", GmailPlainErrorV1::Invalid),
        (b"\r", GmailPlainErrorV1::Invalid),
        (b"\x07", GmailPlainErrorV1::Unsupported),
        (b"\x7f", GmailPlainErrorV1::Unsupported),
        ("\u{85}".as_bytes(), GmailPlainErrorV1::Unsupported),
        ("\u{2028}".as_bytes(), GmailPlainErrorV1::Unsupported),
    ];
    for case in 0..CASES {
        let mut rng = Rng::for_case(16, case);
        let text = generated_text(&mut rng);
        let boundaries: Vec<usize> = text
            .char_indices()
            .map(|(index, _)| index)
            .chain([text.len()])
            .collect();
        let at = boundaries[rng.below(boundaries.len())];
        let (insert, expected) = *rng.pick(forbidden);
        let mut bytes = text.as_bytes().to_vec();
        bytes.splice(at..at, insert.iter().copied());
        let overlong = format!("{text}{}", "x".repeat(999));
        for (encoding, body, expected) in [
            ("base64", wrapped_base64(&bytes), expected),
            ("quoted-printable", quoted_printable(&bytes), expected),
            (
                "base64",
                wrapped_base64(overlong.as_bytes()),
                GmailPlainErrorV1::BoundsExceeded,
            ),
            (
                "quoted-printable",
                quoted_printable(overlong.as_bytes()),
                GmailPlainErrorV1::BoundsExceeded,
            ),
        ] {
            assert_eq!(
                encoded(encoding, body.as_bytes()).err(),
                Some(expected),
                "case {case} {encoding}: {bytes:?}"
            );
        }
    }
}
