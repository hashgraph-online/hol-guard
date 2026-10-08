//! Seeded generated-input checks for the Gmail send preparation chain.
//!
//! Each property runs a fixed number of cases from a deterministic SplitMix64
//! stream, so failures reproduce from the printed seed and case number without
//! adding a property-testing dependency.

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use guard_command::business_gmail_plain::{GmailPlainErrorV1, GmailPlainInputV1};
use guard_command::business_gmail_wire::{
    GmailSendWireErrorV1, GmailSendWireInputV1, GMAIL_SEND_MAX_PARAM_BYTES,
};
use guard_command::business_gws_command::{GwsGmailCommandErrorV1, GwsGmailSendCommandInputV1};
use guard_command::MAX_COMMAND_BYTES;
use guard_contracts::{BusinessRecipientKindV1, MAX_BUSINESS_INLINE_BYTES};

const SEED: u64 = 0x5eed_0fb0_517e_5500;
const CASES: u64 = 512;
const PARAMS: &str = r#"{"userId":"me"}"#;
const ROUTE: &str = "gws gmail users messages send";

struct Rng(u64);

impl Rng {
    fn for_case(property: u64, case: u64) -> Self {
        Self(SEED ^ property.rotate_left(32) ^ case.wrapping_mul(0x9e37_79b9_7f4a_7c15))
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = 1 + self.below(max);
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// Fragments chosen to reach shell, quoting, option and Unicode branches.
const NOISE: &[&str] = &[
    " ",
    "'",
    "\"",
    "\\",
    "$",
    "`",
    "*",
    "?",
    "[",
    "]",
    "~",
    "{",
    "}",
    "(",
    ")",
    "<",
    ">",
    "|",
    "&",
    ";",
    "#",
    "\n",
    "\r",
    "\t",
    "\0",
    "=",
    "--",
    "--params",
    "--json",
    "-o",
    "x",
    "é",
    "\u{202e}",
    "\u{2028}",
    "\u{feff}",
    "\u{ff04}",
    "\u{1f600}",
    "gws",
    "send",
];

fn sample_raw(rng: &mut Rng) -> String {
    let mime = rng.bytes(48);
    if rng.below(2) == 0 {
        URL_SAFE.encode(mime)
    } else {
        URL_SAFE_NO_PAD.encode(mime)
    }
}

fn option(rng: &mut Rng, name: &str, value: &str) -> String {
    match rng.below(4) {
        0 => format!("--{name} '{value}'"),
        1 => format!("--{name}='{value}'"),
        2 => format!("--{name} \"{}\"", value.replace('"', "\\\"")),
        _ => format!("--{name}=\"{}\"", value.replace('"', "\\\"")),
    }
}

/// A valid command with randomized option order, quoting and spacing.
fn valid_command(rng: &mut Rng) -> (String, String) {
    let body = format!(r#"{{"raw":"{}"}}"#, sample_raw(rng));
    let mut options = [option(rng, "params", PARAMS), option(rng, "json", &body)];
    if rng.below(2) == 0 {
        options.swap(0, 1);
    }
    let gap = " ".repeat(1 + rng.below(3));
    let lead = " ".repeat(rng.below(3));
    (
        format!("{lead}{ROUTE}{gap}{}{gap}{}", options[0], options[1]),
        body,
    )
}

fn mutate(rng: &mut Rng, text: &str) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    for _ in 0..1 + rng.below(4) {
        let at = rng.below(chars.len() + 1);
        match rng.below(4) {
            0 => {
                let fragment = rng.pick(NOISE);
                chars.splice(at..at, fragment.chars());
            }
            1 if at < chars.len() => {
                chars.remove(at);
            }
            2 => chars.truncate(at),
            _ => {
                let end = (at + 1 + rng.below(12)).min(chars.len());
                let copy: Vec<char> = chars[at..end].to_vec();
                let to = rng.below(chars.len() + 1);
                chars.splice(to..to, copy);
            }
        }
    }
    chars.into_iter().collect()
}

#[test]
fn generated_valid_commands_recover_exact_payload_bytes() {
    for case in 0..CASES {
        let mut rng = Rng::for_case(1, case);
        let (text, body) = valid_command(&mut rng);
        let input = GwsGmailSendCommandInputV1::from_owned_posix_command(text.clone())
            .unwrap_or_else(|error| panic!("case {case}: {error:?} for {text:?}"));
        assert_eq!(input.command_text(), text, "case {case}");
        assert_eq!(input.wire_input().params_bytes(), PARAMS.as_bytes());
        assert_eq!(input.wire_input().body_bytes(), body.as_bytes());
        let again = GwsGmailSendCommandInputV1::from_owned_posix_command(text).unwrap();
        assert_eq!(again.input_binding(), input.input_binding(), "case {case}");
    }
}

#[test]
fn mutated_commands_never_panic_and_accepted_results_are_self_consistent() {
    let mut accepted = 0;
    for case in 0..CASES * 8 {
        let mut rng = Rng::for_case(2, case);
        let (base, _) = valid_command(&mut rng);
        let text = mutate(&mut rng, &base);
        let Ok(input) = GwsGmailSendCommandInputV1::from_owned_posix_command(text.clone()) else {
            continue;
        };
        accepted += 1;
        assert_eq!(input.command_text(), text, "case {case}");
        assert!(
            !text.contains('\0'),
            "case {case}: accepted NUL in {text:?}"
        );
        // A line break is only acceptable as literal quoted payload data, never
        // as a command separator.
        let payload = [
            input.wire_input().params_bytes(),
            input.wire_input().body_bytes(),
        ];
        for control in [b'\r', b'\n'] {
            let in_text = text.bytes().filter(|b| *b == control).count();
            let in_payload: usize = payload
                .iter()
                .map(|bytes| bytes.iter().filter(|b| **b == control).count())
                .sum();
            assert_eq!(in_text, in_payload, "case {case}: {text:?}");
        }
        // The wire layer alone must reproduce the same interpretation.
        let wire = GmailSendWireInputV1::from_owned_json(
            input.wire_input().params_bytes().to_vec(),
            input.wire_input().body_bytes().to_vec(),
        )
        .unwrap_or_else(|error| panic!("case {case}: wire re-prepare {error:?}"));
        assert_eq!(wire.input_binding(), input.wire_input().input_binding());
        assert_eq!(wire.mime_bytes(), input.wire_input().mime_bytes());
        let again = GwsGmailSendCommandInputV1::from_owned_posix_command(text).unwrap();
        assert_eq!(again.input_binding(), input.input_binding(), "case {case}");
    }
    // Spacing-only and payload-internal mutations still parse; the property is
    // vacuous if the generator never produces an accepted command.
    assert!(accepted > 0);
}

#[test]
fn repeated_or_missing_options_are_always_rejected() {
    let body = r#"{"raw":"Zg"}"#;
    for case in 0..CASES {
        let mut rng = Rng::for_case(3, case);
        let params_count = rng.below(4);
        let json_count = rng.below(4);
        let mut options = Vec::new();
        for _ in 0..params_count {
            options.push(option(&mut rng, "params", PARAMS));
        }
        for _ in 0..json_count {
            options.push(option(&mut rng, "json", body));
        }
        for index in (1..options.len()).rev() {
            let other = rng.below(index + 1);
            options.swap(index, other);
        }
        let text = format!("{ROUTE} {}", options.join(" "));
        let result = GwsGmailSendCommandInputV1::from_owned_posix_command(text.clone());
        assert_eq!(
            result.is_ok(),
            params_count == 1 && json_count == 1,
            "case {case}: {text:?}"
        );
    }
}

#[test]
fn wrappers_compounds_and_alternate_routes_are_never_accepted() {
    const PREFIXES: &[&str] = &[
        "env ",
        "sudo ",
        "command ",
        "exec ",
        "nohup ",
        "timeout 5 ",
        "nice ",
        "xargs ",
        "PATH=/tmp ",
        "GWS_ACCOUNT=other ",
        "time ",
        "builtin ",
        "'gws' ",
    ];
    const SUFFIXES: &[&str] = &[
        " --",
        " -- extra",
        " ; true",
        " && true",
        " || true",
        " | cat",
        " > out",
        " 2>&1",
        " &",
        " #",
        " $(true)",
        " `true`",
        " --dry-run",
        " --page-all",
        " --upload x",
    ];
    const ROUTES: &[&str] = &[
        "./gws gmail users messages send",
        "/usr/bin/gws gmail users messages send",
        "gws gmail users drafts send",
        "gws gmail users messages insert",
        "gws gmail users messages import",
        "gws gmail +send",
        "gws api gmail users messages send",
        "gog gmail send",
        "GWS gmail users messages send",
        "gws gmail users messages",
    ];
    for case in 0..CASES {
        let mut rng = Rng::for_case(4, case);
        let (valid, _) = valid_command(&mut rng);
        let valid = valid.trim_start().to_owned();
        let candidate = match rng.below(4) {
            0 => format!("{}{valid}", rng.pick(PREFIXES)),
            1 => format!("{valid}{}", rng.pick(SUFFIXES)),
            2 => {
                let route = ROUTES[rng.below(ROUTES.len())];
                valid.replacen(ROUTE, route, 1)
            }
            _ => format!("bash -c '{}'", valid.replace('\'', "")),
        };
        assert!(
            GwsGmailSendCommandInputV1::from_owned_posix_command(candidate.clone()).is_err(),
            "case {case}: {candidate:?}"
        );
    }
}

#[test]
fn oversized_commands_fail_with_bounds_before_parsing() {
    for case in 0..64 {
        let mut rng = Rng::for_case(5, case);
        let (valid, _) = valid_command(&mut rng);
        let pad = MAX_COMMAND_BYTES - valid.len() + 1 + rng.below(4096);
        // Padding includes active shell syntax; the byte bound must win.
        let filler = rng.pick(&[" ", "x", "$", ";", "é"]).repeat(pad);
        let candidate = format!("{filler}{valid}");
        assert!(candidate.len() > MAX_COMMAND_BYTES);
        assert_eq!(
            GwsGmailSendCommandInputV1::from_owned_posix_command(candidate).err(),
            Some(GwsGmailCommandErrorV1::BoundsExceeded),
            "case {case}"
        );
    }
}

fn wire(body: String) -> Result<GmailSendWireInputV1, GmailSendWireErrorV1> {
    GmailSendWireInputV1::from_owned_json(PARAMS.as_bytes().to_vec(), body.into_bytes())
}

#[test]
fn canonical_base64url_round_trips_and_corruption_never_changes_bytes() {
    const FOREIGN: &[char] = &['+', '/', ' ', '\n', '.', '=', '%', 'é', '\0'];
    for case in 0..CASES {
        let mut rng = Rng::for_case(6, case);
        let mime = rng.bytes(96);
        let padded = URL_SAFE.encode(&mime);
        let unpadded = URL_SAFE_NO_PAD.encode(&mime);
        for raw in [&padded, &unpadded] {
            let input = wire(format!(r#"{{"raw":"{raw}"}}"#)).unwrap();
            assert_eq!(input.mime_bytes(), mime, "case {case}");
        }
        let mut corrupt: Vec<char> = unpadded.chars().collect();
        let at = rng.below(corrupt.len() + 1);
        corrupt.insert(at, *rng.pick(FOREIGN));
        let corrupt: String = corrupt.into_iter().collect();
        let body = serde_json::json!({ "raw": corrupt }).to_string();
        if let Ok(input) = wire(body) {
            // Only a canonical trailing pad on an unpadded encoding can parse,
            // and it must denote the same bytes.
            assert_eq!(input.mime_bytes(), mime, "case {case}: {corrupt:?}");
        }
    }
}

#[test]
fn nonzero_trailing_bits_are_rejected() {
    for case in 0..CASES {
        let mut rng = Rng::for_case(7, case);
        // One trailing byte leaves four unused bits in the second symbol.
        let mime = rng.bytes(32);
        let mut mime = mime;
        if mime.len() % 3 != 1 {
            mime.truncate(mime.len() - mime.len() % 3);
            mime.push(rng.next() as u8);
        }
        let mut raw: Vec<u8> = URL_SAFE_NO_PAD.encode(&mime).into_bytes();
        let last = raw.len() - 1;
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let value = alphabet.iter().position(|b| *b == raw[last]).unwrap();
        raw[last] = alphabet[(value & !0xf) | (1 + rng.below(15))];
        let raw = String::from_utf8(raw).unwrap();
        assert_eq!(
            wire(format!(r#"{{"raw":"{raw}"}}"#)).err(),
            Some(GmailSendWireErrorV1::Invalid),
            "case {case}: {raw:?}"
        );
    }
}

#[test]
fn principal_selectors_duplicate_fields_and_bounds_fail_closed() {
    for case in 0..CASES {
        let mut rng = Rng::for_case(8, case);
        let selector: String = (0..1 + rng.below(6))
            .map(|_| *rng.pick(&['m', 'e', 'M', 'E', ' ', 'x', '@', 'é']))
            .collect();
        let params = serde_json::json!({ "userId": selector }).to_string();
        let result =
            GmailSendWireInputV1::from_owned_json(params.into_bytes(), br#"{"raw":"Zg"}"#.to_vec());
        if selector == "me" {
            assert!(result.is_ok(), "case {case}");
        } else {
            assert_eq!(
                result.err(),
                Some(GmailSendWireErrorV1::UnsupportedPrincipalSelector),
                "case {case}: {selector:?}"
            );
        }
        let duplicate = *rng.pick(&[
            r#"{"raw":"Zg","raw":"Zg"}"#,
            r#"{"raw":"Zg","threadId":"a","threadId":"a"}"#,
            r#"{"raw":"Zg","raw":"Zh"}"#,
            r#"{"raw":"Zg","extra":1}"#,
            r#"{"raw":"Zg","threadId":null}"#,
            r#"{"raw":"Zg","threadId":""}"#,
        ]);
        assert_eq!(
            wire(duplicate.to_owned()).err(),
            Some(GmailSendWireErrorV1::Invalid),
            "case {case}: {duplicate}"
        );
    }
    let mut rng = Rng::for_case(9, 0);
    let params = format!(
        r#"{{"userId":"me"{}}}"#,
        " ".repeat(GMAIL_SEND_MAX_PARAM_BYTES + rng.below(64))
    );
    assert_eq!(
        GmailSendWireInputV1::from_owned_json(params.into_bytes(), br#"{"raw":"Zg"}"#.to_vec())
            .err(),
        Some(GmailSendWireErrorV1::BoundsExceeded)
    );
    let inline = usize::try_from(MAX_BUSINESS_INLINE_BYTES).unwrap();
    let body = format!(r#"{{"raw":"{}"}}"#, "A".repeat(inline));
    assert_eq!(wire(body).err(), Some(GmailSendWireErrorV1::BoundsExceeded));
}

fn plain(mime: &[u8]) -> Result<GmailPlainInputV1, GmailPlainErrorV1> {
    let wire = wire(format!(r#"{{"raw":"{}"}}"#, URL_SAFE_NO_PAD.encode(mime))).unwrap();
    GmailPlainInputV1::from_owned_wire(wire)
}

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
    // Header order is free; recipients keep source order within each header.
    let from = headers.remove(0);
    let at = rng.below(headers.len() + 1);
    headers.insert(at, from);
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
            _ => (
                (*rng.pick(&["To: Name <n@example.test>", "Cc: \"q\"@example.test"])).to_owned(),
                GmailPlainErrorV1::Invalid,
            ),
        };
        let at = rng.below(headers.len() + 1);
        headers.insert(at, header);
        let result = plain(&render(&headers, "body"));
        assert!(result.is_err(), "case {case}: {headers:?}");
        if expected != GmailPlainErrorV1::Invalid {
            assert_eq!(result.err(), Some(expected), "case {case}: {headers:?}");
        }
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
