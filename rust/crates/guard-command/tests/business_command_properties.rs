//! Seeded generated-input checks for the gws Gmail send command parser and its
//! wire JSON layer.

#[path = "support/business_properties.rs"]
mod business_properties;

use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use business_properties::{wire, Rng, CASES, PARAMS};
use guard_command::business_gmail_wire::{
    GmailSendWireErrorV1, GmailSendWireInputV1, GMAIL_SEND_MAX_PARAM_BYTES,
};
use guard_command::business_gws_command::{GwsGmailCommandErrorV1, GwsGmailSendCommandInputV1};
use guard_command::MAX_COMMAND_BYTES;
use guard_contracts::MAX_BUSINESS_INLINE_BYTES;

const ROUTE: &str = "gws gmail users messages send";

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
fn nonzero_trailing_bits_and_malformed_padding_are_rejected() {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for case in 0..CASES {
        let mut rng = Rng::for_case(7, case);
        // One trailing byte leaves four unused bits in the last symbol and
        // needs two pad characters; two trailing bytes leave two unused bits
        // and need one.
        let tail = 1 + rng.below(2);
        let mut mime = rng.bytes(32);
        mime.truncate(mime.len() - mime.len() % 3);
        mime.extend((0..tail).map(|_| rng.next() as u8));
        let unpadded = URL_SAFE_NO_PAD.encode(&mime);
        let pad = 3 - tail;
        let unused = if tail == 1 { 0xf } else { 0x3 };

        let mut dirty = unpadded.clone().into_bytes();
        let last = dirty.len() - 1;
        let value = ALPHABET.iter().position(|b| *b == dirty[last]).unwrap();
        dirty[last] = ALPHABET[(value & !unused) | (1 + rng.below(unused))];
        let dirty = String::from_utf8(dirty).unwrap();
        let padded_dirty = format!("{dirty}{}", "=".repeat(pad));
        let wrong_pad = format!("{unpadded}{}", "=".repeat(if pad == 2 { 1 } else { 2 }));
        let extra_pad = format!("{unpadded}{}", "=".repeat(pad + 1));
        let early_pad = format!("{}={}", &unpadded[..last], &unpadded[last..]);
        for raw in [&dirty, &padded_dirty, &wrong_pad, &extra_pad, &early_pad] {
            assert_eq!(
                wire(format!(r#"{{"raw":"{raw}"}}"#)).err(),
                Some(GmailSendWireErrorV1::Invalid),
                "case {case}: {raw:?}"
            );
        }
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
