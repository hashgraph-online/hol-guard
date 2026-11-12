use crate::cloud_pack::{pack_from_value, parse_pack, PackAction};
use crate::cloud_pack_mail::{render, MailTemplate};
use crate::cloud_pack_request::render as render_request;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine;
use serde_json::{json, Map, Value};

const GMAIL: &str = include_str!("../../../../contributions/cloud-actions/gmail.json");
const SEND: &str = "gmail.messages.send";

fn mail() -> MailTemplate {
    MailTemplate {
        to: "to".into(),
        cc: Some("cc".into()),
        bcc: None,
        subject: "subject".into(),
        text: "text".into(),
    }
}

fn args(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn decode(raw: &str) -> String {
    String::from_utf8(URL_SAFE.decode(raw).unwrap()).unwrap()
}

fn send() -> PackAction {
    let pack = parse_pack(GMAIL.as_bytes()).unwrap();
    pack.actions
        .into_iter()
        .find(|action| action.action_id == SEND)
        .unwrap()
}

/// The Gmail pack with the send action changed by `change`.
fn edited(change: impl FnOnce(&mut Value)) -> &'static str {
    let mut pack: Value = serde_json::from_str(GMAIL).unwrap();
    let action = pack["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["actionId"] == SEND)
        .unwrap();
    change(action);
    pack_from_value(pack).unwrap_err().code
}

#[test]
fn the_send_action_builds_a_message_with_only_the_declared_recipients() {
    let request = render_request(
        &send(),
        &json!({
            "to": ["pat@example.org"],
            "cc": ["lee@example.com"],
            "subject": "Plan für Q3",
            "text": "Hello\r\nBcc: someone@evil.test\r\n"
        }),
    )
    .unwrap();
    let body: Value = serde_json::from_str(request.body.as_deref().unwrap()).unwrap();
    let message = decode(body["raw"].as_str().unwrap());
    let (head, text) = message.split_once("\r\n\r\n").unwrap();
    let headers: Vec<&str> = head.split("\r\n").collect();
    assert_eq!(headers[0], "To: pat@example.org");
    assert_eq!(headers[1], "Cc: lee@example.com");
    assert_eq!(
        headers[2],
        format!("Subject: =?UTF-8?B?{}?=", STANDARD.encode("Plan für Q3"))
    );
    assert!(!headers.iter().any(|line| line.starts_with("Bcc")));
    let decoded = STANDARD.decode(text.replace("\r\n", "")).unwrap();
    assert_eq!(decoded, b"Hello\r\nBcc: someone@evil.test\r\n");
}

#[test]
fn a_subject_cannot_add_a_header() {
    let raw = render(
        &mail(),
        &args(json!({"to": ["pat@example.org"], "subject": "Hi\r\nBcc: x@evil.test", "text": ""})),
    )
    .unwrap();
    let message = decode(&raw);
    let head = message.split_once("\r\n\r\n").unwrap().0;
    assert!(!head.split("\r\n").any(|line| line.starts_with("Bcc")));
}

#[test]
fn an_address_that_is_not_bare_is_refused() {
    for address in [
        "pat@example.org\r\nBcc: x@evil.test",
        "Pat <pat@example.org>",
        "pat@example.org, lee@example.com",
        "pat",
        "pat@",
        "pat@exa mple.org",
        ".pat@example.org",
    ] {
        let message = args(json!({"to": [address], "subject": "s", "text": "t"}));
        assert_eq!(render(&mail(), &message), None, "{address:?}");
    }
    let copy = args(
        json!({"to": ["pat@example.org"], "cc": ["Lee <lee@example.com>"], "subject": "s", "text": "t"}),
    );
    assert_eq!(render(&mail(), &copy), None);
}

#[test]
fn a_message_needs_a_recipient() {
    let message = args(json!({"to": [], "cc": ["lee@example.com"], "subject": "s", "text": "t"}));
    assert_eq!(render(&mail(), &message), None);
}

#[test]
fn recipient_facts_must_cover_every_recipient_argument() {
    assert_eq!(
        edited(
            |action| action["facts"]["recipientDomains"]["domains"]["arguments"] = json!(["to"])
        ),
        "cloud_pack_mail_recipients_unbound"
    );
    assert_eq!(
        edited(|action| {
            action["facts"]
                .as_object_mut()
                .unwrap()
                .remove("recipientCount");
        }),
        "cloud_pack_mail_recipients_unbound"
    );
}

#[test]
fn the_template_needs_a_required_recipient_list_and_distinct_arguments() {
    assert_eq!(
        edited(|action| action["arguments"]["to"]["required"] = json!(false)),
        "cloud_pack_template_mail_invalid"
    );
    assert_eq!(
        edited(
            |action| action["executor"]["request"]["body"]["object"][0]["value"]["rfc822"]["cc"] =
                json!("to")
        ),
        "cloud_pack_template_mail_invalid"
    );
}

#[test]
fn a_message_cannot_be_built_per_element() {
    let code = edited(|action| {
        let mail = action["executor"]["request"]["body"]["object"][0]["value"].clone();
        action["executor"]["request"]["body"]["object"][0]["value"] =
            json!({"each": {"arg": "to", "item": mail}});
    });
    assert_eq!(code, "cloud_pack_template_mail_invalid");
}

#[test]
fn a_recipient_argument_named_twice_cannot_stand_in_for_another() {
    for fact in ["recipientDomains", "recipientCount"] {
        let key = if fact == "recipientDomains" { "domains" } else { "count" };
        let code = edited(|action| {
            action["facts"][fact][key]["arguments"] = json!(["to", "to", "cc"]);
        });
        assert_eq!(code, "cloud_pack_extractor_argument_invalid", "{fact}");
    }
}

#[test]
fn a_long_subject_is_split_into_short_encoded_words() {
    let subject = "Zusammenfassung für das Quartal: ".repeat(30);
    let raw = render(
        &mail(),
        &args(json!({"to": ["pat@example.org"], "subject": subject, "text": "t"})),
    )
    .unwrap();
    let message = decode(&raw);
    let head = message.split_once("\r\n\r\n").unwrap().0;
    let unfolded = head.replace("\r\n ", " ");
    let line = unfolded
        .split("\r\n")
        .find(|line| line.starts_with("Subject: "))
        .unwrap();
    let mut decoded = Vec::new();
    for word in line["Subject: ".len()..].split(' ') {
        assert!(word.len() <= 75, "{word}");
        let inner = word.strip_prefix("=?UTF-8?B?").unwrap().strip_suffix("?=").unwrap();
        let piece = STANDARD.decode(inner).unwrap();
        assert!(std::str::from_utf8(&piece).is_ok(), "a word splits a character");
        decoded.extend(piece);
    }
    assert_eq!(String::from_utf8(decoded).unwrap(), subject);
    assert!(head.split("\r\n").all(|line| line.len() <= 78), "{head}");
}

#[test]
fn a_long_recipient_list_is_folded_one_address_per_line() {
    let to: Vec<String> = (0..50).map(|n| format!("person{n}@example.org")).collect();
    let raw = render(&mail(), &args(json!({"to": to, "subject": "s", "text": "t"}))).unwrap();
    let message = decode(&raw);
    let head = message.split_once("\r\n\r\n").unwrap().0;
    assert!(head.split("\r\n").all(|line| line.len() <= 78), "{head}");
    let unfolded = head.replace("\r\n ", " ");
    let line = unfolded.split("\r\n").next().unwrap();
    assert_eq!(line, format!("To: {}", to.join(", ")));
}
