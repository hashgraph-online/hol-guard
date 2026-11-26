use guard_contracts::{
    BrowserCardChoiceV1, BrowserCardRequestV1, BrowserCardV1, BrowserIntentV1,
    BrowserMcpArgumentsV1, BrowserMcpDisplayIntentV1, BrowserMcpRequestV1, BrowserMcpResultV1,
};
use serde_json::Value;

use super::browser_card;
use crate::browser_mcp_intent::evaluate_browser_mcp;

const VECTORS: &str = include_str!("../../../../tests/fixtures/browser_drivers/card_vectors.json");

fn vectors() -> Vec<Value> {
    let document: Value = serde_json::from_str(VECTORS).expect("card vectors parse");
    assert_eq!(
        document["schemaVersion"], "guard.browser-card-vectors.v1",
        "vector schema"
    );
    document["vectors"].as_array().expect("vector list").clone()
}

fn request(vector: &Value) -> BrowserCardRequestV1 {
    serde_json::from_value(vector["request"].clone()).expect("card request parses")
}

fn first_valid_request() -> BrowserCardRequestV1 {
    let vector = vectors()
        .into_iter()
        .find(|vector| vector.get("card").is_some())
        .expect("a card vector");
    request(&vector)
}

#[test]
fn every_vector_projects_its_expected_card_or_error() {
    let vectors = vectors();
    assert!(vectors.len() >= 8, "vectors cover the card shapes");
    for vector in vectors {
        let name = vector["name"].as_str().expect("vector name");
        let actual = browser_card(&request(&vector));
        match (vector.get("card"), vector.get("error")) {
            (Some(card), None) => {
                let expected: BrowserCardV1 =
                    serde_json::from_value(card.clone()).expect("expected card parses");
                assert_eq!(actual.as_ref(), Ok(&expected), "{name}");
            }
            (None, Some(error)) => {
                assert_eq!(actual.err(), error.as_str(), "{name}");
            }
            _ => panic!("{name}: a vector names exactly one of card or error"),
        }
    }
}

#[test]
fn every_card_keeps_the_approval_invariant() {
    for vector in vectors() {
        if let Ok(card) = browser_card(&request(&vector)) {
            assert!(card.keeps_approval_invariant(), "{}", vector["name"]);
            assert_eq!(
                card.choices,
                vec![
                    BrowserCardChoiceV1::AllowOnce,
                    BrowserCardChoiceV1::AlwaysAllow,
                    BrowserCardChoiceV1::Deny,
                ]
            );
        }
    }
}

#[test]
fn the_card_never_carries_typed_text_or_the_input_digest() {
    for vector in vectors() {
        let Ok(card) = browser_card(&request(&vector)) else {
            continue;
        };
        let rendered = serde_json::to_string(&card).expect("card serializes");
        assert!(!rendered.contains(&"ab".repeat(32)), "{}", vector["name"]);
        assert!(!rendered.contains("digest"), "{}", vector["name"]);
    }
}

#[test]
fn the_agent_name_is_cleaned_and_bounded() {
    let mut request = first_valid_request();
    request.agent = "  Claude\u{1b}[31m\n  Code  ".to_owned();
    let card = browser_card(&request).expect("card");
    assert!(card.headline.starts_with("Claude [31m Code wants to"));

    request.agent = "x".repeat(200);
    let card = browser_card(&request).expect("card");
    assert!(card
        .headline
        .starts_with(&format!("{} wants to", "x".repeat(48))));
}

#[test]
fn the_agent_name_drops_bidi_and_zero_width_characters() {
    let mut request = first_valid_request();
    request.agent = "Agent\u{202E}\u{2066}x\u{200B}y\u{FEFF}".to_owned();
    let card = browser_card(&request).expect("card");
    assert!(
        card.headline.starts_with("Agent x y wants to"),
        "{}",
        card.headline
    );
    assert!(!card
        .headline
        .contains(['\u{202E}', '\u{2066}', '\u{200B}', '\u{FEFF}']));
}

#[test]
fn the_card_never_shows_origin_userinfo() {
    let mut card_request = first_valid_request();
    card_request.action.target.origin = Some("https://someone:x@shop.example.test:8443".to_owned());
    let card = browser_card(&card_request).expect("card");
    assert_eq!(
        card.site.origin.as_deref(),
        Some("https://shop.example.test:8443")
    );
    let rendered = serde_json::to_string(&card).expect("card serializes");
    assert!(!rendered.contains("someone"), "{rendered}");
    assert!(
        card.headline.contains("shop.example.test:8443"),
        "{}",
        card.headline
    );

    let display = BrowserMcpRequestV1::Display {
        intent: BrowserMcpDisplayIntentV1 {
            intent: BrowserIntentV1::Interact,
            operation: "browser_type".to_owned(),
            target_domain: Some("shop.example.test".to_owned()),
            target_origin: Some("https://shop.example.test:8443".to_owned()),
        },
        arguments: BrowserMcpArgumentsV1::Other,
        card: Some(Box::new(card_request)),
    };
    let wire = serde_json::to_value(&display).expect("display serializes");
    let decoded: BrowserMcpRequestV1 = serde_json::from_value(wire).expect("display parses");
    match evaluate_browser_mcp(&decoded).expect("display") {
        BrowserMcpResultV1::Display { card, .. } => {
            let card = card.expect("card");
            assert_eq!(
                card.site.origin.as_deref(),
                Some("https://shop.example.test:8443")
            );
            assert!(!card.headline.contains("someone"));
        }
        other => panic!("unexpected result {other:?}"),
    }
}

#[test]
fn an_origin_with_hidden_characters_is_not_shown() {
    let mut request = first_valid_request();
    request.action.target.origin = Some("https://shop\u{202E}.example.test".to_owned());
    let card = browser_card(&request).expect("card");
    assert_eq!(card.site.origin, None);
    assert!(!card.headline.contains('\u{202E}'));
}

#[test]
fn a_backslash_origin_cannot_borrow_another_site() {
    for origin in [
        "https://evil.test\\@shop.example.test",
        "https://evil.test\\path@shop.example.test/",
    ] {
        let mut request = first_valid_request();
        request.action.target.origin = Some(origin.to_owned());
        let card = browser_card(&request).expect("card");
        assert_eq!(card.site.origin, None, "{origin}");
        assert!(
            !card.headline.contains("shop.example.test"),
            "{}",
            card.headline
        );
    }
}

#[test]
fn a_display_request_returns_the_card_beside_its_target() {
    let card_request = first_valid_request();
    let expected = browser_card(&card_request).expect("card");
    let display = BrowserMcpRequestV1::Display {
        intent: BrowserMcpDisplayIntentV1 {
            intent: BrowserIntentV1::Interact,
            operation: "browser_type".to_owned(),
            target_domain: Some("shop.example.test".to_owned()),
            target_origin: Some("https://shop.example.test".to_owned()),
        },
        arguments: BrowserMcpArgumentsV1::Other,
        card: Some(Box::new(card_request)),
    };
    match evaluate_browser_mcp(&display).expect("display") {
        BrowserMcpResultV1::Display { card, .. } => {
            assert_eq!(card.as_deref(), Some(&expected));
        }
        other => panic!("unexpected result {other:?}"),
    }

    let BrowserMcpRequestV1::Display {
        intent, arguments, ..
    } = display
    else {
        unreachable!()
    };
    let plain = BrowserMcpRequestV1::Display {
        intent,
        arguments,
        card: None,
    };
    let result = evaluate_browser_mcp(&plain).expect("display");
    let encoded = serde_json::to_value(&result).expect("result serializes");
    assert!(encoded.get("card").is_none(), "no card unless asked");
}

#[test]
fn a_bad_action_inside_a_display_request_fails_the_request() {
    let mut card_request = first_valid_request();
    card_request.action.version = 1;
    let display = BrowserMcpRequestV1::Display {
        intent: BrowserMcpDisplayIntentV1 {
            intent: BrowserIntentV1::Interact,
            operation: "browser_type".to_owned(),
            target_domain: None,
            target_origin: None,
        },
        arguments: BrowserMcpArgumentsV1::Other,
        card: Some(Box::new(card_request)),
    };
    assert_eq!(
        evaluate_browser_mcp(&display).err(),
        Some("browser_action_wrong_version")
    );
}
