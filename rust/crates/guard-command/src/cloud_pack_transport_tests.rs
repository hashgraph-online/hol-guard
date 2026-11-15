use crate::cloud_pack::{pack_from_value, parse_pack, CloudActionPack};
use crate::cloud_pack_artifact::pack_digest;
use crate::cloud_pack_diff::diff;
use crate::cloud_pack_request::render;
use crate::cloud_pack_transport::{partner_toolkit, valid_toolkit, Partner};
use serde_json::{json, Value};

const OUTLOOK: &str = include_str!("../../../../contributions/cloud-actions/outlook.json");

fn outlook_value() -> Value {
    serde_json::from_str(OUTLOOK).unwrap()
}

fn with_transports(transports: Value) -> Value {
    let mut pack = outlook_value();
    pack["transports"] = transports;
    pack
}

fn brokered() -> CloudActionPack {
    pack_from_value(with_transports(
        json!({"partner": [{"partner": "composio", "toolkit": "outlook"}]}),
    ))
    .unwrap()
}

fn refused(transports: Value) -> (&'static str, String) {
    let error = pack_from_value(with_transports(transports)).unwrap_err();
    (error.code, error.pointer)
}

#[test]
fn a_pack_without_transports_serializes_and_digests_as_before() {
    for text in crate::cloud_pack_explain::SHIPPED_SOURCES {
        let pack = parse_pack(text.as_bytes()).unwrap();
        assert!(pack.transports.is_none());
        let value = serde_json::to_value(&pack).unwrap();
        assert!(value.get("transports").is_none(), "{}", pack.provider.id);
    }
    let plain = parse_pack(OUTLOOK.as_bytes()).unwrap();
    assert_ne!(
        pack_digest(&plain).unwrap(),
        pack_digest(&brokered()).unwrap()
    );
    let mut stripped = brokered();
    stripped.transports = None;
    assert_eq!(
        pack_digest(&plain).unwrap(),
        pack_digest(&stripped).unwrap()
    );
}

#[test]
fn a_declared_partner_toolkit_is_read_back() {
    let pack = brokered();
    assert_eq!(partner_toolkit(&pack, Partner::Composio), Some("outlook"));
    assert_eq!(
        partner_toolkit(&parse_pack(OUTLOOK.as_bytes()).unwrap(), Partner::Composio),
        None
    );
}

#[test]
fn transports_outside_the_closed_form_are_refused() {
    let shape = "cloud_pack_shape_invalid";
    let invalid = "cloud_pack_transports_invalid";
    for (transports, code) in [
        (
            json!({"partner": [{"partner": "nango", "toolkit": "outlook"}]}),
            shape,
        ),
        (
            json!({"partner": [{"partner": "composio", "toolkit": "outlook", "url": "https://x.test"}]}),
            shape,
        ),
        (json!({"partner": [{"partner": "composio"}]}), shape),
        (json!({"direct": true, "partner": []}), shape),
        (json!(null), shape),
        (json!({"partner": []}), invalid),
    ] {
        assert_eq!(refused(transports.clone()).0, code, "{transports}");
    }
    for toolkit in [
        "",
        "o",
        "Outlook",
        "1drive",
        "out-look",
        "out look",
        "outlook/../x",
        &"a".repeat(65),
    ] {
        let (code, pointer) =
            refused(json!({"partner": [{"partner": "composio", "toolkit": toolkit}]}));
        assert_eq!(
            (code, pointer.as_str()),
            (invalid, "/transports/partner/0"),
            "{toolkit}"
        );
    }
    let (code, pointer) = refused(json!({"partner": [
        {"partner": "composio", "toolkit": "outlook"},
        {"partner": "composio", "toolkit": "microsoft_outlook"}
    ]}));
    assert_eq!((code, pointer.as_str()), (invalid, "/transports/partner/1"));
}

#[test]
fn a_pack_that_signs_in_with_nothing_cannot_be_brokered() {
    let mut pack =
        with_transports(json!({"partner": [{"partner": "composio", "toolkit": "outlook"}]}));
    pack["auth"] = json!({"mode": "none", "scopes": []});
    let error = pack_from_value(pack).unwrap_err();
    assert_eq!(
        (error.code, error.pointer.as_str()),
        ("cloud_pack_transports_invalid", "/transports")
    );
}

#[test]
fn toolkit_slugs_are_strict() {
    for slug in ["outlook", "one_drive", "box", "m365_mail"] {
        assert!(valid_toolkit(slug), "{slug}");
    }
    for slug in ["_outlook", "o", "outlook!", "outlook\n"] {
        assert!(!valid_toolkit(slug), "{slug:?}");
    }
}

#[test]
fn adding_a_transport_widens_and_removing_one_does_not() {
    let plain = parse_pack(OUTLOOK.as_bytes()).unwrap();
    let pack = brokered();
    let added = diff(&plain, &pack).unwrap();
    assert!(added.widening);
    let codes: Vec<_> = added.changes.iter().map(|change| change.code).collect();
    assert_eq!(codes, ["transport_added"]);
    let removed = diff(&pack, &plain).unwrap();
    assert!(!removed.widening);
    let renamed = pack_from_value(with_transports(
        json!({"partner": [{"partner": "composio", "toolkit": "microsoft_outlook"}]}),
    ))
    .unwrap();
    assert!(diff(&pack, &renamed).unwrap().widening);
    assert!(!diff(&pack, &pack).unwrap().widening);
}

#[test]
fn a_brokered_pack_renders_the_same_absolute_request_with_no_credential() {
    let plain = parse_pack(OUTLOOK.as_bytes()).unwrap();
    let pack = brokered();
    let arguments = json!({"folder": "inbox", "top": 10});
    let direct = render(plain.action("outlook.messages.list").unwrap(), &arguments).unwrap();
    let request = render(pack.action("outlook.messages.list").unwrap(), &arguments).unwrap();
    assert_eq!(request, direct);
    let url = url::Url::parse(&request.url).unwrap();
    assert_eq!(url.scheme(), "https");
    assert!(pack
        .hosts
        .iter()
        .any(|host| Some(host.as_str()) == url.host_str()));
    assert!(url.username().is_empty() && url.password().is_none());
    assert!(request.headers.iter().all(|[name, _]| {
        let name = name.to_ascii_lowercase();
        !["authorization", "cookie", "x-api-key"].contains(&name.as_str())
    }));
}
