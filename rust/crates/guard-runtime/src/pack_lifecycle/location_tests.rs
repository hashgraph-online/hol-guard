use super::*;
use serde_json::json;

const SOURCE: &str = "ffa0eaa6ac9a1ca8daaa18cc587937dbd501cfd5";

#[test]
fn a_location_is_a_standalone_asset_or_a_container_member() {
    let sha = "2".repeat(64);
    let tag = format!("extension-data-{SOURCE}-12.1-000003");
    let object = format!("object-{sha}.json");
    let pack = format!("pack-{sha}.zip");
    let accepted = [
        (json!({"tag": tag, "asset": object}), "object"),
        (json!({"tag": tag, "asset": pack}), "pack"),
        (
            json!({"tag": tag, "asset": "objects-000001.zip", "member": object}),
            "object",
        ),
        (
            json!({"tag": tag, "asset": "packs-000001.zip", "member": pack}),
            "pack",
        ),
    ];
    for (value, kind) in accepted {
        assert_eq!(check(&value, &sha, kind), Ok(()), "{value}");
    }
}

#[test]
fn rejections_keep_the_three_messages_every_caller_reports() {
    let sha = "2".repeat(64);
    let tag = format!("extension-data-{SOURCE}-12.1-000003");
    let object = format!("object-{sha}.json");
    let solo = json!({"tag": tag, "asset": object});
    let member = |asset: Value, name: &str| json!({"tag": tag, "asset": asset, "member": name});
    let cases = [
        (json!(null), &sha[..], "object", Rejection::Location),
        (json!({"tag": tag}), &sha[..], "object", Rejection::Location),
        (
            json!({"tag": tag, "asset": object, "x": 1}),
            &sha[..],
            "object",
            Rejection::Location,
        ),
        (
            json!({"tag": "x", "asset": object}),
            &sha[..],
            "object",
            Rejection::Location,
        ),
        (solo.clone(), "short", "object", Rejection::Location),
        (solo, &sha[..], "other", Rejection::Location),
        (
            json!({"tag": tag, "asset": "object-x.json"}),
            &sha[..],
            "object",
            Rejection::Identity,
        ),
        (
            json!({"tag": tag, "asset": 1}),
            &sha[..],
            "object",
            Rejection::Identity,
        ),
        (
            member(json!("packs-000001.zip"), &object),
            &sha[..],
            "object",
            Rejection::Container,
        ),
        (
            member(json!("objects-1.zip"), &object),
            &sha[..],
            "object",
            Rejection::Container,
        ),
        (
            member(json!("objects-000001.zip"), "object-x.json"),
            &sha[..],
            "object",
            Rejection::Container,
        ),
        (
            member(json!(1), &object),
            &sha[..],
            "object",
            Rejection::Container,
        ),
    ];
    for (value, digest, kind, expected) in cases {
        assert_eq!(check(&value, digest, kind), Err(expected), "{value}");
    }
    assert_eq!(
        Rejection::Location.message(),
        "delivery asset location invalid"
    );
    assert_eq!(
        Rejection::Identity.message(),
        "delivery asset identity invalid"
    );
    assert_eq!(
        Rejection::Container.message(),
        "delivery container location invalid"
    );
}
