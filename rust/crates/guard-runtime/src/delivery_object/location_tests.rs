use super::*;

fn digest() -> String {
    "ab".repeat(32)
}

fn tag() -> String {
    format!("extension-data-{}-12.3-000001", "c".repeat(40))
}

fn whole(kind: &str) -> Value {
    let suffix = if kind == "object" { "json" } else { "zip" };
    json!({"tag": tag(), "asset": format!("{kind}-{}.{suffix}", digest())})
}

fn member(kind: &str, container: &str) -> Value {
    let suffix = if kind == "object" { "json" } else { "zip" };
    json!({
        "tag": tag(),
        "asset": container,
        "member": format!("{kind}-{}.{suffix}", digest()),
    })
}

fn message(outcome: Outcome) -> String {
    outcome.unwrap_err()
}

#[test]
fn container_names_are_numbered_per_family() {
    assert!(family("objects-000001.zip") == Some(Family::Objects));
    assert!(family("packs-123456.zip") == Some(Family::Packs));
    for name in [
        "objects-1.zip",
        "objects-0000001.zip",
        "objects-00000a.zip",
        "objects-000001.zip.zip",
        "pack-000001.zip",
        "objects-000001.json",
        "",
    ] {
        assert!(family(name).is_none(), "{name}");
    }
    assert_eq!(Family::Objects.bound(), 8 * 1024 * 1024);
    assert_eq!(Family::Packs.bound(), 32 * 1024 * 1024);
}

#[test]
fn a_whole_asset_must_be_named_for_its_digest() {
    assert!(check(&whole("object"), &digest(), "object").is_ok());
    assert!(check(&whole("pack"), &digest(), "pack").is_ok());
    assert_eq!(
        check(&whole("object"), &"cd".repeat(32), "object").unwrap_err(),
        "delivery asset identity invalid"
    );
    assert_eq!(
        check(&whole("pack"), &digest(), "object").unwrap_err(),
        "delivery asset identity invalid"
    );
}

#[test]
fn a_member_must_sit_in_a_container_of_its_family() {
    let digest = digest();
    assert!(check(&member("object", "objects-000001.zip"), &digest, "object").is_ok());
    assert!(check(&member("pack", "packs-000002.zip"), &digest, "pack").is_ok());
    for (kind, container) in [
        ("object", "packs-000001.zip"),
        ("pack", "objects-000001.zip"),
        ("object", "objects-1.zip"),
        ("object", "object-abab.json"),
    ] {
        assert_eq!(
            check(&member(kind, container), &digest, kind).unwrap_err(),
            "delivery container location invalid",
            "{kind} in {container}"
        );
    }
    let mut other = member("object", "objects-000001.zip");
    other["member"] = json!(format!("object-{}.json", "cd".repeat(32)));
    assert_eq!(
        check(&other, &digest, "object").unwrap_err(),
        "delivery container location invalid"
    );
}

#[test]
fn a_location_has_exactly_its_known_fields_and_a_valid_tag() {
    let digest = digest();
    let mut extra = whole("object");
    extra["note"] = json!("x");
    let mut loose = member("object", "objects-000001.zip");
    loose["note"] = json!("x");
    let mut tagless = whole("object");
    tagless.as_object_mut().unwrap().remove("tag");
    let mut bad_tag = whole("object");
    bad_tag["tag"] = json!("extension-data-short-1.1-000001");
    let mut bad_sequence = whole("object");
    bad_sequence["tag"] = json!(format!("extension-data-{}-1.1-1", "c".repeat(40)));
    let mut no_asset = whole("object");
    no_asset.as_object_mut().unwrap().remove("asset");
    let cases = [
        extra,
        loose,
        tagless,
        bad_tag,
        bad_sequence,
        no_asset,
        json!("object"),
        json!(null),
    ];
    for case in cases {
        assert_eq!(
            check(&case, &digest, "object").unwrap_err(),
            "delivery asset location invalid",
            "{case}"
        );
    }
    assert_eq!(
        check(&whole("object"), "ABAB", "object").unwrap_err(),
        "delivery asset location invalid"
    );
    assert_eq!(
        check(&whole("object"), &digest, "blob").unwrap_err(),
        "delivery asset location invalid"
    );
}

#[test]
fn a_release_target_resolves_to_its_asset_and_bound() {
    let whole_asset = asset(&json!({"profile": "release", "target": whole("pack")})).unwrap();
    assert_eq!(whole_asset["name"], format!("pack-{}.zip", digest()));
    assert_eq!(whole_asset["kind"], "pack");
    assert_eq!(whole_asset["digest"], digest());
    assert_eq!(whole_asset["tag"], tag());
    assert_eq!(whole_asset["bound"], Value::Null);
    let target = member("object", "objects-000004.zip");
    let inside = asset(&json!({"profile": "release", "target": target})).unwrap();
    assert_eq!(inside["asset"], "objects-000004.zip");
    assert_eq!(inside["name"], format!("object-{}.json", digest()));
    assert_eq!(inside["bound"], 8 * 1024 * 1024);
}

#[test]
fn a_release_target_with_a_wrong_name_is_refused() {
    let mut numeric = whole("object");
    numeric["asset"] = json!(7);
    let mut misnamed = whole("object");
    misnamed["asset"] = json!("notes.json");
    for target in [numeric, misnamed] {
        let outcome = asset(&json!({"profile": "release", "target": target}));
        assert_eq!(message(outcome), "release object location invalid");
    }
    let outcome = asset(&json!({"profile": "release", "target": "object"}));
    assert_eq!(message(outcome), "release object location invalid");
    assert_eq!(
        message(asset(&json!({"profile": "other"}))),
        "delivery object request invalid"
    );
}

#[test]
fn an_installed_target_is_bound_to_its_source() {
    let source = "c".repeat(40);
    let installed = json!({
        "tag": format!("extension-data-{source}-0.0-000007"),
        "asset": "packs-000002.zip",
        "member": format!("pack-{}.zip", digest()),
    });
    let ok = asset(&json!({"profile": "installed", "target": installed, "source": source}));
    let ok = ok.unwrap();
    assert_eq!(ok["bound"], 32 * 1024 * 1024);
    assert_eq!(ok["kind"], "pack");
    let outcome =
        asset(&json!({"profile": "installed", "target": installed, "source": "d".repeat(40)}));
    assert_eq!(message(outcome), "installed bundle asset source differs");
    let released = json!({"tag": tag(), "asset": format!("object-{}.json", digest())});
    let outcome = asset(&json!({"profile": "installed", "target": released, "source": source}));
    assert_eq!(message(outcome), "installed bundle asset source differs");
    let outcome = asset(&json!({"profile": "installed", "target": installed}));
    assert_eq!(message(outcome), "delivery object request invalid");
    let outcome = asset(&json!({"profile": "installed", "target": ["x"], "source": source}));
    assert_eq!(message(outcome), "installed bundle location invalid");
    let outcome =
        asset(&json!({"profile": "installed", "target": {"asset": "x"}, "source": source}));
    assert_eq!(message(outcome), "installed bundle asset invalid");
}
