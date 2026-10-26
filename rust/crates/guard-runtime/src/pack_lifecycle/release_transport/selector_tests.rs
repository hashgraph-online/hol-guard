use super::*;

const CONTRACT: &str = "delivery selector contract invalid";
const IDENTITY: &str = "delivery selector identity invalid";
const LOCAL: &str = "local publication cannot become selected";
const CHANGED: &str = "release root differs from advisory selector";
const PUBLICATION: &str = "release root publication identity differs from selector";

fn selector() -> Value {
    json!({
        "schema": "guard.extension-distribution-selector.v2",
        "source_sha": "1".repeat(40),
        "publication_id": "12.1",
        "root_sha256": "2".repeat(64),
    })
}

fn with(field: &str, value: Value) -> Value {
    let mut selector = selector();
    selector[field] = value;
    selector
}

fn validate(value: Value) -> Value {
    evaluate(&json!({"operation": "selector", "value": value})).unwrap()
}

fn rejected(message: &str) -> Value {
    json!({"rejected": message})
}

#[test]
fn a_valid_selector_names_the_tag_its_root_is_published_under() {
    let tag = format!("extension-distribution-{}-12.1", "1".repeat(40));
    assert_eq!(validate(selector()), json!({"tag": tag}));
    let edge = format!("{}.{}", "9".repeat(20), "9".repeat(10));
    let tag = format!("extension-distribution-{}-{edge}", "1".repeat(40));
    assert_eq!(
        validate(with("publication_id", edge.into())),
        json!({"tag": tag})
    );
}

#[test]
fn a_selector_that_is_not_exactly_the_contract_is_refused() {
    let mut extra = selector();
    extra["extra"] = 1.into();
    let mut missing = selector();
    missing.as_object_mut().unwrap().remove("root_sha256");
    for value in [
        Value::Null,
        json!([]),
        json!("selector"),
        json!(3),
        json!({}),
        extra,
        missing,
        with("schema", "guard.extension-distribution-selector.v1".into()),
        with("schema", Value::Null),
        with("schema", 2.into()),
    ] {
        assert_eq!(validate(value.clone()), rejected(CONTRACT), "{value}");
    }
    let reply = evaluate(&json!({"operation": "selector"})).unwrap();
    assert_eq!(reply, rejected(CONTRACT));
}

#[test]
fn every_identity_in_a_selector_is_exact_lowercase_hex_or_digits() {
    let identities = [
        ("source_sha", "1".repeat(39)),
        ("source_sha", "1".repeat(41)),
        ("source_sha", "A".repeat(40)),
        ("source_sha", "g".repeat(40)),
        ("root_sha256", "2".repeat(63)),
        ("root_sha256", "2".repeat(65)),
        ("root_sha256", "F".repeat(64)),
        ("publication_id", "12".into()),
        ("publication_id", "12.".into()),
        ("publication_id", ".1".into()),
        ("publication_id", "1.2.3".into()),
        ("publication_id", "a.1".into()),
        ("publication_id", "1.-2".into()),
        ("publication_id", "\u{661}.1".into()),
        ("publication_id", "12.1\n".into()),
        ("publication_id", " 12.1".into()),
        ("publication_id", format!("{}.1", "1".repeat(21))),
        ("publication_id", format!("1.{}", "1".repeat(11))),
    ];
    for (field, value) in identities {
        let reply = validate(with(field, value.clone().into()));
        assert_eq!(reply, rejected(IDENTITY), "{field} {value:?}");
    }
    for field in ["source_sha", "publication_id", "root_sha256"] {
        for value in [Value::Null, json!(12.1), json!(true), json!(["1"])] {
            assert_eq!(validate(with(field, value)), rejected(IDENTITY), "{field}");
        }
    }
}

#[test]
fn a_local_build_cannot_become_the_selected_publication() {
    for publication in ["0.0", "00.000", "0.00", "000000000000000000.0000000000"] {
        let reply = validate(with("publication_id", publication.into()));
        assert_eq!(reply, rejected(LOCAL), "{publication}");
    }
    for publication in ["0.1", "1.0", "10.0", "0.10"] {
        assert!(validate(with("publication_id", publication.into()))
            .get("tag")
            .is_some());
    }
    // A malformed identity is reported before the local check.
    let mut value = with("publication_id", "0.0".into());
    value["source_sha"] = "z".into();
    assert_eq!(validate(value), rejected(IDENTITY));
}

#[test]
fn a_root_tag_needs_a_full_source_and_a_well_formed_publication() {
    let ask = |source: Value, publication: Value| {
        let input = json!({"operation": "root_tag", "source": source, "publication": publication});
        evaluate(&input).unwrap()
    };
    let tag = format!("extension-distribution-{}-12.1", "a".repeat(40));
    assert_eq!(
        ask("a".repeat(40).into(), "12.1".into()),
        json!({"tag": tag})
    );
    // The published root of a local build is named the same way.
    assert!(ask("a".repeat(40).into(), "0.0".into())
        .get("tag")
        .is_some());
    let invalid = rejected("release source or publication identity invalid");
    for (source, publication) in [
        ("a".repeat(39), "12.1"),
        ("A".repeat(40), "12.1"),
        ("a".repeat(40), "12"),
        ("a".repeat(40), "12.1.1"),
        ("a".repeat(40), ""),
    ] {
        assert_eq!(ask(source.into(), publication.into()), invalid);
    }
    assert_eq!(ask(Value::Null, "12.1".into()), invalid);
    assert_eq!(ask("a".repeat(40).into(), json!(12.1)), invalid);
}

#[test]
fn a_fetched_root_must_be_the_one_the_selector_names() {
    let bind = |fields: Value| {
        let mut input = json!({"operation": "bind", "selector": selector()});
        for (key, value) in fields.as_object().unwrap() {
            input[key] = value.clone();
        }
        evaluate(&input).unwrap()
    };
    let bound = json!({"bound": true});
    assert_eq!(bind(json!({"root_sha256": "2".repeat(64)})), bound);
    assert_eq!(bind(json!({"publication_id": "12.1"})), bound);
    let both = json!({"root_sha256": "2".repeat(64), "publication_id": "12.1"});
    assert_eq!(bind(both), bound);
    assert_eq!(
        bind(json!({"root_sha256": "3".repeat(64)})),
        rejected(CHANGED)
    );
    assert_eq!(bind(json!({"root_sha256": Value::Null})), rejected(CHANGED));
    assert_eq!(bind(json!({"root_sha256": 2})), rejected(CHANGED));
    assert_eq!(
        bind(json!({"publication_id": "12.2"})),
        rejected(PUBLICATION)
    );
    assert_eq!(bind(json!({"publication_id": 12.1})), rejected(PUBLICATION));
    // The digest is judged first, so a substituted root is never read further.
    let both = json!({"root_sha256": "3".repeat(64), "publication_id": "12.2"});
    assert_eq!(bind(both), rejected(CHANGED));
    assert_eq!(
        bind(json!({})),
        rejected("release transport request invalid")
    );
}

#[test]
fn binding_refuses_a_selector_that_is_not_the_contract() {
    let input = json!({
        "operation": "bind",
        "selector": with("publication_id", "0.0".into()),
        "root_sha256": "2".repeat(64),
    });
    assert_eq!(evaluate(&input).unwrap(), rejected(LOCAL));
    let input = json!({"operation": "bind", "root_sha256": "2".repeat(64)});
    assert_eq!(evaluate(&input).unwrap(), rejected(CONTRACT));
}
