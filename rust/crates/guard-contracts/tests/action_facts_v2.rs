use std::collections::BTreeMap;

use guard_contracts::{ActionFactsV2, FactSelectorV2, FactSubjectV2, Match3, SessionFlowV2};
use serde_json::Value;

fn fixtures() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/cloud-actions/action-facts-v2-fixtures.json"
    ))
    .unwrap()
}

fn patched(base: &Value, patch: Option<&Value>) -> Value {
    let mut value = base.clone();
    if let Some(patch) = patch.and_then(Value::as_object) {
        for (key, field) in patch {
            value[key] = field.clone();
        }
    }
    value
}

#[test]
fn facts_validation_vectors() {
    let fixtures = fixtures();
    for case in fixtures["facts"].as_array().unwrap() {
        let value = patched(&fixtures["base"], case.get("patch"));
        let decoded = ActionFactsV2::from_bounded_json(&serde_json::to_vec(&value).unwrap());
        assert_eq!(
            decoded.is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}: {decoded:?}",
            case["id"]
        );
    }
}

#[test]
fn facts_round_trip_byte_identically() {
    let fixtures = fixtures();
    for case in fixtures["facts"].as_array().unwrap() {
        if case["valid"] != true {
            continue;
        }
        let value = patched(&fixtures["base"], case.get("patch"));
        let decoded =
            ActionFactsV2::from_bounded_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&decoded).unwrap(),
            value,
            "{}",
            case["id"]
        );
    }
}

#[test]
fn oversized_facts_are_refused_before_parsing() {
    let bytes = vec![b' '; guard_contracts::MAX_ACTION_FACTS_BYTES + 1];
    assert_eq!(
        ActionFactsV2::from_bounded_json(&bytes),
        Err(guard_contracts::ActionFactsErrorV2::LimitExceeded)
    );
}

#[test]
fn selector_vectors() {
    let fixtures = fixtures();
    for case in fixtures["selectors"].as_array().unwrap() {
        let id = &case["id"];
        let selector: Result<FactSelectorV2, _> = serde_json::from_value(case["selector"].clone());
        let selector = match selector {
            Ok(selector) if selector.validate().is_ok() => selector,
            _ => {
                assert_eq!(case["expect"], "invalid", "{id}");
                continue;
            }
        };
        assert_ne!(case["expect"], "invalid", "{id}");
        let facts_value = patched(&fixtures["base"], case.get("facts"));
        let facts = ActionFactsV2::from_bounded_json(&serde_json::to_vec(&facts_value).unwrap())
            .unwrap_or_else(|error| panic!("{id}: {error:?}"));
        let session: Option<SessionFlowV2> = case
            .get("session")
            .map(|value| serde_json::from_value(value.clone()).unwrap());
        let windows: BTreeMap<String, u64> = case
            .get("windows")
            .map(|value| serde_json::from_value(value.clone()).unwrap())
            .unwrap_or_default();
        let subject = FactSubjectV2 {
            provider: case["provider"].as_str().unwrap_or("google_gmail"),
            facts: &facts,
            session: session.as_ref(),
            windows: &windows,
        };
        let expected = match case["expect"].as_str().unwrap() {
            "yes" => Match3::Yes,
            "no" => Match3::No,
            "unknown" => Match3::Unknown,
            other => panic!("{id}: {other}"),
        };
        assert_eq!(selector.matches(&subject), expected, "{id}");
    }
}
