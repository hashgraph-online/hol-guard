//! Replays the recorded continuity vectors through the commit the resident
//! answers, so each commit is checked against what the reference Python planned
//! for the same request.

use serde_json::{json, Value};

use super::*;

const VECTORS: &str = include_str!("../tests/fixtures/custom_extension_continuity_vectors.json");

fn vectors(operation: &str) -> Vec<Value> {
    let all: Vec<Value> = serde_json::from_str(VECTORS).expect("vectors");
    all.into_iter()
        .filter(|vector| vector["request"]["operation"] == operation)
        .collect()
}

#[test]
fn plan_commit_applies_what_the_recorded_plan_says() {
    let (mut v1, mut v2, mut last_good, mut removals, mut refused) = (0, 0, 0, 0, 0);
    for vector in vectors("plan") {
        let name = &vector["name"];
        let expected = &vector["expected"];
        let got = evaluate(&vector["request"]).expect("answer");
        if expected["error"].is_string() {
            assert_eq!(&got, expected, "vector {name}");
            refused += 1;
            continue;
        }
        assert_eq!(got["error"], Value::Null, "vector {name}");
        for key in ["authority_updates", "events", "observation_preconditions"] {
            assert_eq!(got[key], expected[key], "vector {name} {key}");
        }
        let writes = got["writes"].as_array().expect("writes");
        let keeps_last_good = expected["write_last_good"] == true;
        let state_roles = if keeps_last_good {
            json!(["state", "last_good"])
        } else {
            json!(["state"])
        };
        assert_eq!(
            writes[0],
            json!({
                "stores": state_roles,
                "payload": expected["state"],
                "item_order": expected["state_item_order"],
            }),
            "vector {name}"
        );
        match &expected["removals"] {
            Value::Null => assert_eq!(writes.len(), 1, "vector {name}"),
            payload => {
                assert_eq!(writes.len(), 2, "vector {name}");
                assert_eq!(
                    writes[1],
                    json!({ "stores": ["removals"], "payload": payload, "item_order": null }),
                    "vector {name}"
                );
                removals += 1;
            }
        }
        let is_v2 = expected["v2"] == true;
        let capability = if is_v2 {
            json!("custom-extension-continuity.v2")
        } else {
            Value::Null
        };
        assert_eq!(
            got["requirements"],
            json!({ "protected_authority": is_v2, "capability": capability }),
            "vector {name}"
        );
        if is_v2 {
            v2 += 1;
        } else {
            v1 += 1;
        }
        if keeps_last_good {
            last_good += 1;
        }
    }
    assert!(v1 > 0 && v2 > 0 && last_good > 0 && removals > 0 && refused > 0);
}

#[test]
fn local_commit_keeps_the_tombstone_and_the_updated_state() {
    let mut with_state = 0;
    let mut without_state = 0;
    for vector in vectors("local_mutation") {
        let name = &vector["name"];
        let expected = &vector["expected"];
        let got = evaluate(&vector["request"]).expect("answer");
        assert_eq!(got["event"], expected["event"], "vector {name}");
        assert_eq!(
            got["observation_precondition"], expected["observation_precondition"],
            "vector {name}"
        );
        let tombstone = json!({
            "stores": ["removals"],
            "payload": expected["removals"],
            "item_order": null,
        });
        let writes = got["writes"].as_array().expect("writes");
        if expected["active"].is_null() {
            assert_eq!(writes, &vec![tombstone], "vector {name}");
            without_state += 1;
        } else {
            let state = json!({
                "stores": ["state"],
                "payload": expected["active"],
                "item_order": expected["active_item_order"],
            });
            assert_eq!(writes, &vec![state, tombstone], "vector {name}");
            with_state += 1;
        }
    }
    assert!(with_state > 0 && without_state > 0);
}

#[test]
fn a_request_for_details_reaches_the_client_unchanged() {
    let mut asked = 0;
    for vector in vectors("plan") {
        let mut lazy = vector["request"].clone();
        lazy["details"] = json!({});
        let Some(planned) = settle(plan(&lazy))
            .ok()
            .filter(|answer| answer.get("need_details").is_some())
        else {
            continue;
        };
        assert_eq!(evaluate(&lazy), Ok(planned), "vector {}", vector["name"]);
        asked += 1;
    }
    assert!(asked > 0);
}

#[test]
fn an_update_without_an_observation_guard_is_refused() {
    let updates = json!([{ "cli_id": "local-cli.a" }]);
    for preconditions in [
        json!({}),
        json!({ "local-cli.a": null }),
        json!({ "local-cli.b": {} }),
    ] {
        assert!(
            matches!(
                require_guards(&updates, &preconditions),
                Err(Fail::Refusal(_))
            ),
            "{preconditions}"
        );
    }
    assert!(matches!(
        require_guards(&json!([{}]), &json!({ "local-cli.a": {} })),
        Err(Fail::Refusal(_))
    ));
    assert!(require_guards(&updates, &json!({ "local-cli.a": {} })).is_ok());
    assert!(require_guards(&json!([]), &json!({})).is_ok());
    assert!(matches!(
        require_guards(&json!({}), &json!({})),
        Err(Fail::Request)
    ));
}
