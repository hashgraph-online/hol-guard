use serde_json::{json, Value};

use super::*;

const IDENTITY: &str = "a1b2c3";

fn intent(risks: Value) -> Value {
    json!({
        "version": 1,
        "intent": "browser.interact",
        "operation": "click",
        "target_origin": "https://example.test",
        "target_domain": " example.test ",
        "mcp_server_name": "chrome-devtools",
        "mcp_server_identity_hash": IDENTITY,
        "risk_categories": risks,
    })
}

fn pick(target: &str, duration: &str) -> Value {
    json!({
        "target": target,
        "duration": duration,
        "now": "2026-07-21T12:00:00.000000+00:00",
        "artifact_id": "codex:project:chrome-devtools:click",
        "artifact_hash": "exact-hash",
    })
}

fn select_one(intent: Value, selection: Value) -> Value {
    dispatch(&json!({ "browser_intent": intent, "selection": selection })).expect("answer")
}

#[test]
fn a_routine_intent_offers_the_bounded_card() {
    let answer = dispatch(&json!({
        "browser_intents": [intent(json!(["browser_interaction", "browser_external_domain"]))],
    }))
    .expect("answer");
    assert_eq!(
        answer["approvals"][0],
        json!({
            "version": 1,
            "eligible": true,
            "server_name": "chrome-devtools",
            "server_identity_hash": IDENTITY,
            "category": "browser_interaction",
            "target_label": "example.test",
            "allowed_targets": ["exact", "category", "server"],
            "allowed_durations": ["once", "15m", "1h", "5h"],
            "hard_risk_exclusions": HARD_RISK_EXCLUSIONS,
        })
    );
}

#[test]
fn any_risk_beyond_the_routine_category_offers_nothing() {
    let mut unnamed = intent(json!(["browser_interaction"]));
    unnamed["mcp_server_name"] = json!("  ");
    let mut unknown = intent(json!(["browser_interaction"]));
    unknown["intent"] = json!("browser.download");
    let answer = dispatch(&json!({
        "browser_intents": [
            intent(json!(["browser_interaction", "secret_access"])),
            intent(json!(["browser_privileged"])),
            intent(json!([])),
            intent(json!("browser_interaction")),
            unnamed,
            unknown,
            "not an intent",
            null,
            intent(json!(["browser_interaction"])),
        ],
    }))
    .expect("answer");
    let approvals = answer["approvals"].as_array().expect("approvals");
    assert_eq!(approvals.len(), 9);
    assert!(approvals[..8].iter().all(Value::is_null), "{approvals:?}");
    assert_eq!(approvals[8]["category"], json!("browser_interaction"));
}

#[test]
fn the_origin_labels_the_card_when_no_domain_is_filed() {
    let mut filed = intent(json!(["browser_interaction"]));
    filed
        .as_object_mut()
        .expect("intent")
        .remove("target_domain");
    let answer = dispatch(&json!({ "browser_intents": [filed] })).expect("answer");
    assert_eq!(
        answer["approvals"][0]["target_label"],
        json!("https://example.test")
    );
}

#[test]
fn a_pick_names_its_selector_and_a_server_clock_expiry() {
    let routine = intent(json!(["browser_interaction"]));
    let category = select_one(routine.clone(), pick("category", "5h"));
    assert_eq!(category["refusal"], Value::Null);
    assert_eq!(
        category["selection"],
        json!({
            "target": "category",
            "duration": "5h",
            "expires_at": "2026-07-21T17:00:00+00:00",
            "server_name": "chrome-devtools",
            "server_identity_hash": IDENTITY,
            "category": "browser_interaction",
            "artifact_id": format!("mcp-temporary-grant:v1:{IDENTITY}:category:browser_interaction"),
        })
    );

    let server = select_one(routine.clone(), pick("server", "15m"));
    assert_eq!(
        server["selection"]["artifact_id"],
        json!(format!("mcp-temporary-grant:v1:{IDENTITY}:server"))
    );
    assert_eq!(
        server["selection"]["expires_at"],
        json!("2026-07-21T12:15:00+00:00")
    );

    let exact = select_one(routine, pick("exact", "1h"));
    let digest = guard_policy_snapshot::digest_bytes(
        "codex:project:chrome-devtools:click\0exact-hash".as_bytes(),
    );
    assert_eq!(
        exact["selection"]["artifact_id"],
        json!(format!("mcp-temporary-grant:v1:exact:{digest}"))
    );
}

#[test]
fn an_offset_or_naive_clock_expires_in_utc() {
    let routine = intent(json!(["browser_interaction"]));
    let mut offset = pick("server", "1h");
    offset["now"] = json!("2026-07-21T14:30:00.250000+02:00");
    assert_eq!(
        select_one(routine.clone(), offset)["selection"]["expires_at"],
        json!("2026-07-21T13:30:00.250000+00:00")
    );
    let mut naive = pick("server", "1h");
    naive["now"] = json!("2026-07-21T12:00:00Z");
    assert_eq!(
        select_one(routine, naive)["selection"]["expires_at"],
        json!("2026-07-21T13:00:00+00:00")
    );
}

#[test]
fn a_pick_the_card_does_not_offer_is_refused() {
    let routine = intent(json!(["browser_interaction"]));
    for (target, duration, code) in [
        ("tool", "1h", "invalid_mcp_grant_target"),
        ("server", "24h", "invalid_mcp_grant_duration"),
        ("server", "once", "invalid_mcp_grant_duration"),
    ] {
        let answer = select_one(routine.clone(), pick(target, duration));
        assert_eq!(answer, json!({ "selection": null, "refusal": code }));
    }
    let mut numeric = pick("server", "1h");
    numeric["target"] = json!(1);
    assert_eq!(
        select_one(routine.clone(), numeric)["refusal"],
        json!("invalid_mcp_grant_target")
    );
    let mut clock = pick("server", "1h");
    clock["now"] = json!("yesterday");
    assert_eq!(
        select_one(routine, clock)["refusal"],
        json!("invalid_mcp_grant_timestamp")
    );
    // An ineligible intent is refused before the pick is read.
    assert_eq!(
        select_one(
            intent(json!(["browser_interaction", "command_execution"])),
            pick("tool", "24h")
        ),
        json!({ "selection": null, "refusal": "temporary_mcp_approval_ineligible" })
    );
    assert_eq!(
        dispatch(&json!({ "selection": pick("server", "1h") })).expect("answer")["refusal"],
        json!("temporary_mcp_approval_ineligible")
    );
}

#[test]
fn malformed_requests_are_invalid() {
    let routine = intent(json!(["browser_interaction"]));
    let too_many = vec![Value::Null; MAX_INTENTS + 1];
    let mut missing_clock = pick("server", "1h");
    missing_clock.as_object_mut().expect("pick").remove("now");
    let mut numeric_hash = pick("exact", "1h");
    numeric_hash["artifact_hash"] = json!(7);
    for args in [
        json!([]),
        json!({}),
        json!({ "browser_intents": {} }),
        json!({ "browser_intents": too_many }),
        json!({ "browser_intents": [], "selection": pick("server", "1h") }),
        json!({ "browser_intent": routine.clone() }),
        json!({ "browser_intent": routine.clone(), "selection": "server" }),
        json!({ "browser_intent": routine.clone(), "selection": missing_clock }),
        json!({ "browser_intent": routine.clone(), "selection": numeric_hash }),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
