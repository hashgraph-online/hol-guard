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

fn site_intent(session: bool) -> Value {
    let mut filed = intent(json!(["browser_interaction"]));
    filed["driver_identity_hash"] = json!("d".repeat(64));
    if session {
        filed["session_ref_digest"] = json!("5".repeat(64));
    }
    filed
}

#[test]
fn a_driver_and_site_named_intent_also_offers_site_targets() {
    let answer = dispatch(&json!({
        "browser_intents": [site_intent(true), site_intent(false)],
    }))
    .expect("answer");
    assert_eq!(
        answer["approvals"][0]["allowed_targets"],
        json!([
            "exact",
            "category",
            "server",
            "session-site",
            "site-category",
            "site"
        ])
    );
    assert_eq!(
        answer["approvals"][0]["allowed_durations"],
        json!(["once", "15m", "1h", "5h", "session"])
    );
    assert_eq!(
        answer["approvals"][1]["allowed_targets"],
        json!(["exact", "category", "server", "site-category", "site"])
    );
    assert_eq!(
        answer["approvals"][1]["allowed_durations"],
        json!(["once", "15m", "1h", "5h"])
    );
}

#[test]
fn a_site_pick_is_filed_under_the_driver_identity_hash() {
    let answer = select_one(site_intent(true), pick("site", "1h"));
    let selector = answer["selection"]["artifact_id"]
        .as_str()
        .expect("selector");
    let driver = "d".repeat(64);
    assert!(
        selector.starts_with(&format!("browser-grant:v2:{driver}:site:")),
        "{selector}"
    );
    let session = select_one(site_intent(true), pick("session-site", "session"));
    assert_eq!(session["refusal"], Value::Null);
    assert_eq!(
        session["selection"]["expires_at"],
        json!("2026-07-21T17:00:00+00:00")
    );
}

#[test]
fn site_picks_the_card_does_not_offer_are_refused() {
    let refused = |filed: Value, target: &str, duration: &str| {
        select_one(filed, pick(target, duration))["refusal"].clone()
    };
    // No driver identity: no site targets at all.
    assert_eq!(
        refused(intent(json!(["browser_interaction"])), "site", "1h"),
        json!("invalid_mcp_grant_target")
    );
    // No session: no session-site, and `session` is not a timed duration.
    assert_eq!(
        refused(site_intent(false), "session-site", "1h"),
        json!("invalid_mcp_grant_target")
    );
    assert_eq!(
        refused(site_intent(true), "site", "session"),
        json!("invalid_mcp_grant_duration")
    );
    assert_eq!(
        refused(site_intent(true), "site-group", "1h"),
        json!("invalid_mcp_grant_target")
    );
}

/// BP-T061: `site_intent` with `risks` and extra filed fields.
fn tiered_intent(session: bool, risks: Value, extra: Value) -> Value {
    let mut filed = site_intent(session);
    filed["risk_categories"] = risks;
    for (key, value) in extra.as_object().expect("extra") {
        filed[key] = value.clone();
    }
    filed
}

#[test]
fn offers_follow_the_tier_and_the_surface() {
    let shared = json!(["browser_interaction", "browser_shared_profile"]);
    let routine = json!(["browser_interaction"]);
    let password = json!({"element": {"is_password": true}});
    let secret = json!({"input": {"preview_class": "looks_like_secret"}});
    let legacy = json!(["exact", "category", "server"]);
    let rows = [
        (
            tiered_intent(true, shared.clone(), json!({})),
            json!(["session-site"]),
        ),
        (tiered_intent(false, shared.clone(), json!({})), Value::Null),
        (
            tiered_intent(true, shared.clone(), password.clone()),
            Value::Null,
        ),
        (
            tiered_intent(true, shared.clone(), secret.clone()),
            Value::Null,
        ),
        (
            tiered_intent(
                true,
                shared,
                json!({"sensitive_surface_flags": ["cookies"]}),
            ),
            Value::Null,
        ),
        (
            tiered_intent(
                true,
                json!([
                    "browser_interaction",
                    "browser_shared_profile",
                    "browser_privileged"
                ]),
                json!({}),
            ),
            Value::Null,
        ),
        (
            tiered_intent(true, routine.clone(), password),
            legacy.clone(),
        ),
        (tiered_intent(true, routine, secret), legacy),
    ];
    for (filed, targets) in rows {
        let answer = dispatch(&json!({ "browser_intents": [filed.clone()] })).expect("answer");
        let approval = &answer["approvals"][0];
        let offered = if approval.is_null() {
            Value::Null
        } else {
            approval["allowed_targets"].clone()
        };
        assert_eq!(offered, targets, "{filed}");
    }
}

#[test]
fn a_shared_profile_call_may_pick_session_site_and_nothing_else() {
    let filed = tiered_intent(
        true,
        json!(["browser_interaction", "browser_shared_profile"]),
        json!({}),
    );
    let picked = select_one(filed.clone(), pick("session-site", "session"));
    assert_eq!(picked["refusal"], Value::Null);
    for target in ["exact", "category", "server", "site", "site-category"] {
        assert_eq!(
            select_one(filed.clone(), pick(target, "15m"))["refusal"],
            json!("invalid_mcp_grant_target"),
            "{target}"
        );
    }
}

#[test]
fn a_shared_profile_card_does_not_call_the_risk_it_covers_uncoverable() {
    let shared = json!(["browser_interaction", "browser_shared_profile"]);
    let answer = dispatch(&json!({
        "browser_intents": [tiered_intent(true, shared, json!({})), site_intent(true)],
    }))
    .expect("answer");
    let named = |index: usize| answer["approvals"][index]["hard_risk_exclusions"].clone();
    assert_eq!(
        answer["approvals"][0]["allowed_targets"],
        json!(["session-site"])
    );
    assert!(!named(0)
        .as_array()
        .expect("list")
        .contains(&json!("browser_shared_profile")));
    assert!(named(0)
        .as_array()
        .expect("list")
        .contains(&json!("browser_transfer")));
    assert_eq!(named(1), json!(HARD_RISK_EXCLUSIONS));
}
