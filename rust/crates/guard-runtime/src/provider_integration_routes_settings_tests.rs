use guard_contracts::{ProviderConnectionStateV1 as State, ProviderEffectLevelV1 as Level};

use super::*;
use crate::provider_integration_routes::tests::{
    code, enforce_change, path, stored_setting, with_proof, Fixture, SHIELD, UNCHANGED,
};

fn baseline(fixture: &mut Fixture) -> String {
    let detail = fixture.call("GET", &path(""), Value::Null);
    assert_eq!(detail.status, 200, "{}", detail.body);
    detail.body["settings_baseline"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// Another client turns on the fresh check for the capability.
fn change_elsewhere(fixture: &mut Fixture) {
    let other = json!({
        "settings": [{"capability": "browser.origin-reputation", "effect": "tighten",
                      "require_fresh_check": true, "quieted_reason_codes": []}],
        "enabled_opt_in_facts": [],
    });
    let preview = fixture.call("POST", &path("/settings/preview"), other.clone());
    let proof = preview.body["challenge"].as_str().unwrap().to_owned();
    let applied = fixture.call("POST", &path("/settings"), with_proof(&other, &proof));
    assert_eq!(applied.status, 200, "{}", applied.body);
}

#[test]
fn the_baseline_names_the_stored_state_and_moves_with_it() {
    let mut fixture = Fixture::connected();
    let first = baseline(&mut fixture);
    assert_eq!(first.len(), 64);
    assert_eq!(baseline(&mut fixture), first, "a read changes nothing");
    change_elsewhere(&mut fixture);
    assert_ne!(baseline(&mut fixture), first);
}

#[test]
fn a_preview_from_a_stale_read_is_refused() {
    let mut fixture = Fixture::connected();
    let read = baseline(&mut fixture);
    change_elsewhere(&mut fixture);
    let fresh = stored_setting(&fixture);

    let mut change = enforce_change();
    change["baseline"] = json!(read);
    let answer = fixture.call("POST", &path("/settings/preview"), change);
    assert_eq!((answer.status, code(&answer)), (409, SETTINGS_CHANGED));
    assert_eq!(stored_setting(&fixture), fresh, "nothing was overwritten");
}

#[test]
fn a_change_made_while_the_preview_is_reviewed_refuses_the_apply() {
    let mut fixture = Fixture::connected();
    let mut change = enforce_change();
    change["baseline"] = json!(baseline(&mut fixture));
    let preview = fixture.call("POST", &path("/settings/preview"), change);
    assert_eq!(preview.status, 200, "{}", preview.body);
    let proof = preview.body["challenge"].as_str().unwrap().to_owned();

    change_elsewhere(&mut fixture);
    let fresh = stored_setting(&fixture);
    assert_ne!(fresh, UNCHANGED);
    let answer = fixture.call(
        "POST",
        &path("/settings"),
        with_proof(&enforce_change(), &proof),
    );
    assert_eq!((answer.status, code(&answer)), (403, PROOF_INVALID));
    assert_eq!(stored_setting(&fixture), fresh, "the other change survives");
}

#[test]
fn a_reconnect_between_preview_and_apply_refuses_the_apply() {
    let mut fixture = Fixture::connected();
    let preview = fixture.call("POST", &path("/settings/preview"), enforce_change());
    let proof = preview.body["challenge"].as_str().unwrap().to_owned();
    let mut stored = provider_connection(&fixture.connection, SHIELD)
        .unwrap()
        .unwrap();
    stored.state = State::Connected;
    stored.updated_at_ms += 1;
    put_connection(&fixture.connection, &stored).unwrap();

    let answer = fixture.call(
        "POST",
        &path("/settings"),
        with_proof(&enforce_change(), &proof),
    );
    assert_eq!(code(&answer), PROOF_INVALID);
    assert_eq!(stored_setting(&fixture), UNCHANGED);
}

#[test]
fn a_preview_without_a_baseline_still_applies() {
    let mut fixture = Fixture::connected();
    let preview = fixture.call("POST", &path("/settings/preview"), enforce_change());
    assert!(preview.body["baseline"].is_string());
    let proof = preview.body["challenge"].as_str().unwrap().to_owned();
    let answer = fixture.call(
        "POST",
        &path("/settings"),
        with_proof(&enforce_change(), &proof),
    );
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert_eq!(
        stored_setting(&fixture).map(|setting| setting.effect_level),
        Some(Level::Enforce)
    );
}
