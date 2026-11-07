//! Every Pulse-protected settings change is bound to its own operation, from
//! hashgraph-online/hol-guard#7352: a Pulse approval for one change cannot
//! complete another, either when the approval comes back or when the change
//! is applied.

use serde_json::json;

use super::*;

const CHANNEL_STABLE: &str = "stable";
const CHANNEL_BETA: &str = "beta";

fn update_channel(channel: &str) -> Value {
    json!({"settings_change": {"kind": "update_channel", "update_channel": channel}})
}

fn reset() -> Value {
    json!({"settings_change": {"kind": "reset"}})
}

/// Start a Pulse approval for `binding` and let the YID app approve it.
fn approved_request(g: &Gate, binding: &Value) -> String {
    let created = g.send(
        "pulse_request",
        NOW,
        json!({"purpose": "settings_write", "strict": true, "params": binding}),
    );
    let id = created["payload"]["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no request id in {created}"))
        .to_owned();
    assert_eq!(g.poll(&id)["payload"]["status"], "approved");
    id
}

/// Hand an approved request back for `binding`, as a route would.
fn verify_for(g: &Gate, id: &str, binding: &Value) -> Value {
    g.send(
        "verify",
        LATER,
        json!({"purpose": "settings_write", "strict": true, "params": binding,
               "approval_gate_input": {"pulse_request_id": id}}),
    )
}

fn grant_for(g: &Gate, binding: &Value) -> Value {
    let id = approved_request(g, binding);
    let verified = verify_for(g, &id, binding);
    assert_eq!(verified["status"], "ok", "{verified}");
    verified["payload"]["grant"].clone()
}

fn apply_settings_write(g: &Gate, grant: &Value, binding: &Value) -> Value {
    g.send(
        "require_settings_write",
        LATER,
        json!({"approval_gate_grant": grant, "params": binding}),
    )
}

fn disable(g: &Gate, grant: &Value) -> Value {
    g.send(
        "disable_pulse",
        LATER,
        json!({"approval_gate_grant": grant}),
    )
}

fn assert_pulse_still_on(g: &Gate) {
    assert!(
        load_state(&g.home).get("pulse_yid").is_some(),
        "Pulse was turned off"
    );
}

#[test]
fn an_update_channel_approval_cannot_be_used_to_disable_pulse_or_reset() {
    let (g, _) = pulse_gate("bind-channel", 0);
    let id = approved_request(&g, &update_channel(CHANNEL_STABLE));
    for other in [disable_binding(), reset()] {
        let r = verify_for(&g, &id, &other);
        assert_ne!(
            r["status"], "ok",
            "{other} accepted an update-channel approval: {r}"
        );
    }
    assert_pulse_still_on(&g);
}

#[test]
fn a_disable_or_reset_approval_cannot_be_used_for_another_change() {
    let (g, _) = pulse_gate("bind-reverse", 0);
    let id = approved_request(&g, &disable_binding());
    for other in [update_channel(CHANNEL_STABLE), reset()] {
        let r = verify_for(&g, &id, &other);
        assert_ne!(
            r["status"], "ok",
            "{other} accepted a disable approval: {r}"
        );
    }
    let id = approved_request(&g, &reset());
    for other in [update_channel(CHANNEL_STABLE), disable_binding()] {
        let r = verify_for(&g, &id, &other);
        assert_ne!(r["status"], "ok", "{other} accepted a reset approval: {r}");
    }
    assert_pulse_still_on(&g);
}

#[test]
fn an_update_channel_approval_covers_only_the_channel_it_named() {
    let (g, _) = pulse_gate("bind-value", 0);
    let id = approved_request(&g, &update_channel(CHANNEL_STABLE));
    let r = verify_for(&g, &id, &update_channel(CHANNEL_BETA));
    assert_ne!(r["status"], "ok", "{r}");
}

#[test]
fn disabling_pulse_needs_a_grant_issued_for_disabling_pulse() {
    let (g, _) = pulse_gate("bind-disable-grant", 0);
    for binding in [json!({}), update_channel(CHANNEL_STABLE), reset()] {
        let grant = grant_for(&g, &binding);
        let r = disable(&g, &grant);
        assert_ne!(
            r["status"], "ok",
            "a grant for {binding} turned Pulse off: {r}"
        );
        assert_pulse_still_on(&g);
    }
    let grant = grant_for(&g, &disable_binding());
    let r = disable(&g, &grant);
    assert_eq!(r["status"], "ok", "{r}");
}

#[test]
fn a_named_settings_write_needs_a_grant_for_that_exact_change() {
    let (g, _) = pulse_gate("bind-consumer", 0);
    let stable = update_channel(CHANNEL_STABLE);
    for binding in [
        json!({}),
        disable_binding(),
        reset(),
        update_channel(CHANNEL_BETA),
    ] {
        let grant = grant_for(&g, &binding);
        let r = apply_settings_write(&g, &grant, &stable);
        assert_ne!(
            r["status"], "ok",
            "a grant for {binding} changed the channel: {r}"
        );
    }
    for binding in [json!({}), disable_binding(), stable.clone()] {
        let grant = grant_for(&g, &binding);
        let r = apply_settings_write(&g, &grant, &reset());
        assert_ne!(
            r["status"], "ok",
            "a grant for {binding} reset settings: {r}"
        );
    }
    let grant = grant_for(&g, &stable);
    assert_eq!(apply_settings_write(&g, &grant, &stable)["status"], "ok");
    let grant = grant_for(&g, &reset());
    assert_eq!(apply_settings_write(&g, &grant, &reset())["status"], "ok");
}
