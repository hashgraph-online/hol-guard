//! Pulse tests added during review of hashgraph-online/hol-guard#7236. Each
//! test names the behavior it protects, so removing the check breaks it.

use serde_json::json;

use super::*;
use crate::approval_gate_pulse::{
    TEST_AFTER_TRANSPORT, TEST_MAX_PENDING_PER_HOME, TEST_PULSE_LEDGER_MAX,
};

/// Run `f` right after the resident's next call to Yanez.
fn after_next_network_call(f: impl FnOnce() + 'static) {
    TEST_AFTER_TRANSPORT.with(|h| *h.borrow_mut() = Some(Box::new(f)));
}

fn request_id(result: &Value) -> String {
    result["payload"]["request_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no request id in {result}"))
        .to_owned()
}

fn confirm(g: &Gate, id: &str) -> Value {
    g.send(
        "confirm_pulse_enrollment",
        NOW,
        json!({"params": {"request_id": id}}),
    )
}

#[test]
fn confirming_before_the_app_approves_keeps_the_setup_waiting() {
    let g = password_gate("early-confirm");
    let id = request_id(&begin(&g));
    let early = confirm(&g, &id);
    assert_eq!(code(&early), "approval_gate_pulse_pending", "{early}");
    assert_eq!(g.poll(&id)["payload"]["status"], "approved");
    let confirmed = confirm(&g, &id);
    assert_eq!(confirmed["payload"]["pulse_enabled"], true, "{confirmed}");
}

#[test]
fn a_confirm_from_another_session_does_not_cancel_the_setup() {
    let g = password_gate("stray-confirm");
    let id = request_id(&begin(&g));
    g.poll(&id);
    let stray = send_from(
        &g.home,
        "sid=other",
        "confirm_pulse_enrollment",
        NOW,
        json!({"params": {"request_id": id}}),
    );
    assert_eq!(code(&stray), "approval_gate_pulse_terms_mismatch");
    let confirmed = confirm(&g, &id);
    assert_eq!(confirmed["payload"]["pulse_enabled"], true, "{confirmed}");
}

#[test]
fn a_failed_spend_at_pulse_leaves_nothing_enabled_and_can_be_retried() {
    let g = password_gate("spend-fails");
    let id = request_id(&begin(&g));
    g.poll(&id);
    // The receipt verifies, then Pulse is unreachable for the spend.
    let fake = g.fake.clone();
    after_next_network_call(move || *fake.offline.borrow_mut() = true);
    let failed = confirm(&g, &id);
    assert_eq!(code(&failed), "approval_gate_pulse_unavailable", "{failed}");
    let st = load_state(&g.home);
    assert_ne!(st["pulse_enabled"], true);
    assert!(st.get("pulse_agent_secret_id").is_none());
    *g.fake.offline.borrow_mut() = false;
    let confirmed = confirm(&g, &id);
    assert_eq!(confirmed["payload"]["pulse_enabled"], true, "{confirmed}");
}

#[test]
fn a_password_change_during_confirm_is_not_undone() {
    let g = password_gate("confirm-race");
    let id = request_id(&begin(&g));
    g.poll(&id);
    let home = g.home.clone();
    after_next_network_call(move || {
        // What a settings save does: a new factor generation.
        let mut st = load_state(&home);
        st["factor_generation"] = json!(7);
        write_state(&home, &st, Some(NOW)).unwrap();
    });
    let r = confirm(&g, &id);
    assert_eq!(code(&r), "approval_gate_pulse_terms_mismatch", "{r}");
    let st = load_state(&g.home);
    assert_eq!(st["factor_generation"], 7, "the newer settings stay");
    assert_ne!(st["pulse_enabled"], true);
    assert!(
        g.fake.consumed.borrow().is_empty(),
        "nothing spent at Pulse"
    );
}

#[test]
fn turning_pulse_off_during_a_verify_is_not_undone() {
    let (g, _) = pulse_gate("verify-race", 0);
    let id = request_id(&g.request("approval_decision", "allow", "artifact", false));
    g.poll(&id);
    let home = g.home.clone();
    after_next_network_call(move || {
        let mut st = load_state(&home);
        crate::approval_gate_pulse::clear_pulse_state(&home, &mut st);
        st["factor_generation"] = json!(99);
        write_state(&home, &st, Some(NOW)).unwrap();
    });
    let r = g.verify(
        "approval_decision",
        "allow",
        "artifact",
        false,
        json!({"pulse_request_id": id}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_terms_mismatch", "{r}");
    let st = load_state(&g.home);
    assert!(st.get("pulse_enabled").is_none(), "Pulse stays off");
    assert_eq!(st["factor_generation"], 99);
}

#[test]
fn spent_receipts_leave_the_ledger_once_they_can_no_longer_verify() {
    let (g, _) = pulse_gate("ledger-age", 0);
    let mut st = load_state(&g.home);
    let long_ago = epoch(Some(NOW)) as i64 - 3600;
    for n in 0..TEST_PULSE_LEDGER_MAX {
        st["pulse_consumed"][format!("old-{n}")] = json!(long_ago);
    }
    write_state(&g.home, &st, Some(NOW)).unwrap();
    let r = g.approve("approval_decision", "allow", "artifact", json!({}));
    assert_eq!(r["status"], "ok", "{r}");
}

#[test]
fn a_full_ledger_says_so_instead_of_calling_it_a_replay() {
    let (g, _) = pulse_gate("ledger-full", 0);
    let mut st = load_state(&g.home);
    let live = epoch(Some(NOW)) as i64 + 600;
    for n in 0..TEST_PULSE_LEDGER_MAX {
        st["pulse_consumed"][format!("live-{n}")] = json!(live);
    }
    write_state(&g.home, &st, Some(NOW)).unwrap();
    let spent_before = g.fake.consumed.borrow().len();
    let r = g.approve("approval_decision", "allow", "artifact", json!({}));
    assert_eq!(code(&r), "approval_gate_pulse_ledger_full", "{r}");
    assert_eq!(r["error_status"], 429);
    assert_eq!(
        g.fake.consumed.borrow().len(),
        spent_before,
        "no remote spend after a local refusal"
    );
}

#[test]
fn a_request_and_its_verify_agree_when_neither_names_a_purpose() {
    let (g, _) = pulse_gate("no-purpose", 0);
    let id = request_id(&g.send(
        "pulse_request",
        NOW,
        json!({"params": {"action": "allow", "scope": "artifact"}}),
    ));
    g.poll(&id);
    let r = g.send(
        "verify",
        LATER,
        json!({"params": {"action": "allow", "scope": "artifact"},
               "approval_gate_input": {"pulse_request_id": id}}),
    );
    assert_eq!(r["status"], "ok", "{r}");
}

#[test]
fn a_full_pending_table_refuses_new_prompts_instead_of_dropping_old_ones() {
    let (g, _) = pulse_gate("busy", 0);
    let first = request_id(&g.request("approval_decision", "allow", "artifact", false));
    for _ in 1..TEST_MAX_PENDING_PER_HOME {
        assert_eq!(
            g.request("approval_decision", "allow", "artifact", false)["status"],
            "ok"
        );
    }
    let sent = g.fake.created.borrow().len();
    let refused = g.request("approval_decision", "allow", "artifact", false);
    assert_eq!(code(&refused), "approval_gate_pulse_busy", "{refused}");
    assert_eq!(refused["error_status"], 429);
    assert_eq!(
        g.fake.created.borrow().len(),
        sent,
        "nothing reaches the phone"
    );
    g.poll(&first);
    let r = g.verify(
        "approval_decision",
        "allow",
        "artifact",
        false,
        json!({"pulse_request_id": first}),
    );
    assert_eq!(r["status"], "ok", "the oldest request still works: {r}");
}

#[test]
fn turning_pulse_off_frees_the_slots_of_its_waiting_requests() {
    let (g, recovery) = pulse_gate("off-clears", 0);
    g.request("approval_decision", "allow", "artifact", false);
    g.request("approval_decision", "block", "workspace", false);
    assert_eq!(pending_len(&g.home), 2);
    let off = g.send(
        "recover_pulse",
        NOW,
        json!({"approval_gate_input": {"password": PASSWORD, "pulse_recovery_code": recovery}}),
    );
    assert_eq!(off["payload"]["pulse_enabled"], false, "{off}");
    assert_eq!(pending_len(&g.home), 0);
}

#[test]
fn the_phone_shows_the_decision_the_grant_is_bound_to() {
    let (g, _) = pulse_gate("decision", 0);
    let id = request_id(&g.request("approval_decision", "allow", "publisher", false));
    let terms = g.fake.created.borrow()[&id].clone();
    let decision = terms["details"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["label"] == "Decision")
        .cloned()
        .unwrap_or_else(|| panic!("no Decision row in {terms}"));
    assert_eq!(decision["value"], "Allow, everything from this publisher");
}

#[test]
fn an_outage_while_checking_an_approval_keeps_it_for_a_retry() {
    let (g, _) = pulse_gate("verify-outage", 0);
    let id = request_id(&g.request("approval_decision", "allow", "artifact", false));
    g.poll(&id);
    let prompts = g.fake.created.borrow().len();
    let input = json!({"pulse_request_id": id});
    *g.fake.offline.borrow_mut() = true;
    let down = g.verify(
        "approval_decision",
        "allow",
        "artifact",
        false,
        input.clone(),
    );
    assert_eq!(code(&down), "approval_gate_pulse_unavailable", "{down}");
    *g.fake.offline.borrow_mut() = false;
    let r = g.verify(
        "approval_decision",
        "allow",
        "artifact",
        false,
        input.clone(),
    );
    assert_eq!(r["status"], "ok", "the same approval verifies: {r}");
    assert_eq!(
        g.fake.created.borrow().len(),
        prompts,
        "no new prompt on the phone"
    );
    let replay = g.verify("approval_decision", "allow", "artifact", false, input);
    assert_eq!(
        code(&replay),
        "approval_gate_pulse_required",
        "still single-use"
    );
}

#[test]
fn an_outage_while_confirming_setup_keeps_it_for_a_retry() {
    let g = password_gate("confirm-outage");
    let id = request_id(&begin(&g));
    g.poll(&id);
    *g.fake.offline.borrow_mut() = true;
    let down = confirm(&g, &id);
    assert_eq!(code(&down), "approval_gate_pulse_unavailable", "{down}");
    assert_ne!(load_state(&g.home)["pulse_enabled"], true);
    *g.fake.offline.borrow_mut() = false;
    let confirmed = confirm(&g, &id);
    assert_eq!(confirmed["payload"]["pulse_enabled"], true, "{confirmed}");
}

/// Enroll with a chosen minimum tier; returns the gate.
fn pulse_gate_at(tag: &str, min_tier: &str) -> Gate {
    let g = password_gate(tag);
    let id = request_id(&begin_at(&g, json!(min_tier)));
    g.poll(&id);
    let confirmed = confirm(&g, &id);
    assert_eq!(
        confirmed["payload"]["pulse_min_tier"], min_tier,
        "{confirmed}"
    );
    g
}

fn begin_at(g: &Gate, min_tier: Value) -> Value {
    g.send(
        "begin_pulse_enrollment",
        NOW,
        json!({
            "params": {"min_tier": min_tier},
            "approval_gate_input": {"password": PASSWORD, "pulse_agent_key": AGENT_KEY},
        }),
    )
}

#[test]
fn a_high_floor_refuses_a_medium_scan() {
    let g = pulse_gate_at("tier-high", "high");
    assert_eq!(load_state(&g.home)["pulse_min_tier"], "high");
    *g.fake.approve_tier.borrow_mut() = AssuranceTier::Medium;
    let r = g.approve("approval_decision", "allow", "artifact", json!({}));
    assert_eq!(code(&r), "approval_gate_pulse_assurance_too_low", "{r}");
    *g.fake.approve_tier.borrow_mut() = AssuranceTier::High;
    let r = g.approve("approval_decision", "allow", "artifact", json!({}));
    assert_eq!(r["status"], "ok", "a high scan still passes: {r}");
}

#[test]
fn medium_is_the_floor_when_none_is_chosen() {
    let (g, _) = pulse_gate("tier-default", 0);
    assert_eq!(load_state(&g.home)["pulse_min_tier"], "medium");
    *g.fake.approve_tier.borrow_mut() = AssuranceTier::Medium;
    let r = g.approve("approval_decision", "allow", "artifact", json!({}));
    assert_eq!(r["status"], "ok", "{r}");
    *g.fake.approve_tier.borrow_mut() = AssuranceTier::Low;
    let r = g.approve("approval_decision", "allow", "artifact", json!({}));
    assert_eq!(code(&r), "approval_gate_pulse_assurance_too_low", "{r}");
}

#[test]
fn low_or_unknown_floors_are_refused_before_setup_starts() {
    let g = password_gate("tier-bad");
    for bad in [
        json!("low"),
        json!("High"),
        json!("ultra"),
        json!(""),
        json!(2),
    ] {
        let r = begin_at(&g, bad.clone());
        assert_eq!(code(&r), "approval_gate_pulse_invalid_tier", "{bad}: {r}");
        assert_eq!(r["error_status"], 400);
    }
    assert!(
        g.fake.created.borrow().is_empty(),
        "nothing reaches the phone"
    );
}

#[test]
fn a_high_floor_needs_a_device_that_can_sign_at_high() {
    let g = password_gate("tier-device");
    *g.fake.user_tier.borrow_mut() = Some(AssuranceTier::Medium);
    let r = begin_at(&g, json!("high"));
    assert_eq!(code(&r), "approval_gate_pulse_no_signing_key", "{r}");
    assert!(g.fake.created.borrow().is_empty());
}

#[test]
fn setup_at_a_high_floor_needs_a_high_scan() {
    let g = password_gate("tier-setup");
    let id = request_id(&begin_at(&g, json!("high")));
    *g.fake.approve_tier.borrow_mut() = AssuranceTier::Medium;
    g.poll(&id);
    let r = confirm(&g, &id);
    assert_eq!(code(&r), "approval_gate_pulse_assurance_too_low", "{r}");
    assert_ne!(load_state(&g.home)["pulse_enabled"], true);
}

#[test]
fn a_saved_floor_guard_cannot_read_counts_as_high() {
    let (g, _) = pulse_gate("tier-tampered", 0);
    for saved in [json!("low"), json!("none"), json!(1)] {
        let mut st = load_state(&g.home);
        st["pulse_min_tier"] = saved.clone();
        write_state(&g.home, &st, Some(NOW)).unwrap();
        *g.fake.approve_tier.borrow_mut() = AssuranceTier::Medium;
        let r = g.approve("approval_decision", "allow", "artifact", json!({}));
        assert_eq!(
            code(&r),
            "approval_gate_pulse_assurance_too_low",
            "{saved}: {r}"
        );
    }
}
