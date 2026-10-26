//! The repair link a tampered command-control block carries.

use super::*;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::json;

use crate::claude_hook_bridge_fixture::{write_private, GuardHome};

/// The home directory of the person whose command was blocked. The fixture
/// puts its Guard home nowhere near a real one, and most of these tests are
/// not about which home the recovery command names, so they pass none; the
/// two that are about it build the pair themselves.
const NO_HOME_DIR: &str = "";

fn authority_block() -> Value {
    json!({
        "decision": "deny",
        "minimum_action": "block",
        "reason_code": "native_command_control_authority_block",
        "reason": "HOL Guard stopped this command. Run `hol-guard command controls recover-authority` in a terminal to restore protection.",
    })
}

/// A Guard home with no approval-center locator, so the page has no link.
fn without_locator(health: &str) -> Value {
    let home = GuardHome::new(&format!("repair-{health}"));
    let mut result = authority_block();
    apply(&mut result, Some(health), &home.home, NO_HOME_DIR);
    result
}

/// A Guard home whose locator names this very process, vouched for by the
/// signed daemon state, with the auth token the link is signed with.
fn with_locator(label: &str, port: u16) -> GuardHome {
    let home = GuardHome::new(label);
    let pid = i64::from(std::process::id());
    let mut state = home.state(port);
    state.insert("pid".to_owned(), json!(pid));
    home.write_state(&state);
    write_private(&home.home.join("daemon-auth-token"), "fixture-auth-token");
    let locator = json!({
        "pid": pid,
        "daemon_url": format!("http://127.0.0.1:{port}"),
        "approval_url_base": format!("http://127.0.0.1:{port}/approvals"),
        "started_at": "2026-10-12T00:00:00+00:00",
        "state_path": home.state_path.to_str().unwrap(),
        "guard_home": home.home_text(),
    });
    std::fs::write(
        home.home.join("approval-center-locator.json"),
        locator.to_string(),
    )
    .unwrap();
    home
}

#[test]
fn a_tampered_authority_block_asks_for_a_repair() {
    for health in ["tampered", "recovery-required"] {
        let result = without_locator(health);
        assert_eq!(result["repair_status"], "approval_required", "{health}");
        assert_eq!(result["reason"], APPROVAL_REASON_WITHOUT_URL, "{health}");
        assert!(result.get("repair_url").is_none(), "{health}");
        // The verdict is untouched: this tool call stays denied, and the
        // person repairs protection from the page instead.
        assert_eq!(result["decision"], "deny", "{health}");
        assert_eq!(result["minimum_action"], "block", "{health}");
    }
}

#[test]
fn a_block_with_no_repair_page_keeps_the_terminal_command() {
    // The link is absent exactly when the approval center is not running, so
    // the page it would address cannot be opened. Naming only that page would
    // leave the person holding a blocked command and nothing that works.
    for health in ["tampered", "recovery-required"] {
        let result = without_locator(health);
        let reason = result["reason"].as_str().unwrap();
        assert!(
            reason.contains("hol-guard command controls recover-authority"),
            "{health}: {reason}"
        );
        assert!(result.get("repair_url").is_none(), "{health}");
    }
}

#[test]
fn a_degraded_authority_block_keeps_the_recover_authority_hint() {
    for health in [
        "degraded-unacknowledged",
        "degraded-acknowledged",
        "protected",
    ] {
        assert_eq!(without_locator(health), authority_block(), "{health}");
    }
}

#[test]
fn only_a_denied_authority_block_is_repaired() {
    let home = GuardHome::new("repair-gate");
    for case in [
        json!({"decision": "deny", "minimum_action": "block", "reason_code": "native_command_blocked"}),
        json!({"decision": "allow", "minimum_action": "block", "reason_code": "native_command_control_authority_block"}),
        json!({"decision": "deny", "minimum_action": "allow", "reason_code": "native_command_control_authority_block"}),
        json!({"decision": "deny", "minimum_action": "block"}),
    ] {
        let mut result = case.clone();
        apply(&mut result, Some("tampered"), &home.home, NO_HOME_DIR);
        assert_eq!(result, case);
    }
}

#[test]
fn an_unbound_snapshot_repairs_nothing() {
    let home = GuardHome::new("repair-unbound");
    let mut result = authority_block();
    apply(&mut result, None, &home.home, NO_HOME_DIR);
    assert_eq!(result, authority_block());
}

#[test]
fn a_live_locator_signs_the_repair_page_for_its_own_surface() {
    let home = with_locator("repair-signed", 4310);
    let mut result = authority_block();
    apply(&mut result, Some("tampered"), &home.home, NO_HOME_DIR);

    let url = result["repair_url"].as_str().expect("repair url");
    let (page, token) = url.split_once("#guard-token=").expect("signed fragment");
    assert_eq!(page, "http://127.0.0.1:4310/protection/repair");
    assert_eq!(
        result["reason"],
        Value::String(format!("{APPROVAL_REASON_PREFIX}{url}"))
    );
    assert_eq!(result["repair_status"], "approval_required");

    // The repair page gets its own surface, never the approval center's.
    let payload = token.split('.').nth(1).expect("token payload");
    let payload = String::from_utf8(
        Base64UrlUnpadded::decode_vec(payload).expect("base64url session payload"),
    )
    .expect("utf-8 session payload");
    assert!(
        payload.contains("\"surface\":\"protection-repair\""),
        "{payload}"
    );
}

#[test]
fn a_locator_the_state_does_not_vouch_for_is_ignored() {
    let home = with_locator("repair-unvouched", 4311);
    // The authenticated state names another daemon's port, so the locator's
    // URL is not one this Guard home published.
    let mut state = home.state(4312);
    state.insert("pid".to_owned(), json!(i64::from(std::process::id())));
    home.write_state(&state);

    let mut result = authority_block();
    apply(&mut result, Some("tampered"), &home.home, NO_HOME_DIR);
    assert_eq!(result["reason"], APPROVAL_REASON_WITHOUT_URL);
    assert!(result.get("repair_url").is_none());
}

#[test]
fn a_stopped_daemon_leaves_no_link() {
    let home = with_locator("repair-stopped", 4313);
    let locator = json!({
        // A pid no process on this host holds.
        "pid": 2_147_483_600_i64,
        "daemon_url": "http://127.0.0.1:4313",
        "approval_url_base": "http://127.0.0.1:4313/approvals",
        "started_at": "2026-10-12T00:00:00+00:00",
        "state_path": home.state_path.to_str().unwrap(),
        "guard_home": home.home_text(),
    });
    std::fs::write(
        home.home.join("approval-center-locator.json"),
        locator.to_string(),
    )
    .unwrap();

    let mut result = authority_block();
    apply(&mut result, Some("tampered"), &home.home, NO_HOME_DIR);
    assert_eq!(result["reason"], APPROVAL_REASON_WITHOUT_URL);
    assert!(result.get("repair_url").is_none());
}

#[test]
fn the_recovery_command_names_a_home_the_cli_would_not_find() {
    // The block names the home whose authority failed. Pasted into a shell
    // that points somewhere else, the bare command recovers a different
    // install and leaves this one blocked, so the home is named whenever it
    // is not the one the CLI picks by itself, quoted for that shell.
    let fixture = GuardHome::new("repair-named-home");
    let home_dir = fixture.scratch("user");
    let elsewhere = fixture.scratch("Guard Home");
    std::fs::create_dir_all(&elsewhere).unwrap();

    let mut result = authority_block();
    apply(
        &mut result,
        Some("tampered"),
        &elsewhere,
        home_dir.to_str().unwrap(),
    );

    let reason = result["reason"].as_str().unwrap();
    assert!(
        reason.contains(&format!(
            "`hol-guard command --guard-home '{}' controls recover-authority`",
            elsewhere.display()
        )),
        "{reason}"
    );
}

#[test]
fn the_default_home_is_left_out_of_the_recovery_command() {
    // `<home_dir>/.hol-guard` is where the command would land anyway, so
    // naming it would only lengthen the line a person has to trust.
    let fixture = GuardHome::new("repair-default-home");
    let home_dir = fixture.scratch("user");
    let guard_home = home_dir.join(".hol-guard");
    std::fs::create_dir_all(&guard_home).unwrap();

    let mut result = authority_block();
    apply(
        &mut result,
        Some("tampered"),
        &guard_home,
        home_dir.to_str().unwrap(),
    );

    assert_eq!(result["reason"], APPROVAL_REASON_WITHOUT_URL);
}
