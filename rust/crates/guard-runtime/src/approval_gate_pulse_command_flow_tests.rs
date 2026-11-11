//! The command row in the YID app, end to end: what reaches Pulse for a
//! paused action, and the `pulse_show_command` opt-in. Off by default, so
//! Guards set up before it existed keep sending program names only
//! (Michael's review of #7541), and only an approval for exactly that
//! change can turn it on.

use serde_json::json;

use super::*;

/// The stored command, with a fake GitHub token built at run time so secret
/// scanners do not flag the source.
fn stored_command() -> String {
    format!(
        "rm -rf /Users/name/client-acme/build --token=ghp_{}",
        "0123456789abcdefghijABCDEFGHIJ012345"
    )
}

/// Store one paused action, as Guard's approval queue would.
fn store_request(g: &Gate) {
    let connection = rusqlite::Connection::open(g.home.join("guard.db")).unwrap();
    connection
        .execute_batch(&format!(
            "create table approval_requests (request_id text primary key, harness text, \
             artifact_type text, risk_headline text, risk_summary text, policy_action text, \
             raw_command_text text, action_envelope_json text);
             insert into approval_requests values ('r1', 'codex', 'tool_action_request', \
             'Deletes files.', null, 'require-reapproval', '{}', null);",
            stored_command()
        ))
        .unwrap();
}

/// Ask the YID app about the stored action; returns what was sent to Pulse.
fn sent_to_phone(g: &Gate) -> String {
    let created = g.send(
        "pulse_request",
        NOW,
        json!({"purpose": "approval_decision",
               "params": {"action": "allow", "scope": "artifact", "subject": "approval-request:r1"}}),
    );
    assert_eq!(created["payload"]["status"], "pending", "{created}");
    g.fake.created.borrow().values().last().unwrap().to_string()
}

fn show_command(show: Value) -> Value {
    json!({"approval_gate": {"pulse_show_command": show}})
}

/// A settings-save grant for `settings`, approved in the YID app.
fn save_grant(g: &Gate, settings: &Value) -> Value {
    let binding = json!({"settings_change": {"kind": "save", "settings": settings}});
    let created = g.send(
        "pulse_request",
        NOW,
        json!({"purpose": "settings_write", "strict": true, "params": binding}),
    );
    let id = created["payload"]["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(g.poll(&id)["payload"]["status"], "approved");
    let verified = g.send(
        "verify",
        LATER,
        json!({"purpose": "settings_write", "strict": true, "params": binding,
               "approval_gate_input": {"pulse_request_id": id}}),
    );
    assert_eq!(verified["status"], "ok", "{verified}");
    verified["payload"]["grant"].clone()
}

fn set_show_command(g: &Gate, show: bool) -> Value {
    let settings = show_command(json!(show));
    let grant = save_grant(g, &settings);
    g.send(
        "update_settings",
        LATER,
        json!({"params": settings["approval_gate"], "approval_gate_grant": grant}),
    )
}

#[test]
fn by_default_the_phone_sees_only_the_program_name() {
    let (g, _) = pulse_gate("command-default", 0);
    store_request(&g);
    let cfg = g.send("public_config", NOW, json!({}));
    assert_eq!(cfg["payload"]["pulse_show_command"], false, "{cfg}");
    assert!(load_state(&g.home).get("pulse_show_command").is_none());
    let sent = sent_to_phone(&g);
    assert!(!sent.contains("\"Command\""), "{sent}");
    for hidden in ["client-acme", "-rf", "/Users", "ghp_0123456789"] {
        assert!(!sent.contains(hidden), "leaked {hidden}: {sent}");
    }
    assert!(sent.contains("\"rm\""), "the program name shows: {sent}");
}

#[test]
fn after_opting_in_the_phone_sees_the_command_with_secrets_and_user_folders_hidden() {
    let (g, _) = pulse_gate("command-shown", 0);
    store_request(&g);
    let on = set_show_command(&g, true);
    assert_eq!(on["status"], "ok", "{on}");
    assert_eq!(on["payload"]["pulse_show_command"], true, "{on}");
    let sent = sent_to_phone(&g);
    for shown in [
        "\"Command\"",
        "rm -rf ~/client-acme/build",
        "Codex",
        "Deletes files.",
    ] {
        assert!(sent.contains(shown), "missing {shown}: {sent}");
    }
    for hidden in ["/Users", "name/", "ghp_0123456789"] {
        assert!(!sent.contains(hidden), "leaked {hidden}: {sent}");
    }

    let off = set_show_command(&g, false);
    assert_eq!(off["payload"]["pulse_show_command"], false, "{off}");
    assert!(!sent_to_phone(&g).contains("client-acme"));
}

#[test]
fn opting_in_needs_an_approval_for_exactly_that_change() {
    let (g, _) = pulse_gate("command-binding", 0);
    store_request(&g);
    let enable = json!({"pulse_show_command": true});
    let unapproved = g.send("update_settings", LATER, json!({"params": enable}));
    assert_ne!(unapproved["status"], "ok", "{unapproved}");

    // A valid grant for another settings save cannot turn sharing on.
    let other = save_grant(
        &g,
        &json!({"approval_gate": {"pulse_cooldown_seconds": 900}}),
    );
    let swapped = g.send(
        "update_settings",
        LATER,
        json!({"params": enable, "approval_gate_grant": other}),
    );
    assert_ne!(swapped["status"], "ok", "{swapped}");
    // Nor can an approval to turn it off be used to turn it on.
    let off_grant = save_grant(&g, &show_command(json!(false)));
    let flipped = g.send(
        "update_settings",
        LATER,
        json!({"params": enable, "approval_gate_grant": off_grant}),
    );
    assert_ne!(flipped["status"], "ok", "{flipped}");
    // Nor can an extra field ride along with an approved opt-in.
    let on_grant = save_grant(&g, &show_command(json!(true)));
    let widened = g.send(
        "update_settings",
        LATER,
        json!({"params": {"pulse_show_command": true, "strict_all_decisions": true},
               "approval_gate_grant": on_grant}),
    );
    assert_ne!(widened["status"], "ok", "{widened}");

    assert_eq!(
        g.send("public_config", NOW, json!({}))["payload"]["pulse_show_command"],
        false
    );
    assert!(!sent_to_phone(&g).contains("client-acme"));
}

#[test]
fn the_switch_is_a_plain_true_or_false() {
    let home = home("command-invalid");
    let bad = send_from(
        &home,
        "sid=tty-1",
        "validate_settings_update",
        NOW,
        json!({"params": {"pulse_show_command": "no"}}),
    );
    assert_eq!(
        code(&bad),
        "approval_gate_invalid_pulse_show_command",
        "{bad}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn without_pulse_false_changes_nothing_and_true_is_refused() {
    // As for the Pulse cooldown: the public config reports the default while
    // Pulse is off, so a settings save or import sends it back unchanged.
    let home = home("command-no-pulse");
    let cfg = send_from(&home, "sid=tty-1", "public_config", NOW, json!({}));
    assert_eq!(cfg["payload"]["pulse_show_command"], false, "{cfg}");
    let validate = |show: bool| {
        send_from(
            &home,
            "sid=tty-1",
            "validate_settings_update",
            NOW,
            json!({"params": {"cooldown_seconds": 0, "pulse_show_command": show}}),
        )
    };
    let kept = validate(false);
    assert_eq!(kept["status"], "ok", "{kept}");
    let on = validate(true);
    assert_eq!(code(&on), "approval_gate_pulse_not_enabled", "{on}");
    let _ = std::fs::remove_dir_all(&home);
}
