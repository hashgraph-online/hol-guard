use serde_json::json;

use super::*;

fn bound(params: Value) -> Value {
    bind(Path::new("/nonexistent-guard-home"), true, Some(&params))
        .unwrap_or_else(|e| panic!("{params} was refused: {}", e.message))
        .unwrap_or_else(|| panic!("{params} named no settings change"))
}

fn refused(settings_scoped: bool, params: Value) -> String {
    match bind(
        Path::new("/nonexistent-guard-home"),
        settings_scoped,
        Some(&params),
    ) {
        Err(e) => e.code,
        Ok(bound) => panic!("{params} was bound as {bound:?}"),
    }
}

#[test]
fn each_settings_change_is_bound_to_its_own_operation() {
    let channel =
        bound(json!({"settings_change": {"kind": "update_channel", "update_channel": "stable"}}));
    assert_eq!(channel["action"], UPDATE_CHANNEL_ACTION);
    assert_eq!(channel["subject"], "update_channel:\"stable\"");
    let reset = bound(json!({"settings_change": {"kind": "reset"}}));
    assert_eq!(reset["action"], SETTINGS_RESET_ACTION);
    assert_eq!(reset["subject"], SETTINGS_RESET_ACTION);
    let disable = bound(json!({"settings_change": {"kind": "pulse_disable"}}));
    assert_eq!(disable["action"], PULSE_DISABLE_ACTION);
    assert_eq!(disable["subject"], PULSE_DISABLE_SUBJECT);
    assert!(
        disable.get(SETTINGS_CHANGE_PARAM).is_none(),
        "the change itself is not passed on"
    );
}

#[test]
fn the_other_params_are_kept() {
    let r = bound(json!({"settings_change": {"kind": "reset"}, "session_nonce": "n-1"}));
    assert_eq!(r["session_nonce"], "n-1");
}

#[test]
fn a_save_is_bound_to_its_settings_but_not_to_how_it_is_approved() {
    let change = json!({"approval_gate": {"new_password": "p"}, "mode": "enforce"});
    let with_proof = json!({
        "approval_gate": {"new_password": "p", "current_password": "c", "totp_code": "1", "pulse_request_id": "r"},
        "mode": "enforce",
    });
    let save = |settings: &Value| {
        bound(json!({"settings_change": {"kind": "save", "settings": settings}}))["subject"].clone()
    };
    let subject = save(&change);
    assert_eq!(subject, save(&with_proof));
    assert_ne!(
        subject,
        save(&json!({"approval_gate": {"new_password": "other"}, "mode": "enforce"}))
    );
    assert!(subject.as_str().is_some_and(|s| s.starts_with("settings:")));
    assert!(
        !subject.to_string().contains("\"p\""),
        "the change is not readable"
    );
}

#[test]
fn the_save_digest_depends_on_its_key() {
    assert_ne!(keyed_digest(b"k", "{}"), keyed_digest(b"another key", "{}"));
}

#[test]
fn a_settings_change_may_not_also_name_its_binding() {
    for extra in [
        json!({"action": "pulse_disable"}),
        json!({"subject": "approval-gate:pulse"}),
    ] {
        let mut params = extra.clone();
        params[SETTINGS_CHANGE_PARAM] = json!({"kind": "reset"});
        assert_eq!(
            refused(true, params),
            "approval_gate_settings_change_invalid"
        );
    }
}

#[test]
fn only_a_settings_write_names_a_settings_change() {
    assert_eq!(
        refused(false, json!({"settings_change": {"kind": "reset"}})),
        "approval_gate_settings_change_invalid"
    );
}

#[test]
fn an_unknown_or_incomplete_change_is_refused() {
    for change in [
        json!({"kind": "something"}),
        json!({"kind": "save"}),
        json!({"kind": "update_channel"}),
        json!("reset"),
    ] {
        assert_eq!(
            refused(true, json!({"settings_change": change})),
            "approval_gate_settings_change_invalid"
        );
    }
}

#[test]
fn params_without_a_settings_change_are_left_alone() {
    let params = json!({"action": "x", "subject": "s-1"});
    assert!(
        bind(Path::new("/nonexistent-guard-home"), true, Some(&params))
            .ok()
            .flatten()
            .is_none()
    );
}
