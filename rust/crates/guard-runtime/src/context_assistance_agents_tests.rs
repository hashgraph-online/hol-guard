use super::*;

fn credential(value: &Value) -> Credential {
    Credential(value["credential"].as_str().unwrap().into())
}

#[test]
fn public_code_does_not_authenticate_and_approval_does_not_reveal_the_private_credential() {
    let now = Instant::now();
    let mut sessions = Sessions::default();
    let begun = sessions.begin(now).unwrap();
    let secret = credential(&begun);
    let id = begun["session_id"].as_str().unwrap();
    assert!(matches!(
        sessions.authenticate(&Credential(id.into()), now),
        Err(RuntimeError::ScopeDenied)
    ));
    assert!(sessions.authenticate(&secret, now).unwrap().1.is_none());
    sessions.authorize(id, "scope:codex", now).unwrap();
    assert_eq!(
        sessions.authenticate(&secret, now).unwrap().1.as_deref(),
        Some("scope:codex")
    );
    assert!(
        matches!(
            sessions.authorize(id, "scope:claude", now),
            Err(RuntimeError::ScopeDenied)
        ),
        "an existing session cannot be retargeted"
    );
    let public = sessions.metadata(now).to_string();
    assert!(!public.contains(begun["credential"].as_str().unwrap()));
    assert!(!format!("{secret:?}").contains(begun["credential"].as_str().unwrap()));
}

#[test]
fn finite_leases_revocation_capacity_and_restart_have_no_restored_authority() {
    let now = Instant::now();
    let mut sessions = Sessions::default();
    let first = sessions.begin(now).unwrap();
    let secret = credential(&first);
    let id = first["session_id"].as_str().unwrap();
    assert!(sessions.authenticate(&secret, now + PENDING_TTL).is_err());
    assert!(sessions
        .authorize(id, "scope:one", now + PENDING_TTL)
        .is_err());
    sessions.authorize(id, "scope:one", now).unwrap();
    assert!(sessions.authenticate(&secret, now + ACTIVE_TTL).is_err());
    for _ in 1..CAPACITY {
        sessions.begin(now).unwrap();
    }
    assert!(matches!(
        sessions.begin(now),
        Err(RuntimeError::ResourceLimit)
    ));
    sessions.revoke(id).unwrap();
    assert!(sessions.authenticate(&secret, now).is_err());
    sessions.begin(now).unwrap();
    assert!(
        sessions.begin(now + ACTIVE_TTL).is_ok(),
        "expired pending sessions do not accumulate"
    );
    assert!(Sessions::default().authenticate(&secret, now).is_err());
}

#[test]
fn agent_inputs_cannot_select_app_workspace_source_scope_or_interpreter() {
    for extra in ["app", "workspace", "scope_id", "sources", "python_version"] {
        let mut input =
            json!({"action":"compile","credential":"a".repeat(64),"arguments":{"query":"context"}});
        input[extra] = json!("forged");
        assert!(crate::strict_json::from_value::<Input>(input).is_err());
        let mut input =
            json!({"action":"compile","credential":"a".repeat(64),"arguments":{"query":"context"}});
        input["arguments"][extra] = json!("forged");
        assert!(crate::strict_json::from_value::<Input>(input).is_err());
    }
    assert!(
        crate::strict_json::from_value::<Input>(json!({"action":"begin","app":"codex"})).is_err()
    );
}

#[test]
fn one_session_per_scope_and_per_session_snapshots_prevent_implicit_sharing() {
    let now = Instant::now();
    let mut sessions = Sessions::default();
    let first = sessions.begin(now).unwrap();
    let second = sessions.begin(now).unwrap();
    let a = first["session_id"].as_str().unwrap();
    let b = second["session_id"].as_str().unwrap();
    sessions.authorize(a, "scope:one", now).unwrap();
    assert!(sessions.authorize(b, "scope:one", now).is_err());
    sessions.retain_snapshot(a, "a".repeat(64)).unwrap();
    assert!(sessions.require_snapshot(a, &"a".repeat(64)).is_ok());
    assert!(sessions.require_snapshot(b, &"a".repeat(64)).is_err());
    assert!(sessions.require_live(a, now + ACTIVE_TTL).is_err());
    sessions.revoke(a).unwrap();
    sessions.authorize(b, "scope:one", now).unwrap();
    assert!(sessions.require_snapshot(b, &"a".repeat(64)).is_err());
}

#[test]
fn explicit_shared_sessions_keep_independent_snapshots_and_short_finite_leases() {
    let now = Instant::now();
    let mut sessions = Sessions::default();
    let first = sessions.begin(now).unwrap();
    let second = sessions.begin(now).unwrap();
    let a = first["session_id"].as_str().unwrap();
    let b = second["session_id"].as_str().unwrap();
    sessions
        .authorize_mode(a, "scope:shared", now, true)
        .unwrap();
    sessions
        .authorize_mode(b, "scope:shared", now, true)
        .unwrap();
    sessions.retain_snapshot(a, "a".repeat(64)).unwrap();
    assert!(sessions.require_snapshot(b, &"a".repeat(64)).is_err());
    assert!(sessions
        .authenticate(&credential(&first), now + PENDING_TTL)
        .is_err());
    assert!(sessions.sweep(now + PENDING_TTL).is_empty());
    assert!(sessions.require_live(a, now + PENDING_TTL).is_err());
}
