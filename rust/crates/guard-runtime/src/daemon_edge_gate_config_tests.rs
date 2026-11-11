use super::super::super::HANDSHAKE_SCHEMA;
use super::*;
use serde_json::json;

fn config_without_session() -> ReadConfig {
    let handshake = json!({
        "schema": HANDSHAKE_SCHEMA,
        "auth_token": "gate-test-value",
        "guard_home": "/nonexistent-guard-home",
        "store_path": "/nonexistent-guard-home/guard.db",
        "source": "default",
        "busy_timeout_ms": 2000,
    });
    ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap()
}

#[test]
fn routes_parse_only_as_posts() {
    assert_eq!(
        Route::parse("POST", "/v1/approval-gate/cooldown/revoke"),
        Some(Route::RevokeCooldown)
    );
    assert_eq!(
        Route::parse("POST", "/v1/approval-gate/totp/enroll"),
        Some(Route::Enroll)
    );
    assert_eq!(
        Route::parse("POST", "/v1/approval-gate/totp/verify"),
        Some(Route::Verify)
    );
    assert_eq!(
        Route::parse("POST", "/v1/approval-gate/totp/disable"),
        Some(Route::Disable)
    );
    assert_eq!(Route::parse("GET", "/v1/approval-gate/totp/enroll"), None);
    assert_eq!(Route::parse("POST", "/v1/approval-gate/totp"), None);
}

#[test]
fn public_config_reads_like_config_from_wire() {
    let answer = serde_json::json!({
        "enabled": true,
        "configured": true,
        "cooldown_seconds": 300,
        "cooldown_active": false,
        "fail_closed": true,
        "strict_all_decisions": false,
        "totp_enabled": true,
        "totp_pending": false,
    });
    let Value::Object(answer) = answer else {
        unreachable!()
    };
    let config = gate::public_config(&answer).expect("config");
    assert_eq!(config["cooldown_expires_at"], Value::Null);
    assert_eq!(config["totp_recent_satisfied"], Value::Bool(false));
    assert_eq!(config["cooldown_seconds"], 300);
    let mut missing = answer.clone();
    missing.remove("totp_pending");
    assert_eq!(gate::public_config(&missing), None);
}

#[test]
fn no_session_goes_to_the_daemon() {
    let config = config_without_session();
    assert_eq!(respond(&Route::Verify, &Map::new(), &config), None);
}
