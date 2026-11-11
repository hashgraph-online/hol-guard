use super::*;

#[test]
fn network_status_reports_no_protection_without_a_backend() {
    let (status, body) = status().unwrap();
    assert_eq!(status, 200);
    assert_eq!(body["schema"], "guard.network-status.v1");
    assert_eq!(body["protection_active"], false);
    assert_eq!(body["effective_grade"], "unavailable");
    assert_eq!(body["backends"].as_array().unwrap().len(), 4);
}

fn config(fingerprint: Option<&str>) -> ReadConfig {
    let mut handshake = json!({
        "schema": super::super::HANDSHAKE_SCHEMA,
        "auth_token": "network-test-value",
        "guard_home": "/tmp/guard-home",
        "store_path": "/tmp/guard-home/guard.db",
        "source": "default",
        "busy_timeout_ms": 2000,
    });
    if let Some(fingerprint) = fingerprint {
        handshake["daemon_fingerprint"] = json!(fingerprint);
    }
    ReadConfig::from_line(&serde_json::to_vec(&handshake).unwrap()).unwrap()
}

#[test]
fn containment_health_without_a_daemon_fingerprint_is_left_to_the_daemon() {
    assert!(containment_health(&config(None)).is_none());
    assert!(containment_health(&config(Some("not-a-digest"))).is_none());
    assert!(containment_health(&config(Some(&"A".repeat(64)))).is_none());
}
