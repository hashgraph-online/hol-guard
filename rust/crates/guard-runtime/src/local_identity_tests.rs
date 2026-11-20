use serde_json::{json, Value};

use super::{dispatch, identity, source, Probe};

fn probe(hostname: Option<&str>, ipv4: Option<&str>, ipv6: Option<&str>) -> Probe {
    Probe {
        hostname: hostname.map(str::to_owned),
        ipv4: ipv4.map(str::to_owned),
        ipv6: ipv6.map(str::to_owned),
    }
}

#[test]
fn the_ipv4_address_is_reported_before_ipv6() {
    let found = identity(
        "2026-11-20T10:00:00+00:00",
        &probe(Some("builder"), Some("10.0.0.5"), Some("fd00::42")),
    );
    assert_eq!(
        Value::Object(found),
        json!({
            "lastSyncedAt": "2026-11-20T10:00:00+00:00",
            "hostname": "builder",
            "ipAddress": "10.0.0.5",
            "privateIpAddress": "10.0.0.5",
        })
    );
}

#[test]
fn ipv6_stands_in_when_no_ipv4_address_was_found() {
    let found = identity("t", &probe(None, None, Some("fd00::42")));
    assert_eq!(found.get("ipAddress"), Some(&json!("fd00::42")));
    assert_eq!(found.get("privateIpAddress"), Some(&json!("fd00::42")));
    assert!(!found.contains_key("hostname"));
}

#[test]
fn an_empty_probe_reports_only_the_sync_time() {
    let found = identity("t", &Probe::default());
    assert_eq!(Value::Object(found), json!({"lastSyncedAt": "t"}));
}

#[test]
fn the_source_names_local_guard_for_each_reported_field() {
    let found = identity("t", &probe(Some("builder"), Some("10.0.0.5"), None));
    assert_eq!(
        Value::Object(source(&found)),
        json!({
            "daemonId": "local-guard",
            "daemonVersion": "local-guard",
            "daemonStatus": "local-guard",
            "relayState": "local-guard",
            "hostname": "local-guard",
            "ipAddress": "local-guard",
            "privateIpAddress": "local-guard",
        })
    );
    let bare = source(&identity("t", &Probe::default()));
    assert!(!bare.contains_key("hostname"));
    assert!(!bare.contains_key("ipAddress"));
}

#[test]
fn the_live_answer_has_the_sync_time_and_matching_source() {
    let answer = dispatch(&json!({"observed_at": "2026-11-20T10:00:00+00:00"})).expect("answer");
    assert_eq!(
        answer["identity"]["lastSyncedAt"],
        json!("2026-11-20T10:00:00+00:00")
    );
    for key in ["hostname", "ipAddress", "privateIpAddress"] {
        assert_eq!(
            answer["identity"].get(key).is_some(),
            answer["source"].get(key).is_some()
        );
    }
    assert_ne!(answer["identity"]["ipAddress"], json!("127.0.0.1"));
}

#[test]
fn malformed_requests_are_refused() {
    assert!(dispatch(&json!({})).is_err());
    assert!(dispatch(&json!({"observed_at": 5})).is_err());
    assert!(dispatch(&json!({"observed_at": "t", "probe": {}})).is_err());
}
