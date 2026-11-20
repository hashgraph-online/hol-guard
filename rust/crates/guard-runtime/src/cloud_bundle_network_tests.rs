use serde_json::json;

use super::network_status;

const DAY: i64 = 24 * 60 * 60;

#[test]
fn nothing_saved_is_not_configured() {
    assert_eq!(
        network_status(&json!({}), 0.0),
        json!({"configured": false})
    );
    assert_eq!(
        network_status(&json!({"bundle": "x"}), 0.0),
        json!({"configured": false})
    );
}

#[test]
fn a_saved_bundle_is_counted() {
    let saved = json!({
        "expiresAtEpoch": 1_000,
        "bundle": {
            "bundleVersion": "v3",
            "generatedAt": "2026-01-01T00:00:00Z",
            "expiresAt": "2026-01-02T00:00:00Z",
            "workspaceRules": [
                {"action": "block"}, {"action": "block"}, {"action": "allow"}, {"action": "log"}
            ],
            "threatUrls": {"feed-a": ["a", "b"], "feed-b": ["c"], "feed-c": "bad"},
            "threatHosts": {"feed-a": ["h"]},
        },
    });
    let status = network_status(&saved, 1_000.0 + (7 * DAY) as f64);
    assert_eq!(status["configured"], json!(true));
    assert_eq!(status["bundle_version"], json!("v3"));
    assert_eq!(status["block_rules"], json!(2));
    assert_eq!(status["allow_rules"], json!(1));
    assert_eq!(status["known_bad_urls"], json!(3));
    assert_eq!(status["known_bad_hosts"], json!(1));
    assert_eq!(status["indicators_applied"], json!(true));
}

#[test]
fn indicators_lapse_a_week_after_expiry() {
    let saved = json!({"expiresAtEpoch": 1_000, "bundle": {}});
    let lapsed = network_status(&saved, 1_001.0 + (7 * DAY) as f64);
    assert_eq!(lapsed["indicators_applied"], json!(false));
    let float = json!({"expiresAtEpoch": 1_000.0, "bundle": {}});
    assert_eq!(
        network_status(&float, 0.0)["indicators_applied"],
        json!(false)
    );
    assert_eq!(lapsed["generated_at"], json!(null));
}
