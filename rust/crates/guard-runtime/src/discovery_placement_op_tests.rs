//! Shared semantic vectors for the native discovery validator. These mirror
//! the TypeScript vectors in hol-points-portal `__tests__/guard-extension-discovery.test.ts`
//! (T06) so cross-language agreement is a reviewed contract.

use super::*;

const GENERATED: &str = "2026-10-13T12:00:00.000Z";
const LEASE: &str = "2026-10-13T12:00:25.000Z";
// 2026-10-13T12:00:00.500Z in epoch milliseconds.
const NOW_MS: i64 = 1_791_892_800_500;

fn base_snapshot() -> Value {
    json!({
        "schemaVersion": DISCOVERY_SNAPSHOT_SCHEMA,
        "snapshotId": "22222222-2222-4222-8222-222222222222",
        "state": "ready",
        "enabled": true,
        "reasonCode": Value::Null,
        "generatedAt": GENERATED,
        "leaseExpiresAt": LEASE,
        "placements": [
            {
                "publicPlacementId": "11111111-1111-4111-8111-111111111111",
                "extensionId": "command.example-tool",
                "product": "sponsored",
                "slotIndex": 0,
                "windowIndex": Value::Null,
                "startsAt": GENERATED,
                "endsAt": LEASE,
                "creativeVersion": "cv-1-abc12345",
                "creative": {
                    "headline": "Explore Example Tool",
                    "body": "Review the supported extension and its permissions.",
                    "brandName": "Example Publisher"
                }
            }
        ],
        "offers": [
            {"product": "always", "availability": "open", "indicativeAmountCents": 50000, "currency": "usd", "checkedAt": GENERATED, "quoteRequired": true},
            {"product": "time_slot", "availability": "open", "indicativeAmountCents": 5000, "currency": "usd", "checkedAt": GENERATED, "quoteRequired": true},
            {"product": "sponsored", "availability": "sold_out", "indicativeAmountCents": 20000, "currency": "usd", "checkedAt": GENERATED, "quoteRequired": true}
        ]
    })
}

fn request(body: Value, now_wall_ms: i64) -> DiscoveryPlacementProjectRequest {
    DiscoveryPlacementProjectRequest {
        schema: DISCOVERY_PROJECT_REQUEST_SCHEMA.to_owned(),
        body: serde_json::to_string(&body).unwrap(),
        server_date_ms: Some(now_wall_ms),
        now_wall_ms,
        policy_allowed: true,
    }
}

fn run(request: DiscoveryPlacementProjectRequest) -> Value {
    let bytes = evaluate_discovery_placement_project(&request).expect("frame bytes");
    serde_json::from_slice(&bytes).expect("frame json")
}

fn outcome(frame: &Value) -> (&str, Option<&str>) {
    (
        frame
            .get("outcome")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        frame.get("error_code").and_then(Value::as_str),
    )
}

fn projection_body(frame: &Value) -> Value {
    frame
        .get("body")
        .and_then(Value::as_str)
        .map(|body| serde_json::from_str(body).expect("projection json"))
        .expect("projection body")
}

#[test]
fn accepts_a_ready_snapshot_and_projects_a_conservative_lease() {
    let frame = run(request(base_snapshot(), NOW_MS));
    assert_eq!(outcome(&frame), ("ok", None));
    let projection = projection_body(&frame);
    assert_eq!(projection.get("policyAllowed"), Some(&Value::Bool(true)));
    // Lease end 12:00:25 minus now 12:00:00.5.
    assert_eq!(projection.get("remainingLeaseMs"), Some(&json!(24_500)));
    assert_eq!(
        projection
            .get("snapshot")
            .and_then(|snapshot| snapshot.get("placements"))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
}

#[test]
fn accepts_a_ready_disabled_snapshot_without_placements() {
    let mut snapshot = base_snapshot();
    snapshot["enabled"] = json!(false);
    snapshot["reasonCode"] = json!("disabled");
    snapshot["placements"] = json!([]);
    let frame = run(request(snapshot, NOW_MS));
    assert_eq!(outcome(&frame), ("ok", None));
}

#[test]
fn rejects_wrong_schema_versions_and_unknown_fields() {
    let mut wrong_version = base_snapshot();
    wrong_version["schemaVersion"] = json!("guard.extensions.discovery.v2");
    assert_eq!(
        outcome(&run(request(wrong_version, NOW_MS))),
        ("error", Some("discovery_snapshot_invalid"))
    );
    let mut extra = base_snapshot();
    extra["targetUrl"] = json!("https://evil.example");
    assert_eq!(
        outcome(&run(request(extra, NOW_MS))),
        ("error", Some("discovery_snapshot_invalid"))
    );
}

#[test]
fn rejects_oversize_pools_and_duplicate_ids() {
    let mut oversize = base_snapshot();
    let mut pool = Vec::new();
    for index in 0..20 {
        pool.push(json!({
            "publicPlacementId": format!("11111111-1111-4111-8111-{}", format!("{index:012}")),
            "extensionId": format!("command.tool-{index:02}"),
            "product": "sponsored",
            "slotIndex": index % 4,
            "windowIndex": Value::Null,
            "startsAt": GENERATED,
            "endsAt": LEASE,
            "creativeVersion": "cv-1-abc12345",
            "creative": {"headline": "H", "body": "B", "brandName": "P"}
        }));
    }
    oversize["placements"] = json!(pool);
    assert_eq!(
        outcome(&run(request(oversize, NOW_MS))),
        ("error", Some("discovery_snapshot_invalid"))
    );

    let mut duplicated = base_snapshot();
    duplicated["placements"] = json!(base_snapshot()["placements"].as_array().unwrap().clone());
    let mut placements = duplicated["placements"].as_array().unwrap().clone();
    placements.push(placements[0].clone());
    duplicated["placements"] = json!(placements);
    assert_eq!(
        outcome(&run(request(duplicated, NOW_MS))),
        ("error", Some("discovery_snapshot_invalid"))
    );
}

#[test]
fn rejects_hostile_creative_and_bad_ids() {
    for hostile in [
        "<script>x</script>",
        "bad\u{0000}control",
        "rtl\u{202e}override",
        "zw\u{200b}zero-width",
        "c1\u{0085}control",
        "line\u{2028}separator",
    ] {
        let mut snapshot = base_snapshot();
        snapshot["placements"][0]["creative"]["headline"] = json!(hostile);
        assert_eq!(
            outcome(&run(request(snapshot, NOW_MS))),
            ("error", Some("discovery_snapshot_invalid"))
        );
    }
    let mut namespace = base_snapshot();
    namespace["placements"][0]["extensionId"] = json!("plugin.example-tool");
    assert_eq!(
        outcome(&run(request(namespace, NOW_MS))),
        ("error", Some("discovery_snapshot_invalid"))
    );
}

#[test]
fn rejects_leases_beyond_thirty_seconds_and_unreasonably_future_observations() {
    let mut long_lease = base_snapshot();
    long_lease["leaseExpiresAt"] = json!("2026-10-13T12:00:45.000Z");
    assert_eq!(
        outcome(&run(request(long_lease, NOW_MS))),
        ("error", Some("discovery_snapshot_invalid"))
    );

    // Observation five seconds beyond the trusted server-date anchor fails.
    let mut future = base_snapshot();
    future["generatedAt"] = json!("2026-10-13T12:00:07.000Z");
    future["leaseExpiresAt"] = json!("2026-10-13T12:00:30.000Z");
    future["placements"] = json!([]);
    assert_eq!(
        outcome(&run(request(future, NOW_MS))),
        ("error", Some("discovery_snapshot_invalid"))
    );
}

#[test]
fn time_slot_placements_must_match_the_current_utc_window() {
    // 12:00 UTC is window 6 (two-hour windows).
    let mut matching = base_snapshot();
    matching["placements"] = json!([{
        "publicPlacementId": "55555555-5555-4555-8555-555555555555",
        "extensionId": "command.window-tool",
        "product": "time_slot",
        "slotIndex": 2,
        "windowIndex": 6,
        "startsAt": GENERATED,
        "endsAt": LEASE,
        "creativeVersion": "cv-1-window01",
        "creative": {"headline": "H", "body": "B", "brandName": "P"}
    }]);
    let frame = run(request(matching.clone(), NOW_MS));
    assert_eq!(outcome(&frame), ("ok", None));

    let mut stale = matching;
    stale["placements"][0]["windowIndex"] = json!(5);
    assert_eq!(
        outcome(&run(request(stale, NOW_MS))),
        ("error", Some("discovery_snapshot_invalid"))
    );
}

#[test]
fn policy_block_empties_paid_content_and_zeroes_the_lease() {
    let body = base_snapshot();
    let mut policy_request = request(body, NOW_MS);
    policy_request.policy_allowed = false;
    let frame = run(policy_request);
    assert_eq!(outcome(&frame), ("ok", None));
    let projection = projection_body(&frame);
    assert_eq!(projection.get("policyAllowed"), Some(&Value::Bool(false)));
    assert_eq!(projection.get("remainingLeaseMs"), Some(&json!(0)));
    assert_eq!(
        projection
            .get("snapshot")
            .and_then(|snapshot| snapshot.get("placements"))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        projection
            .get("snapshot")
            .and_then(|snapshot| snapshot.get("enabled")),
        Some(&Value::Bool(false))
    );
}

#[test]
fn expired_items_are_removed_without_extending_the_lease() {
    // The placement ends at 12:00:15. The snapshot lease runs to 12:00:25.
    // Projecting at 12:00:20.5 drops the ended placement. The item end caps
    // the authority, so the remaining lease is 0 instead of the unused tail.
    let mut snapshot = base_snapshot();
    snapshot["placements"][0]["endsAt"] = json!("2026-10-13T12:00:15.000Z");
    let frame = run(request(snapshot, NOW_MS + 20_000));
    assert_eq!(outcome(&frame), ("ok", None));
    let projection = projection_body(&frame);
    assert_eq!(
        projection
            .get("snapshot")
            .and_then(|snapshot| snapshot.get("placements"))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(projection.get("remainingLeaseMs"), Some(&json!(0)));
}

#[test]
fn rejects_overdepth_and_malformed_bodies() {
    let deep: Value = serde_json::from_str("[[[[[[[[[[[[1]]]]]]]]]]]]").unwrap();
    assert_eq!(
        outcome(&run(request(deep, NOW_MS))),
        ("error", Some("discovery_body_invalid"))
    );
    let mut malformed = request(base_snapshot(), NOW_MS);
    malformed.body = "{\"not json".to_owned();
    assert_eq!(
        outcome(&run(malformed)),
        ("error", Some("discovery_body_invalid"))
    );
    let mut wrong_schema = request(base_snapshot(), NOW_MS);
    wrong_schema.schema = "guard-discovery-project-request.v2".to_owned();
    assert_eq!(
        outcome(&run(wrong_schema)),
        ("error", Some("discovery_request_invalid"))
    );
}

#[test]
fn strict_utc_parser_handles_boundaries() {
    assert_eq!(
        parse_utc_iso_ms("2026-10-13T12:00:00.000Z"),
        Some(1_791_892_800_000)
    );
    assert_eq!(
        parse_utc_iso_ms("2024-02-29T00:00:00Z"),
        Some(1_709_164_800_000)
    );
    assert_eq!(parse_utc_iso_ms("2023-02-29T00:00:00Z"), None);
    assert_eq!(parse_utc_iso_ms("2026-13-01T00:00:00.000Z"), None);
    assert_eq!(parse_utc_iso_ms("2026-10-13T24:00:00.000Z"), None);
    assert_eq!(parse_utc_iso_ms("2026-10-13T12:00:00.000+01:00"), None);
}
