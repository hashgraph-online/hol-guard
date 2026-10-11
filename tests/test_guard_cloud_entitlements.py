from codex_plugin_scanner.guard.cloud_entitlements import (
    GuardCloudEntitlements,
    parse_guard_cloud_entitlements,
)


def test_parses_full_solo_effective_entitlements_and_ignores_unknown_fields() -> None:
    parsed = parse_guard_cloud_entitlements(
        {
            "planId": "solo",
            "planVersion": "2026-08-01",
            "subscriptionStatus": "active",
            "currentPeriodEnd": "2026-09-07T00:00:00Z",
            "trialEnd": None,
            "maxSyncedDevices": 2,
            "activeSyncedDevices": 2,
            "retentionDays": 30,
            "cloudStorageBytes": 1_073_741_824,
            "cloudStorageUsedBytes": 12_345,
            "supplyChainFirewall": False,
            "features": {
                "guard.cloud.receipt_sync": True,
                "guard.cloud.history.basic": True,
                "guard.cloud.alerts.slack": False,
                "future.object": {"ignored": True},
            },
            "futureTopLevelField": "ignored",
        }
    )

    assert parsed == GuardCloudEntitlements(
        plan_id="solo",
        plan_version="2026-08-01",
        subscription_status="active",
        current_period_end="2026-09-07T00:00:00Z",
        trial_end=None,
        max_synced_devices=2,
        active_synced_devices=2,
        retention_days=30,
        cloud_storage_bytes=1_073_741_824,
        cloud_storage_used_bytes=12_345,
        features={
            "guard.cloud.receipt_sync": True,
            "guard.cloud.history.basic": True,
            "guard.cloud.alerts.slack": False,
            "guard.cloud.supply_chain_firewall": False,
        },
    )


def test_parses_compact_oauth_entitlement_without_inventing_limits() -> None:
    parsed = parse_guard_cloud_entitlements(
        {
            "access_token": "redacted",
            "guard_local_entitlement": {
                "plan_id": "solo",
                "tier": "solo",
                "expires_at": "2026-08-07T17:00:00Z",
                "supply_chain_firewall": False,
                "future_field": "ignored",
            },
        }
    )

    assert parsed is not None
    assert parsed.plan_id == "solo"
    assert parsed.max_synced_devices is None
    assert parsed.retention_days is None
    assert parsed.cloud_storage_bytes is None
    assert parsed.features == {"guard.cloud.supply_chain_firewall": False}


def test_preserves_explicit_zero_values_for_free_plan() -> None:
    parsed = parse_guard_cloud_entitlements(
        {
            "planId": "free",
            "maxSyncedDevices": 0,
            "activeSyncedDevices": 0,
            "retentionDays": 0,
            "cloudStorageBytes": 0,
            "cloudStorageUsedBytes": 0,
            "features": {},
        }
    )

    assert parsed is not None
    assert parsed.max_synced_devices == 0
    assert parsed.active_synced_devices == 0
    assert parsed.retention_days == 0
    assert parsed.cloud_storage_bytes == 0
    assert parsed.cloud_storage_used_bytes == 0


def test_legacy_storage_gb_fallback_matches_canonical_guard_binary_bytes() -> None:
    parsed = parse_guard_cloud_entitlements(
        {
            "planId": "solo",
            "includedStorageGb": 1,
        }
    )

    assert parsed is not None
    assert parsed.cloud_storage_bytes == 1_073_741_824


def test_rejects_unknown_plan_identity() -> None:
    assert parse_guard_cloud_entitlements({"planId": "starter"}) is None
    assert parse_guard_cloud_entitlements({"retentionDays": 30}) is None
