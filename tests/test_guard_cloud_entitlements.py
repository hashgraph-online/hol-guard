from codex_plugin_scanner.guard.cloud_entitlements import (
    GuardCloudEntitlements,
    guard_cloud_history_copy,
    guard_cloud_status_copy,
    is_known_guard_plan_error_code,
    parse_guard_cloud_entitlements,
    parse_guard_cloud_plan_error,
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
    assert guard_cloud_history_copy(parsed) == "30-day Cloud history"


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
    assert guard_cloud_history_copy(parsed) == "Cloud history is not included on this plan."


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


def test_normalizes_device_limit_without_affecting_local_protection() -> None:
    error = parse_guard_cloud_plan_error(
        {
            "error": {
                "code": "device_limit_reached",
                "message": "Solo includes two cloud-connected devices.",
                "planId": "solo",
                "limit": 2,
                "current": 2,
                "upgradePlanId": "pro",
                "manageUrl": "/guard/settings/devices",
                "upgradeUrl": "/guard/pricing?from=device_limit",
            }
        },
        http_status=409,
    )

    assert error is not None
    assert error.category == "plan_limit"
    assert error.plan_id == "solo"
    assert error.limit == 2
    assert error.current == 2
    assert error.upgrade_plan_id == "pro"
    assert error.local_protection_affected is False
    assert error.manage_url == "/guard/settings/devices"
    assert "still protected" in guard_cloud_status_copy(error)
    assert "Solo includes Cloud sync for two devices" in guard_cloud_status_copy(error)
    assert "upgrade to Pro" in guard_cloud_status_copy(error)
    assert "$" not in guard_cloud_status_copy(error)


def test_device_limit_copy_does_not_mislabel_other_plans_as_solo() -> None:
    error = parse_guard_cloud_plan_error(
        {
            "error": {
                "code": "device_limit_reached",
                "message": "Device limit reached.",
                "planId": "team",
                "limit": 25,
                "current": 25,
                "upgradePlanId": "enterprise",
            }
        },
        http_status=409,
    )

    assert error is not None
    copy = guard_cloud_status_copy(error)
    assert "still protected" in copy
    assert "25 devices" in copy
    assert "upgrade to Enterprise" in copy
    assert "Solo" not in copy


def test_normalizes_billing_trial_paused_and_outage_separately() -> None:
    past_due = parse_guard_cloud_plan_error(
        {"error": {"code": "subscription_past_due", "message": "Payment required."}},
        http_status=402,
    )
    expired = parse_guard_cloud_plan_error(
        {"error": {"code": "trial_expired", "message": "Trial ended."}},
        http_status=403,
    )
    paused = parse_guard_cloud_plan_error(
        {"error": {"code": "cloud_sync_paused_plan_limit", "message": "Sync paused."}},
        http_status=409,
    )
    outage = parse_guard_cloud_plan_error({}, http_status=503)

    assert past_due is not None and past_due.category == "billing"
    assert expired is not None and expired.category == "trial"
    assert paused is not None and paused.category == "sync_paused"
    assert outage is not None and outage.category == "cloud_error"
    assert all(
        error.local_protection_affected is False
        for error in (past_due, expired, paused, outage)
    )
    assert "Local protection" in guard_cloud_status_copy(past_due)
    assert "Local protection" in guard_cloud_status_copy(expired)
    assert "Local protection" in guard_cloud_status_copy(paused)
    assert "Local protection" in guard_cloud_status_copy(outage)


def test_rejects_untrusted_action_urls_and_nonstandard_origins() -> None:
    for manage_url, upgrade_url in (
        ("https://evil.example/manage", "//evil.example/upgrade"),
        ("/\\evil.example/manage", "/guard/pricing\\@evil.example"),
        ("https://hol.org:8443/manage", "https://www.hol.org:8080/upgrade"),
        ("https://user@hol.org/manage", "https://user:pass@www.hol.org/upgrade"),
    ):
        error = parse_guard_cloud_plan_error(
            {
                "error": {
                    "code": "feature_not_in_plan",
                    "manageUrl": manage_url,
                    "upgradeUrl": upgrade_url,
                }
            },
            http_status=403,
        )

        assert error is not None
        assert error.manage_url is None
        assert error.upgrade_url is None


def test_accepts_relative_and_standard_https_hol_action_urls() -> None:
    error = parse_guard_cloud_plan_error(
        {
            "error": {
                "code": "device_limit_reached",
                "manageUrl": "/guard/settings/devices",
                "upgradeUrl": "https://hol.org/guard/pricing?from=device_limit",
            }
        },
        http_status=409,
    )

    assert error is not None
    assert error.manage_url == "/guard/settings/devices"
    assert error.upgrade_url == "https://hol.org/guard/pricing?from=device_limit"


def test_known_plan_error_registry_is_explicit() -> None:
    for code in (
        "feature_not_in_plan",
        "device_limit_reached",
        "retention_limit_reached",
        "storage_limit_reached",
        "subscription_past_due",
        "trial_expired",
        "cloud_sync_paused_plan_limit",
    ):
        assert is_known_guard_plan_error_code(code)
    assert not is_known_guard_plan_error_code("generic_403")
