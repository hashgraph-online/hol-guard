"""policy status names the devices Cloud left out of a rollout."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_delivery_status import format_policy_status, policy_status_payload
from codex_plugin_scanner.guard.store import GuardStore


def test_status_names_the_inactive_devices_cloud_left_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.policy_delivery_status import fetch_policy_delivery
    from codex_plugin_scanner.guard.runtime import runner

    store = GuardStore(tmp_path / "home")
    response = {
        "versionNumber": 1,
        "devices": [{"id": "a", "name": "laptop", "state": "applied", "reason": None}],
        "deviceCount": 1,
        "stateCounts": {"applied": 1, "pending": 0, "rejected": 0},
        "inactiveDeviceCount": 19,
    }
    monkeypatch.setattr(
        runner,
        "_resolve_guard_sync_auth_context",
        lambda _store: {"sync_url": "https://hol.example/api/guard/receipts/sync"},
    )
    monkeypatch.setattr(runner, "_guard_sync_request", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", lambda **_kwargs: response)

    delivery = fetch_policy_delivery(store)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.policy_delivery_status.fetch_policy_delivery", lambda _store: delivery
    )
    text = format_policy_status(policy_status_payload(store, offline=False))

    assert "Cloud version 1: 1 applied, 0 pending, 0 rejected (19 inactive devices not counted)" in text

    response["inactiveDeviceCount"] = 1
    delivery = fetch_policy_delivery(store)
    assert "(1 inactive device not counted)" in format_policy_status(policy_status_payload(store, offline=False))

    del response["inactiveDeviceCount"]
    delivery = fetch_policy_delivery(store)
    assert "not counted" not in format_policy_status(policy_status_payload(store, offline=False))
