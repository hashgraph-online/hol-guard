"""The posture bridge only hydrates facts and fails closed on any bad native reply."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_supply_chain_posture as bridge

_REPLY = {
    "status": "synced",
    "health_status": "protected",
    "detail": "ready",
    "connection": {},
    "bundle": {},
    "policy": {},
    "supported_ecosystems": [],
    "package_manager_protection": {},
}


class _Store:
    guard_home = Path("/tmp/guard-home-posture")

    def get_cloud_workspace_id(self) -> str | None:
        return "ws-1"

    def get_cloud_sync_profile(self) -> dict[str, object]:
        return {"profile": 1}

    def get_sync_payload(self, name: str) -> object:
        return {"supply_chain_bundle_summary": {"status": "synced"}}.get(name)

    def get_cached_supply_chain_bundle(self, _workspace_id: str) -> dict[str, object]:
        return {"bundle": {"bundleVersion": "b1"}}


def _call(
    monkeypatch: pytest.MonkeyPatch, reply: dict[str, object]
) -> tuple[dict[str, object], list[dict[str, object]]]:
    seen: list[dict[str, object]] = []

    def transport(request: dict[str, object], *_args: object, **_kwargs: object) -> dict[str, object]:
        seen.append(dict(request))
        return reply

    monkeypatch.setattr(bridge, "_transport", transport)
    monkeypatch.setattr("codex_plugin_scanner.guard.synced_policy.synced_policy_payload", lambda _store: None)
    config = SimpleNamespace(security_level="balanced")
    monkeypatch.setattr(bridge, "resolve_risk_action", lambda _config, risk, harness=None: f"{risk}-action")
    posture = bridge.native_local_supply_chain_posture(
        _Store(),
        config,  # type: ignore[arg-type]
        now="2026-06-01T12:00:00Z",
        package_manager_protection={"managed": True},
    )
    return posture, seen


def test_hydrates_store_facts_and_returns_the_native_posture(monkeypatch: pytest.MonkeyPatch) -> None:
    posture, seen = _call(monkeypatch, dict(_REPLY))
    assert posture == _REPLY
    request = seen[0]
    assert request["credentials_present"] is True
    assert request["workspace_id"] == "ws-1"
    assert request["summary"] == {"status": "synced"}
    assert request["entitlement"] == {}
    assert request["remote_policy"] == {}
    assert request["bundle_payload"] == {"bundleVersion": "b1"}
    assert request["config_cloud_advisory_action"] == "cloud_advisory-action"
    assert request["config_package_script_action"] == "package_script-action"
    assert request["package_manager_protection"] == {"managed": True}


@pytest.mark.parametrize(
    ("cached", "projected"),
    [
        (
            {"bundleVersion": "b1", "tier": "pro", "advisories": [{"id": "a"}] * 3, "packages": [{"n": "p"}]},
            {"bundleVersion": "b1", "tier": "pro"},
        ),
        ({"advisories": [{"id": "a"}]}, {"expiresAt": None}),
        ({}, {}),
    ],
)
def test_only_bundle_identity_fields_are_sent(
    monkeypatch: pytest.MonkeyPatch, cached: dict[str, object], projected: dict[str, object]
) -> None:
    monkeypatch.setattr(_Store, "get_cached_supply_chain_bundle", lambda _self, _workspace_id: {"bundle": cached})
    _posture, seen = _call(monkeypatch, dict(_REPLY))
    assert seen[0]["bundle_payload"] == projected


@pytest.mark.parametrize(
    "reply",
    [
        {key: value for key, value in _REPLY.items() if key != "detail"},
        {**_REPLY, "extra": 1},
        {**_REPLY, "status": 5},
        {**_REPLY, "health_status": None},
    ],
)
def test_malformed_reply_fails_closed(monkeypatch: pytest.MonkeyPatch, reply: dict[str, object]) -> None:
    with pytest.raises(bridge.NativePackagePostureError):
        _call(monkeypatch, reply)
