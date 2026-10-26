"""The package-firewall entitlement is decided by the resident, not here."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import package_firewall_entitlement as entitlement_module
from codex_plugin_scanner.guard.native_hook_artifact_compose import NativeHookComposeError


class _Store:
    """A store that answers the rows the resolution reads, and nothing else."""

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = str(guard_home)

    def get_sync_payload(self, key: str) -> dict[str, object] | None:
        return {"supply_chain_plan_id": "pro"} if key == "oauth_local_credentials" else None

    def get_oauth_local_credential_health(self) -> dict[str, object]:
        return {"status": "healthy"}

    def get_effective_guard_connect_state(self, *, now: str) -> dict[str, object]:
        return {"state": "connected", "observed_at": now}

    def get_cloud_sync_profile(self) -> dict[str, object]:
        return {"workspace_id": "workspace-1"}


def _resolve(store: _Store, monkeypatch: pytest.MonkeyPatch, compose: object) -> dict[str, object]:
    monkeypatch.setattr(entitlement_module, "native_hook_compose", compose)
    return entitlement_module.resolve_package_firewall_entitlement(
        cast(Any, store),
        now=datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc),
    )


def test_the_stored_rows_travel_to_the_resident_unjudged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: dict[str, object] = {}

    def _compose(kind: str, fields: dict[str, object], *, guard_home: Path) -> dict[str, object]:
        sent.update({"kind": kind, "guard_home": guard_home, **fields})
        return {"allowed": True, "reason": "paid_oauth_entitlement_active", "tier": "pro", "upgrade_cta": None}

    answer = _resolve(_Store(tmp_path), monkeypatch, _compose)

    assert answer == {
        "allowed": True,
        "reason": "paid_oauth_entitlement_active",
        "tier": "pro",
        "upgrade_cta": None,
    }
    assert sent["kind"] == "package_firewall_entitlement"
    assert sent["guard_home"] == tmp_path
    assert sent["now"] == "2026-10-20T12:00:00+00:00"
    assert sent["oauth_payload"] == {"supply_chain_plan_id": "pro"}
    assert sent["oauth_health"] == {"status": "healthy"}
    assert sent["connect_state"] == {"state": "connected", "observed_at": "2026-10-20T12:00:00+00:00"}
    assert sent["bundle_payload"] is None
    assert sent["has_cloud_sync_profile"] is True


def test_an_unreachable_resident_does_not_let_this_side_read_an_allow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _unavailable(kind: str, fields: dict[str, object], *, guard_home: Path) -> dict[str, object]:
        raise NativeHookComposeError("native_hook_artifact_compose_unavailable")

    with pytest.raises(NativeHookComposeError):
        _resolve(_Store(tmp_path), monkeypatch, _unavailable)
