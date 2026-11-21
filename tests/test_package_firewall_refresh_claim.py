from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.native_runner_authority import NativeRunnerAuthorityError
from codex_plugin_scanner.guard.store import GuardStore


def _record_refreshes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def _proof(_store: GuardStore, **_options: object) -> dict[str, object]:
        calls.append("proof")
        return {}

    def _bundle(_store: GuardStore, **_options: object) -> dict[str, object]:
        calls.append("bundle")
        return {}

    monkeypatch.setattr(local_supply_chain_module, "sync_local_guard_cloud_proof", _proof)
    monkeypatch.setattr(local_supply_chain_module, "sync_supply_chain_bundle", _bundle)
    return calls


def test_a_denied_entitlement_refreshes_guard_cloud_once_per_interval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seed_connected_oauth_without_entitlement,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    seed_connected_oauth_without_entitlement(store)
    calls = _record_refreshes(monkeypatch)

    first = local_supply_chain_module.resolve_package_firewall_entitlement_with_refresh(store)
    second = local_supply_chain_module.resolve_package_firewall_entitlement_with_refresh(store)

    assert calls == ["proof", "bundle"]
    assert first["allowed"] is False
    assert second == first
    assert (store.guard_home / "package-firewall-refresh.json").is_file()


def test_an_unavailable_refresh_claim_skips_the_cloud_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seed_connected_oauth_without_entitlement,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    seed_connected_oauth_without_entitlement(store)
    calls = _record_refreshes(monkeypatch)

    def _unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise NativeRunnerAuthorityError("native_runner_authority_unavailable")

    monkeypatch.setattr(local_supply_chain_module, "native_runner_authority", _unavailable)

    entitlement = local_supply_chain_module.resolve_package_firewall_entitlement_with_refresh(store)

    assert calls == []
    assert entitlement["allowed"] is False
