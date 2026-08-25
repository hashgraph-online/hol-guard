from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.daemon.server import _repair_detected_package_shims
from codex_plugin_scanner.guard.runtime.runner import (
    GuardSyncEndpointUntrustedError,
    GuardSyncNotConfiguredError,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.supply_chain_repair import (
    SupplyChainRepairDeferredError,
    coordinate_supply_chain_repair,
)
from codex_plugin_scanner.guard.supply_chain_repair_sync import repair_sync_intelligence


def test_supply_chain_repair_runs_every_step() -> None:
    calls: list[str] = []

    result = coordinate_supply_chain_repair(
        repair_package_shims=lambda: calls.append("repair"),
        activate_runtime=lambda: calls.append("activate") or (200, {}),
        sync_intelligence=lambda: calls.append("sync"),
    )

    assert calls == ["repair", "activate", "sync"]
    assert result["repaired"] is True
    assert result["completed_steps"] == ["package_shims", "runtime_activation", "intelligence_sync"]
    assert result["failed_steps"] == []
    assert result["remaining_steps"] == []


@pytest.mark.parametrize("failed_step", ("repair", "activate", "sync"))
def test_supply_chain_repair_keeps_running_after_independent_failure(failed_step: str) -> None:
    calls: list[str] = []

    def step(name: str) -> Callable[[], object]:
        def run() -> object:
            calls.append(name)
            if name == failed_step:
                raise RuntimeError("private failure detail")
            return {}

        return run

    def activate() -> tuple[int, dict[str, object]]:
        calls.append("activate")
        if failed_step == "activate":
            return 409, {"message": "private failure detail"}
        return 200, {}

    result = coordinate_supply_chain_repair(
        repair_package_shims=step("repair"),
        activate_runtime=activate,
        sync_intelligence=step("sync"),
    )

    assert calls == ["repair", "activate", "sync"]
    assert result["repaired"] is False
    failed_steps = cast(list[dict[str, str]], result["failed_steps"])
    assert [failure["step"] for failure in failed_steps] == [
        {"repair": "package_shims", "activate": "runtime_activation", "sync": "intelligence_sync"}[failed_step]
    ]
    assert "private failure detail" not in str(result)


def test_supply_chain_repair_handles_complete_failure_without_inventing_proof() -> None:
    def fail() -> object:
        raise OSError("no")

    result = coordinate_supply_chain_repair(
        repair_package_shims=fail,
        activate_runtime=lambda: (500, {}),
        sync_intelligence=fail,
    )

    assert result["repaired"] is False
    assert result["completed_steps"] == []
    assert len(cast(list[dict[str, str]], result["failed_steps"])) == 3
    assert result["remaining_steps"] == []


def test_supply_chain_repair_defers_unconfigured_cloud_intelligence() -> None:
    def sync() -> object:
        raise SupplyChainRepairDeferredError(
            code="guard_cloud_connect_required",
            message="Connect Guard Cloud to refresh safety intelligence.",
            action="connect",
        )

    result = coordinate_supply_chain_repair(
        repair_package_shims=lambda: {},
        activate_runtime=lambda: (200, {}),
        sync_intelligence=sync,
    )

    assert result["repaired"] is False
    assert result["completed_steps"] == ["package_shims", "runtime_activation"]
    assert result["failed_steps"] == []
    remaining = cast(list[dict[str, str]], result["remaining_steps"])
    assert [step["step"] for step in remaining] == ["intelligence_sync"]
    assert remaining[0]["action"] == "connect"
    assert "Connect Guard Cloud" in str(result["message"])


def test_repair_sync_intelligence_defers_unconfigured_cloud(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unconfigured(_store: object) -> dict[str, object]:
        raise GuardSyncNotConfiguredError("Guard Cloud workspace is not connected.")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server._resolve_guard_sync_auth_context",
        unconfigured,
    )

    with pytest.raises(SupplyChainRepairDeferredError) as caught:
        repair_sync_intelligence(GuardStore(tmp_path / "guard"), workspace_dir=None)

    assert caught.value.action == "connect"
    assert caught.value.code == "guard_cloud_connect_required"


def test_repair_sync_intelligence_keeps_untrusted_endpoint_as_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def untrusted(_store: object) -> dict[str, object]:
        raise GuardSyncEndpointUntrustedError("Guard Cloud endpoint failed trust validation.")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server._resolve_guard_sync_auth_context",
        untrusted,
    )

    with pytest.raises(GuardSyncEndpointUntrustedError):
        repair_sync_intelligence(GuardStore(tmp_path / "guard"), workspace_dir=None)


def test_repair_detected_package_shims_installs_detected_unprotected_manager(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    home_dir.mkdir()
    workspace_dir.mkdir()
    context = HarnessContext(
        guard_home=tmp_path / "guard",
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.shims._detect_system_package_managers",
        lambda _context, path_env=None: (["npm"], []),
    )

    result = _repair_detected_package_shims(context)

    assert result["installed_now"] == ["npm"]
    package_shims = cast(dict[str, object], result["package_shims"])
    assert package_shims["installed_managers"] == ["npm"]
