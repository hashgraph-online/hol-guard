from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler, _repair_detected_package_shims
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


@pytest.mark.parametrize("allowed,proof_required", [(False, False), (True, False), (True, True)])
def test_guided_repair_checks_cloud_access_before_requesting_local_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    allowed: bool,
    proof_required: bool,
) -> None:
    handler = object.__new__(_GuardDaemonHandler)
    handler.server = SimpleNamespace(store=SimpleNamespace(guard_home=tmp_path, get_cloud_workspace_id=lambda: None))
    events: list[str] = []
    responses: list[tuple[int, dict]] = []
    context = HarnessContext(guard_home=tmp_path, home_dir=tmp_path, workspace_dir=tmp_path)
    monkeypatch.setattr(handler, "_enforce_package_firewall_rate_limit", lambda *args: True)
    monkeypatch.setattr(
        handler, "_supply_chain_entitlement", lambda: {"allowed": allowed, "reason": "paid_guard_cloud_required"}
    )
    monkeypatch.setattr(handler, "_supply_chain_context", lambda payload: context)
    monkeypatch.setattr(handler, "_write_json", lambda payload, status=200: responses.append((status, payload)))
    monkeypatch.setattr(
        handler, "_write_approval_gate_error", lambda error: responses.append((error.status, {"error": error.code}))
    )
    monkeypatch.setattr(handler, "_record_headless_receipt", lambda **kwargs: None)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.package_shim_status", lambda context: {"installed_managers": []}
    )

    def require_proof(*args, **kwargs):
        events.append("proof")
        if proof_required:
            raise ApprovalGateError("approval_gate_required", "Local approval required.")

    monkeypatch.setattr("codex_plugin_scanner.guard.daemon.server.require_high_risk", require_proof)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server._repair_detected_package_shims",
        lambda *args, **kwargs: events.append("repair"),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server._activate_package_firewall_runtime", lambda context: (200, {})
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.repair_sync_intelligence", lambda *args, **kwargs: None
    )

    handler._handle_supply_chain_repair({})

    if proof_required:
        assert events == ["proof"]
        assert responses == [(403, {"error": "approval_gate_required"})]
    elif allowed:
        assert events == ["proof", "repair"]
        assert responses[0][0] == 200
        assert responses[0][1]["result"]["repaired"] is True
    else:
        assert events == []
        assert responses[0][0] == 402
        assert responses[0][1]["error"] == "paid_guard_cloud_required"


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


def test_repair_sync_intelligence_refreshes_bundle_without_auditing_workspaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth_context = {"sync_url": "https://guard.example.test/sync"}
    store = GuardStore(tmp_path / "guard")
    refreshed: list[tuple[GuardStore, dict[str, object]]] = []

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server._resolve_guard_sync_auth_context",
        lambda _store: auth_context,
    )

    def refresh_bundle(
        actual_store: GuardStore,
        *,
        auth_context: dict[str, object],
    ) -> dict[str, object]:
        refreshed.append((actual_store, auth_context))
        return {"status": "synced"}

    def reject_workspace_audit(*_args: object, **_kwargs: object) -> dict[str, object]:
        pytest.fail("restore must not synchronously audit managed workspaces")

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.local_supply_chain.sync_supply_chain_bundle",
        refresh_bundle,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.local_supply_chain.sync_managed_workspace_audits",
        reject_workspace_audit,
    )

    result = repair_sync_intelligence(store, workspace_dir=tmp_path / "workspace")

    assert result == {"status": "synced"}
    assert refreshed == [(store, auth_context)]


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


def test_local_recovery_without_cloud_access_does_not_install_new_managers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = HarnessContext(guard_home=tmp_path, home_dir=tmp_path, workspace_dir=tmp_path)
    observed: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.package_shim_status",
        lambda context: {
            "installed_managers": ["npm"],
            "detected_managers": ["npm", "pip3"],
            "missing_managers": ["pip3"],
            "manager_details": [{"manager": "npm", "integrity": "ok"}, {"manager": "pip3", "integrity": "missing"}],
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.server.activate_package_shims",
        lambda context, *, managers, repair: observed.append(managers) or {},
    )

    result = coordinate_supply_chain_repair(
        repair_package_shims=lambda: _repair_detected_package_shims(context, install_missing=False),
        activate_runtime=lambda: (200, {}),
        sync_intelligence=lambda: None,
    )

    assert observed == [("npm",)]
    assert result["repaired"] is False
    assert result["failed_steps"] == []
    assert result["completed_steps"] == ["runtime_activation", "intelligence_sync"]
    assert result["remaining_steps"] == [
        {
            "step": "package_shims",
            "code": "paid_guard_cloud_required",
            "action": "check_access",
            "message": (
                "Existing package tools were repaired. "
                "Check Cloud access to protect additional detected tools: pip3."
            ),
        }
    ]
    assert (
        result["message"]
        == "Existing protection was repaired. Check Cloud access before protecting additional package tools."
    )
