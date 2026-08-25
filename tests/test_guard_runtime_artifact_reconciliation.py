"""Runtime ownership changes reconcile only Guard-managed artifacts."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import runtime_artifact_reconciliation as reconciliation
from codex_plugin_scanner.guard.shim_refresh import ShimRefreshResult


class _Store:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home

    def list_managed_installs(self) -> list[dict[str, object]]:
        return [{"harness": "codex", "active": True}]


def test_reconcile_repairs_existing_artifacts_without_enrolling_new_managers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(tmp_path / "guard")
    package_repairs: list[tuple[str, ...]] = []
    status_calls = {"count": 0}

    monkeypatch.setattr(
        reconciliation,
        "refresh_stale_harness_shims",
        lambda **_kwargs: ShimRefreshResult(refreshed=("codex",), unchanged=(), errors=()),
    )
    monkeypatch.setattr(
        reconciliation,
        "repair_failing_managed_harness_hooks",
        lambda *_args, **_kwargs: (("codex",), ()),
    )

    def package_status(_context: object) -> dict[str, object]:
        status_calls["count"] += 1
        if status_calls["count"] == 1:
            return {"installed_managers": ["npm"], "manager_details": []}
        return {
            "installed_managers": ["npm"],
            "manager_details": [{"manager": "npm", "integrity": "ok"}],
        }

    monkeypatch.setattr(reconciliation, "package_shim_status", package_status)
    monkeypatch.setattr(
        reconciliation,
        "repair_package_shims",
        lambda _context, *, managers: package_repairs.append(managers) or {"repaired": ["npm"]},
    )

    result = reconciliation.reconcile_runtime_artifacts(store, home_dir=tmp_path / "home")

    assert result.healthy is True
    assert result.changed is True
    assert result.refreshed_launchers == ("codex",)
    assert result.repaired_harnesses == ("codex",)
    assert result.repaired_package_managers == ("npm",)
    assert package_repairs == [("npm",)]


def test_reconcile_does_not_install_package_shims_without_an_existing_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(tmp_path / "guard")
    monkeypatch.setattr(
        reconciliation,
        "refresh_stale_harness_shims",
        lambda **_kwargs: ShimRefreshResult(refreshed=(), unchanged=(), errors=()),
    )
    monkeypatch.setattr(
        reconciliation,
        "repair_failing_managed_harness_hooks",
        lambda *_args, **_kwargs: ((), ()),
    )
    monkeypatch.setattr(
        reconciliation,
        "package_shim_status",
        lambda _context: {"installed_managers": [], "detected_managers": ["npm"]},
    )
    monkeypatch.setattr(
        reconciliation,
        "repair_package_shims",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not enroll package managers")),
    )

    result = reconciliation.reconcile_runtime_artifacts(store, home_dir=tmp_path / "home")

    assert result.healthy is True
    assert result.changed is False


def test_reconcile_reports_failed_readback_instead_of_claiming_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store(tmp_path / "guard")
    monkeypatch.setattr(
        reconciliation,
        "refresh_stale_harness_shims",
        lambda **_kwargs: ShimRefreshResult(
            refreshed=(),
            unchanged=(),
            errors=("codex: write failed",),
        ),
    )
    monkeypatch.setattr(
        reconciliation,
        "repair_failing_managed_harness_hooks",
        lambda *_args, **_kwargs: ((), ("codex",)),
    )
    monkeypatch.setattr(
        reconciliation,
        "package_shim_status",
        lambda _context: {
            "installed_managers": ["npm"],
            "manager_details": [{"manager": "npm", "integrity": "tampered"}],
        },
    )
    monkeypatch.setattr(
        reconciliation,
        "repair_package_shims",
        lambda *_args, **_kwargs: {"repaired": []},
    )

    result = reconciliation.reconcile_runtime_artifacts(store, home_dir=tmp_path / "home")

    assert result.healthy is False
    assert result.failed_harnesses == ("codex",)
    assert "launcher:codex: write failed" in result.errors
    assert "package:npm:integrity" in result.errors
