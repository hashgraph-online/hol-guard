"""Runtime ownership changes reconcile only Guard-managed artifacts."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import runtime_artifact_reconciliation as reconciliation
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.shim_refresh import ShimRefreshResult
from codex_plugin_scanner.guard.shims import package_shim_status


class _Store:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home

    def list_managed_installs(self) -> list[dict[str, object]]:
        return [{"harness": "codex", "active": True}]

    def get_managed_install(self, _harness: str) -> dict[str, object] | None:
        return {"harness": "codex", "active": True}


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
            "manager_details": [{"manager": "npm", "integrity": "ok", "path_active": True}],
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
            "manager_details": [{"manager": "npm", "integrity": "tampered", "path_active": True}],
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


def test_harness_repair_preserves_stored_workspace_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    store = _Store(tmp_path / "guard")
    store.list_managed_installs = lambda: [{"harness": "codex", "active": True, "workspace": str(workspace)}]
    store.get_managed_install = lambda _harness: {
        "harness": "codex",
        "active": True,
        "workspace": str(workspace),
    }
    observed: list[tuple[Path | None, str | None]] = []
    verification_calls = {"count": 0}

    def verify(_installs: object, _store: object) -> dict[str, bool]:
        verification_calls["count"] += 1
        return {"codex": verification_calls["count"] > 1}

    def apply(
        _command: str,
        _harness: str,
        _install_all: bool,
        context: object,
        _store: object,
        stored_workspace: str | None,
        _now: str,
    ) -> None:
        observed.append((context.workspace_dir, stored_workspace))

    monkeypatch.setattr(reconciliation, "_live_hook_verification", verify)
    monkeypatch.setattr(reconciliation, "apply_managed_install", apply)

    repaired, failed = reconciliation.repair_failing_managed_harness_hooks(
        store,
        home_dir=tmp_path / "home",
    )

    assert repaired == ("codex",)
    assert failed == ()
    assert observed == [(workspace.resolve(), str(workspace))]


def test_reconcile_reports_inactive_package_shim(
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
        lambda _context: {
            "installed_managers": ["npm"],
            "manager_details": [{"manager": "npm", "integrity": "ok", "path_active": False}],
        },
    )
    monkeypatch.setattr(
        reconciliation,
        "repair_package_shims",
        lambda *_args, **_kwargs: {"repaired": [], "path_repair_required": ["npm"]},
    )

    result = reconciliation.reconcile_runtime_artifacts(store, home_dir=tmp_path / "home")

    assert result.healthy is False
    assert result.errors == ("package:npm:path_inactive",)


def test_reconcile_projects_profile_activation_for_daemon_health(
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
    raw_status = {
        "path_status": "restart_required",
        "shell_profile_configured": True,
        "installed_managers": ["npm"],
        "manager_details": [{"manager": "npm", "integrity": "ok", "path_active": False}],
    }
    projected_status = {
        **raw_status,
        "path_status": "in_path",
        "path_active": True,
        "manager_details": [{"manager": "npm", "integrity": "ok", "path_active": True}],
    }
    monkeypatch.setattr(reconciliation, "package_shim_status", lambda _context: raw_status)
    monkeypatch.setattr(reconciliation, "package_shim_dashboard_status", lambda _context: projected_status)
    monkeypatch.setattr(
        reconciliation,
        "repair_package_shims",
        lambda *_args, **_kwargs: {"repaired": []},
    )

    result = reconciliation.reconcile_runtime_artifacts(store, home_dir=tmp_path / "home")

    assert result.healthy is True
    assert result.errors == ()


def test_reconcile_reports_unreadable_existing_package_manifest(
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
        lambda _context: {
            "manifest_state": "unreadable",
            "installed_managers": [],
        },
    )
    monkeypatch.setattr(
        reconciliation,
        "repair_package_shims",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not infer managers")),
    )

    result = reconciliation.reconcile_runtime_artifacts(store, home_dir=tmp_path / "home")

    assert result.healthy is False
    assert result.changed is False
    assert result.errors == ("package:manifest:unreadable",)


def test_package_shim_status_distinguishes_absent_and_unreadable_manifests(
    tmp_path: Path,
) -> None:
    home_dir = tmp_path / "home"
    guard_home = tmp_path / "guard-home"
    context = HarnessContext(home_dir=home_dir, workspace_dir=None, guard_home=guard_home)

    assert package_shim_status(context)["manifest_state"] == "absent"

    manifest_path = guard_home / "package-shims" / "manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text("{not-json", encoding="utf-8")

    status = package_shim_status(context)

    assert status["manifest_state"] == "unreadable"
    assert status["installed_managers"] == []


_OLD_DIGEST = "a" * 64
_NEW_DIGEST = "b" * 64


def _pinned_config(path: Path, digest: str) -> Path:
    path.write_text(
        '{"hooks": {"PreToolUse": [{"command": "/g/native-runtime/'
        + digest
        + '/hol-guard-runtime bounded-hook-bridge"}]}}',
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize(("pinned", "expected"), [(_OLD_DIGEST, ("zcode",)), (_NEW_DIGEST, ())])
def test_harness_repair_repins_a_hook_config_naming_an_older_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pinned: str,
    expected: tuple[str, ...],
) -> None:
    config = _pinned_config(tmp_path / "config.json", pinned)
    install = {"harness": "zcode", "active": True, "manifest": {"config_path": str(config)}}
    store = _Store(tmp_path / "guard")
    store.list_managed_installs = lambda: [install]
    store.get_managed_install = lambda _harness: install
    applied: list[str] = []

    def apply(_command: str, harness: str, *_args: object) -> None:
        applied.append(harness)
        _pinned_config(config, _NEW_DIGEST)

    monkeypatch.setattr(reconciliation, "_live_hook_verification", lambda *_args: {"zcode": True})
    monkeypatch.setattr(reconciliation, "_current_durable_runtime_digest", lambda: _NEW_DIGEST)
    monkeypatch.setattr(reconciliation, "apply_managed_install", apply)

    repaired, failed = reconciliation.repair_failing_managed_harness_hooks(store, home_dir=tmp_path / "home")

    assert repaired == expected
    assert applied == list(expected)
    assert failed == ()


def test_harness_repair_fails_when_reinstall_leaves_the_older_runtime_pinned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _pinned_config(tmp_path / "config.json", _OLD_DIGEST)
    install = {"harness": "zcode", "active": True, "manifest": {"config_path": str(config)}}
    store = _Store(tmp_path / "guard")
    store.list_managed_installs = lambda: [install]
    store.get_managed_install = lambda _harness: install

    monkeypatch.setattr(reconciliation, "_live_hook_verification", lambda *_args: {"zcode": True})
    monkeypatch.setattr(reconciliation, "_current_durable_runtime_digest", lambda: _NEW_DIGEST)
    monkeypatch.setattr(reconciliation, "apply_managed_install", lambda *_args: None)

    assert reconciliation.repair_failing_managed_harness_hooks(store, home_dir=tmp_path / "home") == ((), ("zcode",))


def test_a_source_install_never_repins_hook_configs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delattr(reconciliation.sys, "frozen", raising=False)

    assert reconciliation._current_durable_runtime_digest() is None
    assert not reconciliation._pins_stale_native_runtime({"manifest": {"config_path": "/missing"}}, None)


def test_a_windows_escaped_pin_is_read(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        '{"command": "C:\\\\g\\\\native-runtime\\\\' + _OLD_DIGEST + '\\\\hol-guard-runtime.exe"}', encoding="utf-8"
    )

    assert reconciliation._pins_stale_native_runtime({"manifest": {"config_path": str(config)}}, _NEW_DIGEST)
    assert not reconciliation._pins_stale_native_runtime({"manifest": {"config_path": str(config)}}, _OLD_DIGEST)


def test_a_hook_artifact_outside_config_path_is_read(tmp_path: Path) -> None:
    hook = _pinned_config(tmp_path / "pretool.sh", _OLD_DIGEST)
    yaml_config = tmp_path / "hermes.yaml"
    yaml_config.write_text("guard: managed\n", encoding="utf-8")
    manifest = {
        "config_path": str(yaml_config),
        "pretool_hook_path": str(hook),
        "files": [{"path": str(hook)}],
    }

    assert reconciliation._pins_stale_native_runtime({"manifest": manifest}, _NEW_DIGEST)
    assert not reconciliation._pins_stale_native_runtime({"manifest": {"config_path": str(yaml_config)}}, _NEW_DIGEST)


def test_a_pin_past_the_first_chunk_is_read(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    filler = "x" * (reconciliation._PINNED_SCAN_CHUNK_BYTES * 4 + 7)
    config.write_text(
        '{"notes": "' + filler + '", "command": "/g/native-runtime/' + _OLD_DIGEST + '/hol-guard-runtime"}',
        encoding="utf-8",
    )
    manifest = {"config_path": str(config)}

    assert reconciliation._pins_stale_native_runtime({"manifest": manifest}, _NEW_DIGEST)


def test_a_pin_split_across_a_chunk_boundary_is_read(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    prefix = '{"command": "/g'
    pad = "x" * (reconciliation._PINNED_SCAN_CHUNK_BYTES - len(prefix) - 20)
    config.write_text(
        prefix + pad + "/native-runtime/" + _OLD_DIGEST + '/hol-guard-runtime"}',
        encoding="utf-8",
    )

    assert reconciliation._pins_stale_native_runtime({"manifest": {"config_path": str(config)}}, _NEW_DIGEST)


def test_a_preserved_user_field_naming_a_runtime_path_is_not_a_stale_pin(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        '{"notes": "archived under /home/u/.hol-guard/native-runtime/' + _OLD_DIGEST + '/ before the upgrade"}',
        encoding="utf-8",
    )

    assert not reconciliation._pins_stale_native_runtime({"manifest": {"config_path": str(config)}}, _NEW_DIGEST)


def test_a_note_beside_a_current_hook_command_is_not_a_stale_pin(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(
        '{"notes": "old copy: /home/u/.hol-guard/native-runtime/'
        + _OLD_DIGEST
        + '/", "command": "/home/u/.hol-guard/native-runtime/'
        + _NEW_DIGEST
        + '/hol-guard-runtime bounded-hook-bridge"}',
        encoding="utf-8",
    )

    assert not reconciliation._pins_stale_native_runtime({"manifest": {"config_path": str(config)}}, _NEW_DIGEST)


def test_a_file_past_the_scan_budget_is_not_read_to_the_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reconciliation, "_PINNED_SCAN_CHUNK_BYTES", 64)
    monkeypatch.setattr(reconciliation, "_PINNED_SCAN_MAX_BYTES", 128)
    config = tmp_path / "config.json"
    config.write_text(
        '{"notes": "' + "x" * 256 + '", "command": "/g/native-runtime/' + _OLD_DIGEST + '/hol-guard-runtime"}',
        encoding="utf-8",
    )

    assert not reconciliation._pins_stale_native_runtime({"manifest": {"config_path": str(config)}}, _NEW_DIGEST)


def test_a_malformed_persisted_path_does_not_stop_the_remaining_harnesses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _pinned_config(tmp_path / "config.json", _OLD_DIGEST)
    broken = {"harness": "cursor", "active": True, "manifest": {"config_path": "/g/\x00/config.json"}}
    stale = {"harness": "zcode", "active": True, "manifest": {"config_path": str(config)}}
    store = _Store(tmp_path / "guard")
    store.list_managed_installs = lambda: [broken, stale]
    store.get_managed_install = lambda harness: broken if harness == "cursor" else stale
    applied: list[str] = []

    def apply(_command: str, harness: str, *_args: object) -> None:
        applied.append(harness)
        _pinned_config(config, _NEW_DIGEST)

    monkeypatch.setattr(reconciliation, "_live_hook_verification", lambda *_args: {"cursor": True, "zcode": True})
    monkeypatch.setattr(reconciliation, "_current_durable_runtime_digest", lambda: _NEW_DIGEST)
    monkeypatch.setattr(reconciliation, "apply_managed_install", apply)

    repaired, failed = reconciliation.repair_failing_managed_harness_hooks(store, home_dir=tmp_path / "home")

    assert applied == ["zcode"]
    assert repaired == ("zcode",)
    assert failed == ()
