from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.mdm import acl, managed_file_trust
from codex_plugin_scanner.guard.mdm.contracts import MachinePaths, default_machine_paths


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(
        runtime_root=root / "runtime",
        state_root=root / "state",
        policy_path=root / "policy.json",
        log_root=root / "logs",
        manifest_path=root / "runtime" / "release-manifest.json",
    )


def _macos_surfaces(root: Path) -> tuple[acl._PathSurface, ...]:
    paths = _paths(root)
    return (
        acl._PathSurface("runtime", paths.runtime_root, True, root),
        acl._PathSurface("manifest", paths.manifest_path, False, root),
        acl._PathSurface("machineState", paths.state_root, True, root),
        acl._PathSurface("managedPolicy", paths.policy_path or root / "missing", False, root),
        acl._PathSurface("logs", paths.log_root, True, root),
        acl._PathSurface("serviceRegistration", root / "service.plist", False, root),
    )


def _create_macos_surfaces(root: Path) -> None:
    paths = _paths(root)
    paths.runtime_root.mkdir()
    paths.state_root.mkdir()
    paths.log_root.mkdir()
    paths.manifest_path.write_text("{}")
    assert paths.policy_path is not None
    paths.policy_path.write_text("{}")
    (root / "service.plist").write_text("plist")
    root.chmod(0o755)
    for directory in (paths.runtime_root, paths.state_root, paths.log_root):
        directory.chmod(0o755)
    for file_path in (paths.manifest_path, paths.policy_path, root / "service.plist"):
        file_path.chmod(0o644)


@pytest.mark.skipif(sys.platform != "darwin", reason="reads extended ACLs with the macOS ls")
def test_macos_acl_verification_accepts_root_owned_nonwritable_surfaces(tmp_path: Path) -> None:
    _create_macos_surfaces(tmp_path)

    result = acl.verify_protected_ownership_and_acl(
        _paths(tmp_path),
        system_name="Darwin",
        expected_posix_uid=os.getuid(),
        macos_surfaces=_macos_surfaces(tmp_path),
    )

    assert result.healthy
    assert result.reason_code == "ownership_acl_valid"
    assert all(surface.healthy for surface in result.surfaces)


@pytest.mark.skipif(sys.platform != "darwin", reason="reads extended ACLs with the macOS ls")
def test_macos_acl_verification_detects_standard_user_writable_surface(tmp_path: Path) -> None:
    _create_macos_surfaces(tmp_path)
    _paths(tmp_path).state_root.chmod(0o777)

    result = acl.verify_protected_ownership_and_acl(
        _paths(tmp_path),
        system_name="Darwin",
        expected_posix_uid=os.getuid(),
        macos_surfaces=_macos_surfaces(tmp_path),
    )

    assert result.status == "tampered"
    assert result.reason_code == "ownership_acl_standard_user_writable"


def test_macos_acl_verification_sends_each_surface_to_the_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    requests: list[dict[str, object]] = []

    def answer(request: dict[str, object], *, deadline: float) -> dict[str, object]:
        del deadline
        requests.append(request)
        return {"ok": True, "status": "healthy", "reason_code": "ownership_acl_valid", "surfaces": []}

    monkeypatch.setattr(acl, "_native_answer", answer)

    result = acl.verify_protected_ownership_and_acl(
        _paths(tmp_path),
        system_name="Darwin",
        expected_posix_uid=501,
        macos_surfaces=_macos_surfaces(tmp_path)[:1],
    )

    assert result.healthy
    assert requests == [
        {
            "op": "macos-verify",
            "macos_surfaces": [
                {"name": "runtime", "path": str(tmp_path / "runtime"), "directory": True, "trust_root": str(tmp_path)}
            ],
            "expected_uid": 501,
        }
    ]


def test_macos_acl_verification_without_the_runtime_fails_the_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _create_macos_surfaces(tmp_path)
    monkeypatch.setattr(acl, "_native_answer", lambda _request, *, deadline: None)

    result = acl.verify_protected_ownership_and_acl(
        _paths(tmp_path),
        system_name="Darwin",
        expected_posix_uid=os.getuid(),
        macos_surfaces=_macos_surfaces(tmp_path),
    )

    assert result.status == "unknown"
    assert result.reason_code == "ownership_acl_probe_failed"


def _windows_paths() -> MachinePaths:
    return default_machine_paths(system_name="Windows")


def test_windows_acl_verification_asks_the_runtime_to_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    requests: list[dict[str, object]] = []

    def answer(request: dict[str, object], *, deadline: float) -> dict[str, object]:
        del deadline
        requests.append(request)
        return {
            "ok": True,
            "status": "healthy",
            "reason_code": "ownership_acl_valid",
            "surfaces": [{"name": "filesystem-000", "state": "healthy", "reason_code": "ownership_acl_valid"}],
        }

    monkeypatch.setattr(acl, "_native_answer", answer)
    monkeypatch.setattr(acl, "_windows_directory", lambda: r"D:\Windows")
    paths = _windows_paths()

    result = acl.verify_protected_ownership_and_acl(paths, system_name="Windows")

    assert result.healthy
    assert requests == [
        {
            "op": "windows-probe",
            "windows_paths": {
                "runtime_root": str(paths.runtime_root),
                "manifest_path": str(paths.manifest_path),
                "state_root": str(paths.state_root),
                "log_root": str(paths.log_root),
            },
            "windows_directory": r"D:\Windows",
        }
    ]


@pytest.mark.parametrize("answer", [None, {"ok": True}])
def test_windows_acl_verification_fails_closed_without_a_native_verdict(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None
) -> None:
    monkeypatch.setattr(acl, "_windows_directory", lambda: r"D:\Windows")
    monkeypatch.setattr(acl, "_native_answer", lambda _request, **_kwargs: answer)

    result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert not result.healthy
    assert result.reason_code == "ownership_acl_probe_failed"


def _no_windows_directory() -> str:
    raise OSError("windows_system_directory_unavailable")


def test_windows_acl_verification_without_a_windows_directory_never_asks(monkeypatch: pytest.MonkeyPatch) -> None:
    ask = Mock(side_effect=AssertionError("runtime asked without a Windows directory"))
    monkeypatch.setattr(acl, "_windows_directory", _no_windows_directory)
    monkeypatch.setattr(acl, "_native_answer", ask)

    result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert result.reason_code == "ownership_acl_probe_failed"
    ask.assert_not_called()


@pytest.mark.parametrize(("status", "trusted"), [("healthy", True), ("tampered", False), (None, False)])
def test_windows_managed_file_trust_asks_the_runtime_to_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str | None, trusted: bool
) -> None:
    requests: list[dict[str, object]] = []

    def answer(request: dict[str, object], *, deadline: float) -> dict[str, object] | None:
        del deadline
        requests.append(request)
        return None if status is None else {"ok": True, "status": status}

    monkeypatch.setattr(managed_file_trust, "_native_answer", answer)
    monkeypatch.setattr(managed_file_trust, "windows_directory", lambda: r"D:\Windows")
    managed = tmp_path / "policy.json"

    assert managed_file_trust.machine_controlled_file_is_trusted(managed, system_name="Windows") is trusted
    assert requests == [{"op": "windows-file-probe", "managed_file": str(managed), "windows_directory": r"D:\Windows"}]


def test_windows_managed_file_trust_without_a_windows_directory_never_asks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ask = Mock(side_effect=AssertionError("runtime asked without a Windows directory"))
    monkeypatch.setattr(managed_file_trust, "windows_directory", _no_windows_directory)
    monkeypatch.setattr(managed_file_trust, "_native_answer", ask)

    assert not managed_file_trust.machine_controlled_file_is_trusted(tmp_path / "policy.json", system_name="Windows")
    ask.assert_not_called()


@pytest.mark.skipif(os.name != "nt", reason="requires a Windows MDM installation")
def test_windows_installed_tree_and_default_ancestors_have_safe_acls() -> None:
    paths = _windows_paths()
    if not paths.runtime_root.exists():
        pytest.skip("HOL Guard MDM runtime is not installed")

    result = acl.verify_protected_ownership_and_acl(paths, system_name="Windows")
    surfaces = {surface.name: surface for surface in result.surfaces}

    assert len(surfaces) == len(result.surfaces)
    assert any(surface.healthy for surface in surfaces.values())
    assert all(surface.state in {"healthy", "absent"} for surface in surfaces.values())


def test_unsupported_platform_never_reports_acl_health(tmp_path: Path) -> None:
    result = acl.verify_protected_ownership_and_acl(_paths(tmp_path), system_name="Linux")

    assert not result.healthy
    assert result.reason_code == "ownership_acl_platform_unsupported"


def test_a_spent_native_budget_never_starts_the_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    spawn = Mock(return_value=None)
    monkeypatch.setattr(native_runtime, "_run_native_process", spawn)

    answer = acl._native_answer({"op": "aggregate", "surfaces": []}, deadline=time.monotonic() - 1)

    assert answer is None
    spawn.assert_not_called()
