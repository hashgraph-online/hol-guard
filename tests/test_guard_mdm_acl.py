from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.mdm import acl
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


def test_windows_payload_deduplicates_case_insensitive_paths() -> None:
    paths = _windows_paths()
    mixed_case_paths = MachinePaths(
        runtime_root=paths.runtime_root,
        state_root=paths.state_root,
        policy_path=paths.policy_path,
        log_root=paths.log_root,
        manifest_path=Path(str(paths.runtime_root).upper()) / "release-manifest.json",
    )

    payload = acl._windows_surface_payload(mixed_case_paths, deadline=acl._native_deadline())
    normalized_paths = [(str(item["kind"]), str(item["path"]).casefold()) for item in payload]

    assert len(normalized_paths) == len(set(normalized_paths))


def _windows_rows() -> list[dict[str, object]]:
    return [
        {
            "Name": item["name"],
            "Kind": item["kind"],
            "ExpectedContainer": item["expectedContainer"],
            "Leaf": item["leaf"],
            "Exists": True,
            "Owner": "S-1-5-18",
            "Attributes": 16 if item["expectedContainer"] else 0,
            "Container": item["expectedContainer"],
            "NullDacl": False,
            "Truncated": False,
            "Rules": [
                {
                    "Sid": "S-1-5-32-545",
                    "Type": "Allow",
                    "Rights": 1_179_817,
                    "Propagation": "None",
                }
            ],
        }
        for item in acl._windows_surface_payload(_windows_paths(), deadline=acl._native_deadline())
    ]


def test_windows_acl_verification_uses_sid_rights_and_accepts_read_only_users(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths, **_kwargs: _windows_rows())

    result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert result.healthy


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("Owner", "S-1-5-21-1-2-3-1001", "ownership_acl_wrong_owner"),
        ("Owner", "S-1-3-0", "ownership_acl_wrong_owner"),
        ("Attributes", 0x400, "ownership_acl_path_escape"),
        ("Exists", False, "ownership_acl_surface_absent"),
        ("Truncated", True, "ownership_acl_probe_failed"),
        ("NullDacl", True, "ownership_acl_standard_user_writable"),
    ],
)
def test_windows_acl_verification_fails_honestly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    reason: str,
) -> None:
    rows = _windows_rows()
    rows[0][field] = value
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths, **_kwargs: rows)

    result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert result.reason_code == reason


@pytest.mark.skipif(os.name != "nt", reason="requires a Windows MDM installation")
def test_windows_installed_tree_and_default_ancestors_have_safe_acls() -> None:
    paths = _windows_paths()
    if not paths.runtime_root.exists():
        pytest.skip("HOL Guard MDM runtime is not installed")

    payload = acl._windows_surface_payload(paths, deadline=acl._native_deadline())
    required_paths = {
        str(paths.runtime_root).casefold(),
        str(paths.manifest_path).casefold(),
        str(paths.state_root).casefold(),
        str(paths.log_root).casefold(),
    }
    required_names = {str(item["name"]) for item in payload if str(item["path"]).casefold() in required_paths}
    result = acl.verify_protected_ownership_and_acl(paths, system_name="Windows")
    surfaces = {surface.name: surface for surface in result.surfaces}

    assert required_names <= surfaces.keys()
    assert all(surfaces[name].healthy for name in required_names)
    assert all(surface.state in {"healthy", "absent"} for surface in surfaces.values())


@pytest.mark.parametrize("answer", [None, {"ok": True}])
def test_windows_acl_verification_fails_closed_without_a_native_verdict(
    monkeypatch: pytest.MonkeyPatch, answer: dict[str, object] | None
) -> None:
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths, **_kwargs: [])
    monkeypatch.setattr(acl, "_native_answer", lambda _request, **_kwargs: answer)

    result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert not result.healthy
    assert result.reason_code == "ownership_acl_probe_failed"


def test_windows_acl_probe_uses_pinned_powershell_and_encoded_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Mock(return_value=subprocess.CompletedProcess(["powershell"], 0, json.dumps(_windows_rows()), ""))
    monkeypatch.setattr(acl, "_windows_directory", lambda: r"D:\Windows")
    monkeypatch.setattr(acl.subprocess, "run", run)

    acl._run_windows_acl_probe(_windows_paths(), deadline=acl._native_deadline())

    command = run.call_args.args[0]
    kwargs = run.call_args.kwargs
    assert command[0] == r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    assert str(tmp_path) not in command[-1]
    assert kwargs["cwd"] == r"D:\Windows\System32"
    assert kwargs["env"] == {
        "ComSpec": r"D:\Windows\System32\cmd.exe",
        "SystemRoot": r"D:\Windows",
        "WINDIR": r"D:\Windows",
    }


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
