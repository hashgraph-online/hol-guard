from __future__ import annotations

import json
import os
import subprocess
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


def test_macos_acl_verification_accepts_root_owned_nonwritable_surfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _create_macos_surfaces(tmp_path)
    monkeypatch.setattr(acl, "_macos_acl_is_mutable", lambda _path: False)

    result = acl.verify_protected_ownership_and_acl(
        _paths(tmp_path),
        system_name="Darwin",
        expected_posix_uid=os.getuid(),
        macos_surfaces=_macos_surfaces(tmp_path),
    )

    assert result.healthy
    assert result.reason_code == "ownership_acl_valid"
    assert all(surface.healthy for surface in result.surfaces)


def test_macos_acl_verification_queries_shared_ancestors_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _create_macos_surfaces(tmp_path)
    query = Mock(return_value=False)
    monkeypatch.setattr(acl, "_macos_acl_is_mutable", query)

    acl.verify_protected_ownership_and_acl(
        _paths(tmp_path),
        system_name="Darwin",
        expected_posix_uid=os.getuid(),
        macos_surfaces=_macos_surfaces(tmp_path),
    )

    queried = [call.args[0] for call in query.call_args_list]
    assert queried.count(tmp_path) == 1


def test_macos_acl_verification_detects_standard_user_writable_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _create_macos_surfaces(tmp_path)
    _paths(tmp_path).state_root.chmod(0o777)
    monkeypatch.setattr(acl, "_macos_acl_is_mutable", lambda _path: False)

    result = acl.verify_protected_ownership_and_acl(
        _paths(tmp_path),
        system_name="Darwin",
        expected_posix_uid=os.getuid(),
        macos_surfaces=_macos_surfaces(tmp_path),
    )

    assert result.status == "tampered"
    assert result.reason_code == "ownership_acl_standard_user_writable"


def test_macos_acl_verification_detects_symlink_and_missing_surface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _create_macos_surfaces(tmp_path)
    monkeypatch.setattr(acl, "_macos_acl_is_mutable", lambda _path: False)
    paths = _paths(tmp_path)
    paths.manifest_path.unlink()
    paths.manifest_path.symlink_to(tmp_path / "policy.json")

    symlink_result = acl.verify_protected_ownership_and_acl(
        paths,
        system_name="Darwin",
        expected_posix_uid=os.getuid(),
        macos_surfaces=_macos_surfaces(tmp_path),
    )
    paths.manifest_path.unlink()
    missing_result = acl.verify_protected_ownership_and_acl(
        paths,
        system_name="Darwin",
        expected_posix_uid=os.getuid(),
        macos_surfaces=_macos_surfaces(tmp_path),
    )

    assert symlink_result.reason_code == "ownership_acl_path_escape"
    assert missing_result.reason_code == "ownership_acl_surface_absent"


def test_macos_extended_acl_detects_non_root_mutation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    output = "-rw-r--r--+ 1 root wheel 0 Jul 17 00:00 policy\n 0: user:developer allow read,writeattr,delete\n"
    monkeypatch.setattr(
        acl.subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess(["ls"], 0, output, "")),
    )

    assert acl._macos_acl_is_mutable(tmp_path)


def test_macos_extended_acl_does_not_exempt_wheel_mutation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    output = "-rw-r--r--+ 1 root wheel 0 Jul 17 00:00 policy\n 0: group:wheel allow read,writeattr\n"
    monkeypatch.setattr(
        acl.subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess(["ls"], 0, output, "")),
    )

    assert acl._macos_acl_is_mutable(tmp_path)


def test_macos_extended_acl_exempts_inherited_root_mutation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    output = "-rw-r--r--+ 1 root wheel 0 Jul 17 00:00 policy\n 0: user:root inherited allow read,writeattr\n"
    monkeypatch.setattr(
        acl.subprocess,
        "run",
        Mock(return_value=subprocess.CompletedProcess(["ls"], 0, output, "")),
    )

    assert not acl._macos_acl_is_mutable(tmp_path)


def test_macos_acl_verification_detects_pathname_race(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _create_macos_surfaces(tmp_path)

    def mutate_once(path: Path) -> bool:
        if path == tmp_path:
            path.chmod(0o700)
        return False

    monkeypatch.setattr(acl, "_macos_acl_is_mutable", mutate_once)

    result = acl.verify_protected_ownership_and_acl(
        _paths(tmp_path),
        system_name="Darwin",
        expected_posix_uid=os.getuid(),
        macos_surfaces=_macos_surfaces(tmp_path),
    )

    assert result.reason_code == "ownership_acl_probe_failed"


def test_macos_acl_verification_detects_final_same_type_swap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "service.plist"
    target.write_text("first")
    target.chmod(0o644)
    tmp_path.chmod(0o755)
    real_lstat = Path.lstat
    target_calls = 0

    def swap_before_final(path: Path) -> os.stat_result:
        nonlocal target_calls
        metadata = real_lstat(path)
        if path == target:
            target_calls += 1
            if target_calls == 4:
                values = list(metadata)
                values[1] += 1
                return os.stat_result(values)
        return metadata

    monkeypatch.setattr(Path, "lstat", swap_before_final)
    monkeypatch.setattr(acl, "_macos_acl_is_mutable", lambda _path: False)

    result = acl.verify_protected_ownership_and_acl(
        _paths(tmp_path),
        system_name="Darwin",
        expected_posix_uid=os.getuid(),
        macos_surfaces=(acl._PathSurface("serviceRegistration", target, False, tmp_path),),
    )

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

    payload = acl._windows_surface_payload(mixed_case_paths)
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
        for item in acl._windows_surface_payload(_windows_paths())
    ]


def test_windows_acl_verification_uses_sid_rights_and_accepts_read_only_users(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths: _windows_rows())

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
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths: rows)

    result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert result.reason_code == reason


def test_windows_acl_verification_rejects_standard_user_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = _windows_rows()
    runtime_name = next(
        item["name"]
        for item in acl._windows_surface_payload(_windows_paths())
        if item["kind"] == "filesystem" and item["leaf"] is True and item["expectedContainer"] is True
    )
    runtime_row = next(row for row in rows if row["Name"] == runtime_name)
    rules = runtime_row["Rules"]
    assert isinstance(rules, list)
    assert isinstance(rules[0], dict)
    rules[0]["Rights"] = 2
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths: rows)

    result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert result.reason_code == "ownership_acl_standard_user_writable"


@pytest.mark.parametrize("rights", [0x40000000, 0x10000000])
@pytest.mark.parametrize("leaf", [False, True])
def test_windows_acl_verification_rejects_generic_mutation_bits(
    monkeypatch: pytest.MonkeyPatch, rights: int, leaf: bool
) -> None:
    rows = _windows_rows()
    payload = acl._windows_surface_payload(_windows_paths())
    target_name = next(item["name"] for item in payload if item["kind"] == "filesystem" and item["leaf"] is leaf)
    row = next(item for item in rows if item["Name"] == target_name)
    rules = row["Rules"]
    assert isinstance(rules, list)
    assert isinstance(rules[0], dict)
    rules[0]["Rights"] = rights
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths: rows)

    result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert result.reason_code == "ownership_acl_standard_user_writable"


@pytest.mark.parametrize(
    ("kind", "path", "rights"),
    [("filesystem", r"C:\ProgramData", 64), ("registry", r"HKLM:\Software", 65_536)],
)
def test_windows_acl_verification_rejects_mutable_ancestor(
    monkeypatch: pytest.MonkeyPatch, kind: str, path: str, rights: int
) -> None:
    rows = _windows_rows()
    payload = acl._windows_surface_payload(_windows_paths())
    target_name = next(item["name"] for item in payload if item["kind"] == kind and item["path"] == path)
    row = next(item for item in rows if item["Name"] == target_name)
    rules = row["Rules"]
    assert isinstance(rules, list)
    assert isinstance(rules[0], dict)
    rules[0]["Rights"] = rights
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths: rows)

    result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert result.reason_code == "ownership_acl_standard_user_writable"


@pytest.mark.parametrize(
    ("kind", "path", "rights"),
    [("filesystem", "C:\\", 4), ("registry", r"HKLM:\Software", 4)],
)
def test_windows_acl_verification_allows_nonreplacement_ancestor_creation(
    monkeypatch: pytest.MonkeyPatch, kind: str, path: str, rights: int
) -> None:
    rows = _windows_rows()
    payload = acl._windows_surface_payload(_windows_paths())
    target_name = next(item["name"] for item in payload if item["kind"] == kind and item["path"] == path)
    row = next(item for item in rows if item["Name"] == target_name)
    rules = row["Rules"]
    assert isinstance(rules, list)
    assert isinstance(rules[0], dict)
    rules[0]["Rights"] = rights
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths: rows)

    result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert result.healthy


@pytest.mark.skipif(os.name != "nt", reason="requires a Windows MDM installation")
def test_windows_installed_tree_and_default_ancestors_have_safe_acls() -> None:
    paths = _windows_paths()
    if not paths.runtime_root.exists():
        pytest.skip("HOL Guard MDM runtime is not installed")

    raw = acl._run_windows_acl_probe(paths)
    rows = raw if isinstance(raw, list) else [raw]
    payload = acl._windows_surface_payload(paths)
    required_paths = {
        str(paths.runtime_root).casefold(),
        str(paths.manifest_path).casefold(),
        str(paths.state_root).casefold(),
        str(paths.log_root).casefold(),
    }
    required_names = {item["name"] for item in payload if str(item["path"]).casefold() in required_paths}
    row_results = [(row, acl._windows_result(row)) for row in rows]
    results = {result.name: result for _, result in row_results}

    assert required_names <= results.keys()
    assert all(results[name].healthy for name in required_names)
    assert all(result.healthy for row, result in row_results if isinstance(row, dict) and row.get("Exists") is True)


def test_windows_acl_verification_ignores_inherit_only_non_owner_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = _windows_rows()
    rules = rows[0]["Rules"]
    assert isinstance(rules, list)
    assert isinstance(rules[0], dict)
    rules[0]["Rights"] = 983_551
    rules[0]["Propagation"] = "InheritOnly"
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths: rows)

    result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert result.healthy


def test_windows_acl_verification_rejects_malformed_or_duplicate_probe_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    malformed = _windows_rows()
    rules = malformed[0]["Rules"]
    assert isinstance(rules, list)
    assert isinstance(rules[0], dict)
    rules[0]["Rights"] = "Write"
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths: malformed)
    malformed_result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    duplicate = _windows_rows()
    duplicate.append(dict(duplicate[0]))
    monkeypatch.setattr(acl, "_run_windows_acl_probe", lambda _paths: duplicate)
    duplicate_result = acl.verify_protected_ownership_and_acl(_windows_paths(), system_name="Windows")

    assert malformed_result.reason_code == "ownership_acl_probe_failed"
    assert duplicate_result.reason_code == "ownership_acl_probe_failed"


def test_windows_acl_probe_uses_pinned_powershell_and_encoded_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Mock(return_value=subprocess.CompletedProcess(["powershell"], 0, json.dumps(_windows_rows()), ""))
    monkeypatch.setattr(acl, "_windows_directory", lambda: r"D:\Windows")
    monkeypatch.setattr(acl.subprocess, "run", run)

    acl._run_windows_acl_probe(_windows_paths())

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
