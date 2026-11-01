from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.cli import commands_dispatch_mdm
from codex_plugin_scanner.guard.mdm import supervisor
from codex_plugin_scanner.guard.mdm.contracts import MachinePaths


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(
        runtime_root=root / "runtime",
        state_root=root / "state",
        policy_path=root / "policy.json",
        log_root=root / "logs",
        manifest_path=root / "runtime" / "release-manifest.json",
    )


def _native_runtime(
    monkeypatch: pytest.MonkeyPatch,
    output: str | None,
    features: frozenset[str] = frozenset({supervisor.SUPERVISOR_VERDICT_FEATURE, supervisor.SUPERVISOR_PROBE_FEATURE}),
) -> Mock:
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("hol-guard-native")),
        capabilities=SimpleNamespace(features=features),
    )
    process = Mock(return_value=output)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **_kwargs: status)
    monkeypatch.setattr(native_runtime, "_run_native_process", process)
    return process


def _sent(process: Mock) -> dict[str, object]:
    assert process.call_args.args[1] == ("supervisor-verdict", "--stdin")
    return json.loads(process.call_args.kwargs["input_text"])


def test_macos_supervisor_asks_the_runtime_to_read_and_probe_the_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    plist_file = tmp_path / "org.hol.guard.machine-health.plist"
    process = _native_runtime(monkeypatch, '{"ok": true, "state": "running", "reason_code": "supervisor_running"}')

    result = supervisor.verify_machine_supervisor(paths, system_name="Darwin", macos_plist_path=plist_file)

    assert (result.state, result.reason_code) == ("running", "supervisor_running")
    assert _sent(process) == {
        "schema": "supervisor-verdict.v1",
        "op": "macos-verify",
        "executable": str(paths.runtime_root / "hol-guard" / "hol-guard"),
        "plist_file": str(plist_file),
        "plist_path": "/Library/LaunchDaemons/org.hol.guard.machine-health.plist",
        "stdout_log": str(paths.log_root / "machine-health.log"),
        "stderr_log": str(paths.log_root / "machine-health-error.log"),
    }


def test_windows_supervisor_asks_the_runtime_to_query_the_task(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = _paths(tmp_path)
    process = _native_runtime(monkeypatch, '{"ok": true, "state": "absent", "reason_code": "supervisor_absent"}')
    monkeypatch.setattr(supervisor, "_windows_directory", lambda: r"D:\Windows")
    run = Mock(side_effect=AssertionError("Python ran schtasks"))
    monkeypatch.setattr(supervisor.subprocess, "run", run)

    result = supervisor.verify_machine_supervisor(paths, system_name="Windows")

    assert (result.state, result.reason_code) == ("absent", "supervisor_absent")
    assert _sent(process) == {
        "schema": "supervisor-verdict.v1",
        "op": "windows-verify",
        "executable": str(paths.runtime_root / "hol-guard" / "hol-guard.exe"),
        "windows_directory": r"D:\Windows",
    }
    run.assert_not_called()


_TASK_FEATURES = frozenset({supervisor.SUPERVISOR_VERDICT_FEATURE, supervisor.SUPERVISOR_INSTALL_FEATURE})


def _windows_installer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MachinePaths:
    paths = _paths(tmp_path)
    monkeypatch.setattr(supervisor.platform, "system", lambda: "Windows")
    monkeypatch.setattr(supervisor, "_windows_is_administrator", lambda: True)
    monkeypatch.setattr(supervisor, "default_machine_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(supervisor, "_windows_directory", lambda: r"D:\Windows")
    return paths


def test_windows_supervisor_install_asks_the_runtime_to_register_the_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _windows_installer(tmp_path, monkeypatch)
    process = _native_runtime(
        monkeypatch, '{"ok": true, "state": "running", "reason_code": "supervisor_running"}', _TASK_FEATURES
    )
    run = Mock()
    monkeypatch.setattr(supervisor.subprocess, "run", run)

    result = supervisor.install_machine_supervisor()

    assert result["healthy"] is True
    assert result["reasonCodes"] == ["supervisor_running"]
    assert _sent(process) == {
        "schema": "supervisor-verdict.v1",
        "op": "windows-install",
        "executable": str(paths.runtime_root / "hol-guard" / "hol-guard.exe"),
        "windows_directory": r"D:\Windows",
        "state_root": str(paths.state_root),
    }
    run.assert_not_called()


def test_windows_supervisor_remove_asks_the_runtime_to_delete_the_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _windows_installer(tmp_path, monkeypatch)
    process = _native_runtime(monkeypatch, '{"ok": true, "state": "absent"}', _TASK_FEATURES)

    result = supervisor.remove_machine_supervisor()

    assert (result["operation"], result["state"]) == ("supervisor-remove", "absent")
    assert _sent(process) == {
        "schema": "supervisor-verdict.v1",
        "op": "windows-remove",
        "executable": str(paths.runtime_root / "hol-guard" / "hol-guard.exe"),
        "windows_directory": r"D:\Windows",
    }


@pytest.mark.parametrize(
    ("output", "error"),
    [
        ('{"ok": false, "error": "supervisor_runtime_absent"}', "supervisor_runtime_absent"),
        ('{"ok": false, "error": "supervisor_registration_failed"}', "supervisor_registration_failed"),
        ('{"ok": false, "error": "something_else"}', "supervisor_verdict_native_unavailable"),
        ('{"ok": false, "error": ["supervisor_runtime_absent"]}', "supervisor_verdict_native_unavailable"),
        ('{"ok": true, "state": "absent"}', "supervisor_verdict_native_unavailable"),
        ("not json", "supervisor_verdict_native_unavailable"),
        (None, "supervisor_verdict_native_unavailable"),
    ],
)
def test_windows_supervisor_install_reports_why_the_runtime_could_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str | None, error: str
) -> None:
    _ = _windows_installer(tmp_path, monkeypatch)
    _ = _native_runtime(monkeypatch, output, _TASK_FEATURES)

    with pytest.raises(OSError, match=f"^{error}$"):
        _ = supervisor.install_machine_supervisor()


@pytest.mark.parametrize("operation", ["install_machine_supervisor", "remove_machine_supervisor"])
def test_windows_task_changes_need_a_runtime_that_installs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    _ = _windows_installer(tmp_path, monkeypatch)
    process = _native_runtime(monkeypatch, '{"ok": true, "state": "running"}')

    with pytest.raises(OSError, match=r"^supervisor_verdict_native_unavailable$"):
        _ = getattr(supervisor, operation)()
    process.assert_not_called()


@pytest.mark.parametrize("operation", ["install_machine_supervisor", "remove_machine_supervisor"])
def test_windows_task_changes_need_an_administrator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    _ = _windows_installer(tmp_path, monkeypatch)
    monkeypatch.setattr(supervisor, "_windows_is_administrator", lambda: False)
    process = _native_runtime(monkeypatch, None, _TASK_FEATURES)

    with pytest.raises(PermissionError, match=r"^supervisor_administrator_required$"):
        _ = getattr(supervisor, operation)()
    process.assert_not_called()


def test_supervisor_cli_dispatches_installer_only_commands(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    expected = {
        "schemaVersion": "hol-guard-mdm-status.v1",
        "operation": "supervisor-install",
        "healthy": True,
        "state": "running",
        "reasonCodes": ["supervisor_running"],
    }
    monkeypatch.setattr(commands_dispatch_mdm, "install_machine_supervisor", lambda: expected)

    exit_code = cli.main(["mdm", "supervisor-install", "--json"])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == expected


def test_unsupported_platform_never_reports_supervisor_health(tmp_path: Path) -> None:
    result = supervisor.verify_machine_supervisor(_paths(tmp_path), system_name="Linux")

    assert not result.healthy
    assert result.reason_code == "supervisor_platform_unsupported"


@pytest.mark.parametrize("system_name", ["Darwin", "Windows"])
@pytest.mark.parametrize(
    "features",
    [frozenset(), frozenset({supervisor.SUPERVISOR_VERDICT_FEATURE})],
)
def test_supervisor_health_is_unknown_without_a_runtime_that_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, system_name: str, features: frozenset[str]
) -> None:
    process = _native_runtime(
        monkeypatch, '{"ok": true, "state": "running", "reason_code": "supervisor_running"}', features
    )
    monkeypatch.setattr(supervisor, "_windows_directory", lambda: r"C:\Windows")

    result = supervisor.verify_machine_supervisor(
        _paths(tmp_path),
        system_name=system_name,
        macos_plist_path=tmp_path / "org.hol.guard.machine-health.plist",
    )

    assert (result.state, result.reason_code) == ("unknown", "supervisor_probe_failed")
    process.assert_not_called()


def test_an_unreadable_windows_directory_is_a_failed_probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable() -> str:
        raise OSError("windows_directory_unavailable")

    process = _native_runtime(monkeypatch, None)
    monkeypatch.setattr(supervisor, "_windows_directory", unavailable)

    result = supervisor.verify_machine_supervisor(_paths(tmp_path), system_name="Windows")

    assert (result.state, result.reason_code) == ("unknown", "supervisor_probe_failed")
    process.assert_not_called()


@pytest.mark.parametrize(
    "output",
    [
        None,
        "",
        "not json",
        '{"ok": false, "error": "supervisor_verdict_request_invalid"}',
        '{"ok": true, "state": "healthy", "reason_code": "supervisor_running"}',
        '{"ok": true, "state": "running", "reason_code": "supervisor_fine"}',
        '{"ok": true, "next": "disabled"}',
    ],
)
def test_a_malformed_native_verdict_is_a_failed_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, output: str | None
) -> None:
    _ = _native_runtime(monkeypatch, output)

    result = supervisor.verify_machine_supervisor(
        _paths(tmp_path),
        system_name="Darwin",
        macos_plist_path=tmp_path / "org.hol.guard.machine-health.plist",
    )

    assert (result.state, result.reason_code) == ("unknown", "supervisor_probe_failed")
