from __future__ import annotations

import json
import subprocess
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


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["native"], returncode, stdout, stderr)


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


def test_windows_probe_uses_pinned_schtasks_and_bounded_context(monkeypatch: pytest.MonkeyPatch) -> None:
    run = Mock(return_value=_completed(stdout="<Task />"))
    monkeypatch.setattr(supervisor, "_windows_directory", lambda: r"D:\Windows")
    monkeypatch.setattr(supervisor.subprocess, "run", run)

    supervisor._run_schtasks("/Query")

    command = run.call_args.args[0]
    kwargs = run.call_args.kwargs
    assert command[0] == r"D:\Windows\System32\schtasks.exe"
    assert kwargs["cwd"] == r"D:\Windows\System32"
    assert kwargs["env"] == {
        "ComSpec": r"D:\Windows\System32\cmd.exe",
        "SystemDrive": "D:",
        "SystemRoot": r"D:\Windows",
        "WINDIR": r"D:\Windows",
    }


def test_windows_supervisor_install_uses_protected_temporary_xml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    executable = paths.runtime_root / "hol-guard" / "hol-guard.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"exe")
    paths.state_root.mkdir()
    run = Mock(return_value=_completed())
    monkeypatch.setattr(supervisor.platform, "system", lambda: "Windows")
    monkeypatch.setattr(supervisor, "_windows_is_administrator", lambda: True)
    monkeypatch.setattr(supervisor, "default_machine_paths", lambda **_kwargs: paths)
    monkeypatch.setattr(supervisor, "_run_schtasks", run)

    result = supervisor.install_machine_supervisor()

    task_xml_path = Path(run.call_args.args[4])
    assert result["healthy"] is True
    assert run.call_args.args[:4] == ("/Create", "/TN", r"\HOL Guard\Machine Health", "/XML")
    assert not task_xml_path.exists()
    assert list(paths.state_root.iterdir()) == []


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
