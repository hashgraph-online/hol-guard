from __future__ import annotations

import json
import plistlib
import subprocess
from pathlib import Path
from unittest.mock import Mock
from xml.etree import ElementTree

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_dispatch_mdm
from codex_plugin_scanner.guard.mdm import supervisor
from codex_plugin_scanner.guard.mdm.contracts import MachinePaths, default_machine_paths


def _paths(root: Path) -> MachinePaths:
    return MachinePaths(
        runtime_root=root / "runtime",
        state_root=root / "state",
        policy_path=root / "policy.json",
        log_root=root / "logs",
        manifest_path=root / "runtime" / "release-manifest.json",
    )


def _macos_plist(tmp_path: Path, mutate: object | None = None) -> Path:
    payload = plistlib.loads(Path("scripts/mdm/macos/org.hol.guard.machine-health.plist").read_bytes())
    if callable(mutate):
        mutate(payload)
    target = tmp_path / "org.hol.guard.machine-health.plist"
    target.write_bytes(plistlib.dumps(payload))
    return target


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(["native"], returncode, stdout, stderr)


def _launchctl_print(paths: MachinePaths) -> str:
    executable = paths.runtime_root / "hol-guard" / "hol-guard"
    return f"""system/org.hol.guard.machine-health = {{
    path = /Library/LaunchDaemons/org.hol.guard.machine-health.plist
    state = running
    program = {executable}
    arguments = {{
        {executable}
        mdm
        integrity-snapshot
        --scope
        machine
        --json
    }}
    run interval = 300 seconds
}}"""


def test_macos_supervisor_accepts_exact_loaded_registration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = default_machine_paths(system_name="Darwin")
    run = Mock(
        side_effect=[
            _completed(stdout='disabled services = { "other" => true }'),
            _completed(stdout=_launchctl_print(paths)),
        ]
    )
    monkeypatch.setattr(supervisor, "_run_macos_launchctl", run)

    result = supervisor.verify_machine_supervisor(
        paths,
        system_name="Darwin",
        macos_plist_path=_macos_plist(tmp_path),
    )

    assert result.healthy
    assert result.reason_code == "supervisor_running"
    assert run.call_args_list[0].args == ("print-disabled", "system")
    assert run.call_args_list[1].args == ("print", "system/org.hol.guard.machine-health")


@pytest.mark.parametrize(
    ("old", "new", "reason"),
    [
        (
            "program = /Library/Application Support/HOL Guard/hol-guard/hol-guard",
            "program = /tmp/evil",
            "supervisor_executable_mismatch",
        ),
        ("        --json", "        --version", "supervisor_executable_mismatch"),
        ("run interval = 300 seconds", "run interval = 3600 seconds", "supervisor_schedule_invalid"),
        ("state = running", "state = waiting", "supervisor_stopped"),
        (
            "path = /Library/LaunchDaemons/org.hol.guard.machine-health.plist",
            "path = /tmp/evil.plist",
            "supervisor_registration_invalid",
        ),
    ],
)
def test_macos_supervisor_rejects_modified_loaded_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, old: str, new: str, reason: str
) -> None:
    paths = default_machine_paths(system_name="Darwin")
    loaded = _launchctl_print(paths).replace(old, new, 1)
    monkeypatch.setattr(
        supervisor,
        "_run_macos_launchctl",
        Mock(side_effect=[_completed(stdout="disabled services = {}"), _completed(stdout=loaded)]),
    )

    result = supervisor.verify_machine_supervisor(paths, system_name="Darwin", macos_plist_path=_macos_plist(tmp_path))

    assert result.reason_code == reason


def test_macos_supervisor_accepts_idle_loaded_job(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = default_machine_paths(system_name="Darwin")
    loaded = _launchctl_print(paths).replace("state = running", "state = not running")
    monkeypatch.setattr(
        supervisor,
        "_run_macos_launchctl",
        Mock(side_effect=[_completed(stdout="disabled services = {}"), _completed(stdout=loaded)]),
    )

    result = supervisor.verify_machine_supervisor(paths, system_name="Darwin", macos_plist_path=_macos_plist(tmp_path))

    assert result.reason_code == "supervisor_running"


def test_macos_supervisor_reports_absent_without_invoking_launchctl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = Mock()
    monkeypatch.setattr(supervisor, "_run_macos_launchctl", run)

    result = supervisor.verify_machine_supervisor(
        default_machine_paths(system_name="Darwin"),
        system_name="Darwin",
        macos_plist_path=tmp_path / "missing.plist",
    )

    assert result.state == "absent"
    assert result.reason_code == "supervisor_absent"
    run.assert_not_called()


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (
            lambda payload: payload["ProgramArguments"].__setitem__(0, "/tmp/hol-guard"),
            "supervisor_executable_mismatch",
        ),
        (lambda payload: payload.__setitem__("StartInterval", 3600), "supervisor_schedule_invalid"),
        (
            lambda payload: payload.__setitem__("EnvironmentVariables", {"PATH": "/tmp"}),
            "supervisor_registration_invalid",
        ),
    ],
)
def test_macos_supervisor_rejects_modified_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate: object,
    reason: str,
) -> None:
    run = Mock()
    monkeypatch.setattr(supervisor, "_run_macos_launchctl", run)

    result = supervisor.verify_machine_supervisor(
        default_machine_paths(system_name="Darwin"),
        system_name="Darwin",
        macos_plist_path=_macos_plist(tmp_path, mutate),
    )

    assert result.reason_code == reason
    run.assert_not_called()


def test_macos_supervisor_distinguishes_disabled_and_stopped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = default_machine_paths(system_name="Darwin")
    plist_path = _macos_plist(tmp_path)
    monkeypatch.setattr(
        supervisor,
        "_run_macos_launchctl",
        Mock(return_value=_completed(stdout='"org.hol.guard.machine-health" => true')),
    )
    disabled = supervisor.verify_machine_supervisor(paths, system_name="Darwin", macos_plist_path=plist_path)

    monkeypatch.setattr(
        supervisor,
        "_run_macos_launchctl",
        Mock(side_effect=[_completed(stdout="disabled services = {}"), _completed(returncode=113)]),
    )
    stopped = supervisor.verify_machine_supervisor(paths, system_name="Darwin", macos_plist_path=plist_path)

    assert disabled.reason_code == "supervisor_disabled"
    assert stopped.reason_code == "supervisor_stopped"


def _windows_xml(paths: MachinePaths) -> str:
    return supervisor._windows_task_xml(paths).decode("utf-16")


def _mutate_windows_xml(xml_text: str, path: str, value: str) -> str:
    root = ElementTree.fromstring(xml_text)
    element = root.find(path, {"task": supervisor._TASK_NAMESPACE})
    assert element is not None
    element.text = value
    return ElementTree.tostring(root, encoding="unicode")


def test_windows_supervisor_accepts_exact_system_task(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = default_machine_paths(system_name="Windows")
    xml_text = _windows_xml(paths)
    root = ElementTree.fromstring(xml_text)
    trigger = root.find("./task:Triggers/task:TimeTrigger", {"task": supervisor._TASK_NAMESPACE})
    assert trigger is not None
    assert [element.tag.rsplit("}", 1)[-1] for element in trigger] == ["Enabled", "StartBoundary", "Repetition"]
    run = Mock(return_value=_completed(stdout=xml_text))
    monkeypatch.setattr(supervisor, "_run_schtasks", run)

    result = supervisor.verify_machine_supervisor(paths, system_name="Windows")

    assert result.healthy
    assert result.reason_code == "supervisor_running"
    assert run.call_args.args == ("/Query", "/TN", r"\HOL Guard\Machine Health", "/XML", "/HRESULT")


@pytest.mark.parametrize(
    ("path", "value", "reason"),
    [
        ("./task:Settings/task:Enabled", "false", "supervisor_disabled"),
        ("./task:Actions/task:Exec/task:Command", r"C:\Users\attacker\hol-guard.exe", "supervisor_executable_mismatch"),
        ("./task:Principals/task:Principal/task:UserId", "S-1-5-32-545", "supervisor_registration_invalid"),
        ("./task:Triggers/*/task:Repetition/task:Interval", "PT1H", "supervisor_schedule_invalid"),
        ("./task:Triggers/*/task:Repetition/task:StopAtDurationEnd", "true", "supervisor_schedule_invalid"),
        ("./task:Triggers/*/task:StartBoundary", "2999-01-01T00:00:00", "supervisor_schedule_invalid"),
        ("./task:RegistrationInfo/task:SecurityDescriptor", "D:(A;;FA;;;WD)", "supervisor_registration_invalid"),
        ("./task:Settings/task:Hidden", "false", "supervisor_schedule_invalid"),
    ],
)
def test_windows_supervisor_rejects_modified_task(
    monkeypatch: pytest.MonkeyPatch, path: str, value: str, reason: str
) -> None:
    paths = default_machine_paths(system_name="Windows")
    xml_text = _mutate_windows_xml(_windows_xml(paths), path, value)
    monkeypatch.setattr(supervisor, "_run_schtasks", Mock(return_value=_completed(stdout=xml_text)))

    result = supervisor.verify_machine_supervisor(paths, system_name="Windows")

    assert result.reason_code == reason


def test_windows_supervisor_accepts_canonicalized_protected_sddl(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = default_machine_paths(system_name="Windows")
    xml_text = _mutate_windows_xml(
        _windows_xml(paths),
        "./task:RegistrationInfo/task:SecurityDescriptor",
        "O:S-1-5-32-544G:S-1-5-18D:P(A;;FA;;;S-1-5-32-544)(A;;FA;;;S-1-5-18)",
    )
    monkeypatch.setattr(supervisor, "_run_schtasks", Mock(return_value=_completed(stdout=xml_text)))

    result = supervisor.verify_machine_supervisor(paths, system_name="Windows")

    assert result.reason_code == "supervisor_running"


def test_windows_supervisor_rejects_wrong_trigger_and_action_context(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = default_machine_paths(system_name="Windows")
    root = ElementTree.fromstring(_windows_xml(paths))
    namespace = {"task": supervisor._TASK_NAMESPACE}
    trigger = root.find("./task:Triggers/task:TimeTrigger", namespace)
    actions = root.find("./task:Actions", namespace)
    assert trigger is not None and actions is not None
    trigger.tag = f"{{{supervisor._TASK_NAMESPACE}}}CalendarTrigger"
    actions.set("Context", "InteractiveUsers")
    monkeypatch.setattr(
        supervisor,
        "_run_schtasks",
        Mock(return_value=_completed(stdout=ElementTree.tostring(root, encoding="unicode"))),
    )

    result = supervisor.verify_machine_supervisor(paths, system_name="Windows")

    assert result.reason_code == "supervisor_schedule_invalid"

    root = ElementTree.fromstring(_windows_xml(paths))
    actions = root.find("./task:Actions", namespace)
    assert actions is not None
    actions.set("Context", "InteractiveUsers")
    monkeypatch.setattr(
        supervisor,
        "_run_schtasks",
        Mock(return_value=_completed(stdout=ElementTree.tostring(root, encoding="unicode"))),
    )

    result = supervisor.verify_machine_supervisor(paths, system_name="Windows")

    assert result.reason_code == "supervisor_registration_invalid"


def test_windows_supervisor_distinguishes_absence_from_probe_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    paths = default_machine_paths(system_name="Windows")
    monkeypatch.setattr(supervisor, "_run_schtasks", Mock(return_value=_completed(returncode=0x80070002)))
    absent = supervisor.verify_machine_supervisor(paths, system_name="Windows")

    monkeypatch.setattr(supervisor, "_run_schtasks", Mock(return_value=_completed(returncode=5)))
    unknown = supervisor.verify_machine_supervisor(paths, system_name="Windows")

    assert absent.reason_code == "supervisor_absent"
    assert unknown.reason_code == "supervisor_probe_failed"


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
