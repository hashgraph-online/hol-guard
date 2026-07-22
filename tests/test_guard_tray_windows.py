"""Tests for the Windows tray platform adapter (Task Scheduler).

The Windows adapter uses a per-user Task Scheduler task (not a Run-key
registry entry) with ``pythonw.exe`` (no console flash), bounded
restart-on-failure, and least-privilege execution.

Since we're on macOS, all Windows-specific calls are mocked.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from codex_plugin_scanner.guard.tray.platforms.windows import (
    TASK_NAME,
    WindowsTrayAdapter,
    _build_task_xml,
    _pythonw_path,
)


def _mock_schtasks_result(
    *,
    returncode: int = 0,
    stdout: str = "",
    stderr: str = "",
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["schtasks.exe"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


OWNED_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions>
    <Exec>
      <Command>C:\\Python\\pythonw.exe</Command>
      <Arguments>-m codex_plugin_scanner.guard.cli guard tray run --guard-home C:\\Users\\test\\.guard</Arguments>
    </Exec>
  </Actions>
</Task>"""

FOREIGN_TASK_XML = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Actions>
    <Exec>
      <Command>C:\\SomeOther\\app.exe</Command>
      <Arguments>--tray</Arguments>
    </Exec>
  </Actions>
</Task>"""


class TestWindowsAdapterPlatform:
    def test_platform_returns_windows(self) -> None:
        assert WindowsTrayAdapter().platform.value == "windows"


class TestPythonwPath:
    def test_returns_pythonw_when_exists(self) -> None:
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=True):
            assert "pythonw.exe" in _pythonw_path()

    def test_falls_back_to_sys_executable(self) -> None:
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=False):
            assert _pythonw_path() == "/fake/python.exe"

    def test_returns_sys_executable_when_already_pythonw(self) -> None:
        with patch("sys.executable", "/fake/pythonw.exe"):
            assert _pythonw_path() == "/fake/pythonw.exe"


class TestBuildTaskXml:
    def test_xml_contains_pythonw_executable(self, tmp_path: Path) -> None:
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=True):
            assert "pythonw.exe" in _build_task_xml(tmp_path)

    def test_xml_contains_guard_home(self, tmp_path: Path) -> None:
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=True):
            assert str(tmp_path) in _build_task_xml(tmp_path)

    def test_xml_contains_codex_plugin_scanner(self, tmp_path: Path) -> None:
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=True):
            assert "codex_plugin_scanner" in _build_task_xml(tmp_path)

    def test_xml_has_logon_trigger(self, tmp_path: Path) -> None:
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=True):
            assert "LogonTrigger" in _build_task_xml(tmp_path)

    def test_xml_has_least_privilege(self, tmp_path: Path) -> None:
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=True):
            assert "LeastPrivilege" in _build_task_xml(tmp_path)

    def test_xml_has_bounded_restart(self, tmp_path: Path) -> None:
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=True):
            xml = _build_task_xml(tmp_path)
            assert "RestartOnFailure" in xml
            assert "PT60S" in xml
            assert "<Count>3</Count>" in xml

    def test_xml_has_interactive_token(self, tmp_path: Path) -> None:
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=True):
            assert "InteractiveToken" in _build_task_xml(tmp_path)

    def test_xml_has_no_secrets(self) -> None:
        """The task XML must not contain auth tokens or secrets.

        Note: 'token' appears in 'InteractiveToken' (a Windows LogonType XML
        element) — that's not a secret. We check for actual secret patterns.
        Uses a fixed path (not tmp_path) to avoid the test name leaking
        'secret' into the guard_home path.
        """
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=True):
            xml = _build_task_xml(Path("/tmp/guard-home")).lower()
            for secret in ("auth_token", "secret", "password", "bearer", "api_key", "credential"):
                assert secret not in xml, f"Found '{secret}' in task XML"

    def test_xml_escapes_ampersand_in_path(self) -> None:
        """Paths with & must be escaped as &amp; in the XML."""
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=True):
            assert "&amp;" in _build_task_xml(Path("/tmp/a&b"))

    def test_xml_escapes_double_quote_in_path(self) -> None:
        """Paths with \" must be escaped as &quot; to avoid breaking the
        --guard-home \"...\" argument quoting on the Windows side."""
        with patch("sys.executable", "/fake/python.exe"), patch("pathlib.Path.exists", return_value=True):
            xml = _build_task_xml(Path('/tmp/a"b'))
            assert "&quot;" in xml


class TestInspectRegistration:
    def test_returns_absent_when_no_task(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch("subprocess.run", return_value=_mock_schtasks_result(returncode=1)):
            result = adapter.inspect_registration(guard_home=tmp_path)
        assert result["installed"] is False

    def test_returns_present_owned(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch("subprocess.run", return_value=_mock_schtasks_result(stdout=OWNED_TASK_XML)):
            result = adapter.inspect_registration(guard_home=tmp_path)
        assert result["installed"] is True
        assert result["owned"] is True
        assert result["task_name"] == TASK_NAME

    def test_returns_present_foreign(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch("subprocess.run", return_value=_mock_schtasks_result(stdout=FOREIGN_TASK_XML)):
            result = adapter.inspect_registration(guard_home=tmp_path)
        assert result["installed"] is True
        assert result["owned"] is False

    def test_returns_unavailable_on_filenotfound(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            result = adapter.inspect_registration(guard_home=tmp_path)
        assert result["installed"] is False
        assert result["reason"] == "schtasks_unavailable"


class TestInstallRegistration:
    def test_install_creates_task(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch(
            "subprocess.run",
            side_effect=[
                _mock_schtasks_result(returncode=1),
                _mock_schtasks_result(returncode=0),
            ],
        ):
            result = adapter.install_registration(
                guard_home=tmp_path,
                capability=adapter.detect_capability(),
            )
        assert result["installed"] is True
        assert result["task_name"] == TASK_NAME

    def test_install_refuses_foreign_collision(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch("subprocess.run", return_value=_mock_schtasks_result(stdout=FOREIGN_TASK_XML)):
            result = adapter.install_registration(
                guard_home=tmp_path,
                capability=adapter.detect_capability(),
            )
        assert result["installed"] is False
        assert result["reason"] == "startup_registration_collision"

    def test_install_overwrites_owned_task(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch(
            "subprocess.run",
            side_effect=[
                _mock_schtasks_result(stdout=OWNED_TASK_XML),
                _mock_schtasks_result(returncode=0),
            ],
        ):
            result = adapter.install_registration(
                guard_home=tmp_path,
                capability=adapter.detect_capability(),
            )
        assert result["installed"] is True

    def test_install_fails_on_schtasks_error(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch(
            "subprocess.run",
            side_effect=[
                _mock_schtasks_result(returncode=1),
                _mock_schtasks_result(returncode=1, stderr="Access denied"),
            ],
        ):
            result = adapter.install_registration(
                guard_home=tmp_path,
                capability=adapter.detect_capability(),
            )
        assert result["installed"] is False
        assert result["reason"] == "startup_registration_failed"


class TestRemoveRegistration:
    def test_remove_owned_task(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch(
            "subprocess.run",
            side_effect=[
                _mock_schtasks_result(stdout=OWNED_TASK_XML),
                _mock_schtasks_result(returncode=0),
            ],
        ):
            result = adapter.remove_registration(guard_home=tmp_path)
        assert result["removed"] is True

    def test_remove_when_absent_is_idempotent(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch("subprocess.run", return_value=_mock_schtasks_result(returncode=1)):
            result = adapter.remove_registration(guard_home=tmp_path)
        assert result["removed"] is False
        assert result["reason"] == "not_installed"

    def test_remove_refuses_foreign_task(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch("subprocess.run", return_value=_mock_schtasks_result(stdout=FOREIGN_TASK_XML)):
            result = adapter.remove_registration(guard_home=tmp_path)
        assert result["removed"] is False
        assert result["reason"] == "startup_registration_collision"


class TestStartProcess:
    def test_start_uses_pythonw(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        mock_proc = type("P", (), {"pid": 12345})()
        with (
            patch("sys.executable", "/fake/python.exe"),
            patch("pathlib.Path.exists", return_value=True),
            patch("subprocess.Popen", return_value=mock_proc) as mock_popen,
        ):
            result = adapter.start_process(
                guard_home=tmp_path,
                capability=adapter.detect_capability(),
            )
        assert result["started"] is True
        assert result["pid"] == 12345
        assert "pythonw.exe" in mock_popen.call_args[0][0][0]

    def test_start_returns_error_on_oserror(self, tmp_path: Path) -> None:
        adapter = WindowsTrayAdapter()
        with patch("subprocess.Popen", side_effect=OSError("spawn failed")):
            result = adapter.start_process(
                guard_home=tmp_path,
                capability=adapter.detect_capability(),
            )
        assert result["started"] is False
        assert result["reason"] == "internal_error"


class TestStopProcess:
    def test_stop_kills_by_pid(self) -> None:
        adapter = WindowsTrayAdapter()
        with patch("subprocess.run", return_value=_mock_schtasks_result(returncode=0)):
            assert adapter.stop_process(pid=12345)["stopped"] is True

    def test_stop_returns_not_running_for_zero_pid(self) -> None:
        adapter = WindowsTrayAdapter()
        result = adapter.stop_process(pid=0)
        assert result["stopped"] is False
        assert result["reason"] == "not_running"
