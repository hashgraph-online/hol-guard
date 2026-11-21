"""``hol-guard telemetry plugins``: argument parsing and rendering.

The native ``plugin-telemetry-host`` command owns consent, the device key and
the weekly report; its behaviour is tested in the Rust crate. These cases pin
what the CLI asks the host for and how it prints the answer.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard.plugin_telemetry import cli as telemetry_cli
from codex_plugin_scanner.guard.plugin_telemetry import host as telemetry_host


class FakeHost:
    def __init__(self, answers: dict[str, dict[str, Any] | str]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, Path, dict[str, object]]] = []

    def __call__(self, command: str, guard_home: Path, **fields: object) -> dict[str, Any]:
        self.calls.append((command, guard_home, fields))
        answer = self.answers[command]
        if isinstance(answer, str):
            raise telemetry_host.PluginTelemetryError(answer)
        return answer


@pytest.fixture
def guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "guard-home"
    monkeypatch.setattr(telemetry_cli, "resolve_guard_home", lambda override=None: home)
    monkeypatch.setattr(telemetry_cli, "user_home", lambda: "/home/someone")
    return home


def _host(monkeypatch: pytest.MonkeyPatch, **answers: dict[str, Any] | str) -> FakeHost:
    fake = FakeHost({command.replace("_", "-"): answer for command, answer in answers.items()})
    monkeypatch.setattr(telemetry_cli, "host_request", fake)
    return fake


def _run(argv: list[str]) -> tuple[int, str, str]:
    output = io.StringIO()
    error = io.StringIO()
    original_argv = guard_cli.sys.argv
    try:
        guard_cli.sys.argv = ["hol-guard"]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            exit_code = guard_cli.main(argv)
    finally:
        guard_cli.sys.argv = original_argv
    return exit_code, output.getvalue(), error.getvalue()


def test_on_off_and_status_ask_the_native_host(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host = _host(
        monkeypatch,
        on={"enabled": True},
        off={"enabled": False},
        status={"enabled": True, "lastWeek": "2026-W43"},
    )
    exit_code, output, _ = _run(["telemetry", "plugins", "on"])
    assert exit_code == 0
    assert output.startswith("Plugin install counts are on.")
    assert telemetry_host.PRIVACY_URL in output
    assert _run(["telemetry", "plugins", "status"])[1].strip() == ("Plugin install counts: on. Last report: 2026-W43.")
    exit_code, output, _ = _run(["telemetry", "plugins", "status", "--json"])
    assert json.loads(output) == {"enabled": True, "lastWeek": "2026-W43"}
    assert _run(["telemetry", "plugins", "off", "--json"])[1].strip() == '{\n  "enabled": false\n}'
    assert [(command, home, fields) for command, home, fields in host.calls] == [
        ("on", guard_home, {}),
        ("status", guard_home, {}),
        ("status", guard_home, {}),
        ("off", guard_home, {}),
    ]


def test_status_before_any_report_says_never(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _host(monkeypatch, status={"enabled": False, "lastWeek": None})
    assert _run(["telemetry", "plugins", "status"])[1].strip() == "Plugin install counts: off. Last report: never."


def test_send_passes_the_user_home_and_prints_the_counts(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host = _host(monkeypatch, send={"week": "2026-W43", "installed": 2, "listed": 1, "accepted": 1})
    exit_code, output, error = _run(["telemetry", "plugins", "send"])
    assert (exit_code, error) == (0, "")
    assert output.strip() == "Sent 1 listed plugins for 2026-W43 (1 accepted)."
    assert host.calls == [("send", guard_home, {"home": "/home/someone"})]


def test_dry_run_prints_the_report(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report = {"schema": "s", "week": "2026-W43", "guardVersion": "1", "entries": [{"slug": "acme/notes-kit"}]}
    host = _host(monkeypatch, dry_run={"report": report, "installed": 2})
    exit_code, output, _ = _run(["telemetry", "plugins", "send", "--dry-run"])
    assert exit_code == 0
    printed, summary = output.split("\n\n")
    assert json.loads(printed) == report
    assert summary.strip() == "2 plugins installed; the report above lists the HOL listings."
    assert host.calls == [("dry-run", guard_home, {"home": "/home/someone"})]


def test_a_host_refusal_prints_its_message(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _host(monkeypatch, send="Plugin install counts are off. Run: hol-guard telemetry plugins on")
    exit_code, output, error = _run(["telemetry", "plugins", "send"])
    assert (exit_code, output) == (2, "")
    assert error.strip() == "Error: Plugin install counts are off. Run: hol-guard telemetry plugins on"


def test_an_old_native_runtime_is_reported(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    class Status:
        available = False
        compatible = False
        identity = None
        capabilities = None

    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: Status())
    exit_code, _, error = _run(["telemetry", "plugins", "status"])
    assert exit_code == 2
    assert "needs a newer Guard native runtime" in error
