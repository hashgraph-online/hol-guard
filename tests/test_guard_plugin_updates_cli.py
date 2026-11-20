"""``hol-guard plugin updates``: argument parsing and rendering.

The native ``plugin-telemetry-host`` command downloads the public indexes and
compares installed versions on the device; its behaviour is tested in the Rust
crates. These cases pin what the CLI asks the host for and how it prints the
answer.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard.plugin_telemetry import host as telemetry_host
from codex_plugin_scanner.guard.plugin_telemetry import updates as plugin_updates

RELEASES_URL = "https://hol.org/plugins/acme/notes-kit/releases"


def _update(latest: str, reason: str | None = None) -> dict[str, object]:
    return {
        "installedVersion": "1.2.0",
        "latestVersion": latest,
        "reason": reason,
        "releasesUrl": RELEASES_URL,
        "runtime": "claude-code",
        "slug": "acme/notes-kit",
        "urgent": reason is not None,
    }


class FakeHost:
    def __init__(self, answers: dict[str, dict[str, Any] | str]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, dict[str, object]]] = []

    def __call__(self, command: str, guard_home: Path, **fields: object) -> dict[str, Any]:
        self.calls.append((command, fields))
        answer = self.answers[command]
        if isinstance(answer, str):
            raise telemetry_host.PluginTelemetryError(answer)
        return answer


@pytest.fixture
def guard_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "guard-home"
    monkeypatch.setattr(plugin_updates, "resolve_guard_home", lambda override=None: home)
    monkeypatch.setattr(plugin_updates, "user_home", lambda: "/home/someone")
    return home


def _host(monkeypatch: pytest.MonkeyPatch, answers: dict[str, dict[str, Any] | str]) -> FakeHost:
    fake = FakeHost(answers)
    monkeypatch.setattr(plugin_updates, "host_request", fake)
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


def test_json_prints_the_host_answer(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    answer = {"dismissed": 0, "updates": [_update("1.3.0")]}
    host = _host(monkeypatch, {"updates": answer})
    exit_code, output, error = _run(["plugin", "updates", "--json"])
    assert (exit_code, error) == (0, "")
    assert json.loads(output) == answer
    assert host.calls == [("updates", {"home": "/home/someone"})]


@pytest.mark.parametrize(
    ("reason", "line"),
    [
        ("security_fix", "Urgent: a newer release fixes a high or critical finding."),
        ("installed_high_severity", "Urgent: the installed release had a high or critical finding."),
    ],
)
def test_urgent_updates_say_why(guard_home: Path, monkeypatch: pytest.MonkeyPatch, reason: str, line: str) -> None:
    _host(monkeypatch, {"updates": {"dismissed": 0, "updates": [_update("1.2.1", reason)]}})
    exit_code, output, _ = _run(["plugin", "updates"])
    assert exit_code == 0
    assert "acme/notes-kit (claude-code): 1.2.0 -> 1.2.1" in output
    assert RELEASES_URL in output
    assert line in output


def test_no_updates_names_the_dismissed_count(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _host(monkeypatch, {"updates": {"dismissed": 1, "updates": []}})
    exit_code, output, _ = _run(["plugin", "updates"])
    assert exit_code == 0
    assert "No newer checked releases" in output
    assert "1 dismissed. Run: hol-guard plugin updates reset" in output


def test_dismiss_and_reset_ask_the_host(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    host = _host(monkeypatch, {"updates-dismiss": {"dismissed": 1}, "updates-reset": {"dismissed": 0}})
    exit_code, output, _ = _run(["plugin", "updates", "dismiss", "acme/notes-kit", "--version", "1.3.0"])
    assert (exit_code, output.strip()) == (0, "Dismissed acme/notes-kit 1.3.0.")
    exit_code, output, _ = _run(["plugin", "updates", "reset", "--json"])
    assert (exit_code, json.loads(output)) == (0, {"dismissed": 0})
    assert host.calls == [
        ("updates-dismiss", {"slug": "acme/notes-kit", "version": "1.3.0"}),
        ("updates-reset", {}),
    ]


def test_a_host_refusal_prints_its_message(guard_home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _host(monkeypatch, {"updates-dismiss": "plugin_updates_dismissals_unwritable"})
    exit_code, output, error = _run(["plugin", "updates", "dismiss", "acme/notes-kit", "--version", "1.3.0"])
    assert (exit_code, output) == (2, "")
    assert "plugin_updates_dismissals_unwritable" in error
