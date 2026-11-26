"""``hol-guard browser report-prompt`` sends one request to the native runtime and prints the skeleton."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import browser_explain_command

SKELETON: dict[str, object] = {
    "driver": "browser.playwright-mcp",
    "tool": "browser_navigate",
    "verb": "navigate",
    "intent": "browser.navigate",
    "origin": {"placeholder": "https://site-a.example.test/", "loopback": False},
    "reason_codes": ["browser.first_visit"],
    "arguments": {"url": "https://site-a.example.test/"},
}


def _record(monkeypatch: pytest.MonkeyPatch, reply: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake(line: str, *, command: str = "browser-explain") -> dict[str, object]:
        sent.append((command, json.loads(line)))
        return reply

    monkeypatch.setattr(browser_explain_command, "_native_request", fake)
    return sent


def test_report_prompt_sends_the_guard_home_and_request_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent = _record(monkeypatch, {"ok": True, "skeleton": SKELETON})
    status = cli.main(["guard", "browser", "report-prompt", "req-1", "--guard-home", str(tmp_path), "--json"])
    assert status == 0
    assert sent == [("browser-report-prompt", {"guard_home": str(tmp_path.resolve()), "request_id": "req-1"})]
    assert json.loads(capsys.readouterr().out) == {"skeleton": SKELETON}


def test_report_prompt_prints_a_pasteable_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _record(monkeypatch, {"ok": True, "skeleton": SKELETON})
    assert cli.main(["guard", "browser", "report-prompt", "req-1", "--guard-home", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "```json" in out
    assert '"placeholder": "https://site-a.example.test/"' in out
    assert "Guard has not sent it anywhere." in out


def test_report_prompt_reports_native_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _record(
        monkeypatch,
        {"ok": False, "error": {"code": "not_a_browser_call", "message": "That approval is not a browser call."}},
    )
    status = cli.main(["guard", "browser", "report-prompt", "req-1", "--guard-home", str(tmp_path)])
    assert status == 2
    assert "not_a_browser_call" in capsys.readouterr().err
