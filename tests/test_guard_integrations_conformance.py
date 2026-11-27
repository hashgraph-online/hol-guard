"""``hol-guard integrations conformance`` sends one request to the native runtime and renders the report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import integrations_command

MANIFEST = "tests/fixtures/provider_integrations/exampleshield/manifest.json"


def _checks(failing: str | None = None) -> list[dict[str, object]]:
    ids = ["compile", "recordings", "share-set", "no-added-prompt", "bounded-prompt"]
    return [
        {
            "id": check,
            "passed": check != failing,
            "problems": ["browser.origin-reputation: no recording answers unknown"] if check == failing else [],
        }
        for check in ids
    ]


def _answer(failing: str | None = None) -> dict[str, object]:
    return {
        "ok": True,
        "provider_id": "provider.exampleshield",
        "passed": failing is None,
        "corpus_rows": 23,
        "recordings": 9,
        "checks": _checks(failing),
    }


def _record(monkeypatch: pytest.MonkeyPatch, reply: dict[str, object]) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []

    def fake(line: str) -> dict[str, object]:
        sent.append(json.loads(line))
        return reply

    monkeypatch.setattr(integrations_command, "_native_request", fake)
    return sent


def test_conformance_sends_absolute_paths(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    sent = _record(monkeypatch, _answer())
    status = cli.main(["guard", "integrations", "conformance", MANIFEST, "--recordings", "r.json", "--json"])
    assert status == 0
    assert sent == [
        {
            "manifest": str(Path(MANIFEST).absolute()),
            "recordings": str(Path("r.json").absolute()),
        }
    ]
    result = json.loads(capsys.readouterr().out)
    assert "ok" not in result
    assert result["passed"] is True


def test_a_failing_check_prints_its_problems_and_exits_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _record(monkeypatch, _answer("recordings"))
    assert cli.main(["guard", "integrations", "conformance", MANIFEST]) == 1
    out = capsys.readouterr().out
    assert "provider.exampleshield fails conformance (9 recordings, 23 benign browser rows)." in out
    assert "  FAIL  recordings" in out
    assert "no recording answers unknown" in out
    assert "  pass  share-set" in out


def test_a_refusal_exits_two(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    _record(monkeypatch, {"ok": False, "error": {"code": "gate_not_found", "message": "Name the gate."}})
    assert cli.main(["guard", "integrations", "conformance", "elsewhere.json"]) == 2
    assert "gate_not_found: Name the gate." in capsys.readouterr().err
