"""``hol-guard browser explain`` sends one request to the native runtime and renders the answer."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import browser_explain_command
from codex_plugin_scanner.guard.native_runtime import native_runtime_status

PLAYWRIGHT = "browser.playwright-mcp"

ANSWER: dict[str, object] = {
    "ok": True,
    "driver": {"id": PLAYWRIGHT, "name": "Playwright MCP", "server": "playwright"},
    "tool": "browser_snapshot",
    "action": {"intent": "browser.inspect", "verb": "Read", "sensitive_surface_flags": []},
    "unclassified": None,
    "decision": {"action": "allow", "source": "browser-routine", "summaryCode": "risk"},
    "riskCategories": ["browser_inspection"],
    "grant": {"eligible": True, "category": "browser_inspection"},
}


def _record(monkeypatch: pytest.MonkeyPatch, replies: list[dict[str, object]]) -> list[dict[str, object]]:
    sent: list[dict[str, object]] = []

    def fake(line: str) -> dict[str, object]:
        sent.append(json.loads(line))
        return replies.pop(0)

    monkeypatch.setattr(browser_explain_command, "_native_request", fake)
    return sent


def _explain(*extra: str) -> int:
    return cli.main(["guard", "browser", "explain", "--driver", PLAYWRIGHT, *extra])


def test_explain_sends_driver_tool_and_arguments(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent = _record(monkeypatch, [dict(ANSWER)])
    status = _explain("--tool", "browser_snapshot", "--args", '{"depth": 2}', "--json")
    assert status == 0
    assert sent == [{"driver": PLAYWRIGHT, "tool": "browser_snapshot", "arguments": {"depth": 2}}]
    result = json.loads(capsys.readouterr().out)
    assert "ok" not in result
    assert result["decision"]["action"] == "allow"


def test_explain_renders_the_action_decision_and_grant(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _record(monkeypatch, [dict(ANSWER)])
    assert _explain("--tool", "browser_snapshot") == 0
    out = capsys.readouterr().out
    assert "browser_snapshot on Playwright MCP" in out
    assert "intent: browser.inspect" in out
    assert "Default decision: allow" in out
    assert "A temporary browser grant can cover this call (browser_inspection)." in out


def test_explain_renders_an_unclassified_call(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answer = {
        **ANSWER,
        "tool": "browser_teleport",
        "action": None,
        "unclassified": "tool_not_listed",
        "grant": {"eligible": False, "category": None},
    }
    _record(monkeypatch, [answer])
    assert _explain("--tool", "browser_teleport") == 0
    out = capsys.readouterr().out
    assert "unclassified: tool_not_listed" in out
    assert "No temporary browser grant can cover this call." in out


@pytest.mark.parametrize("raw", ["{", "null", "[1]", '"text"'])
def test_explain_refuses_non_object_arguments_before_the_native_call(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], raw: str
) -> None:
    sent = _record(monkeypatch, [])
    status = _explain("--tool", "browser_snapshot", "--args", raw, "--json")
    assert (status, json.loads(capsys.readouterr().out)["error"]["code"]) == (2, "arguments_invalid")
    assert sent == []


def test_a_text_mode_failure_goes_to_the_supplied_error_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    import argparse
    import io

    _record(monkeypatch, [])
    args = argparse.Namespace(driver=PLAYWRIGHT, tool="browser_snapshot", tool_arguments="null", json=False)
    out, err = io.StringIO(), io.StringIO()
    assert browser_explain_command.run_browser_command(args, output_stream=out, error_stream=err) == 2
    assert out.getvalue() == ""
    assert err.getvalue().startswith("arguments_invalid:")


def test_a_native_refusal_names_the_shipped_profiles(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    refusal = {
        "ok": False,
        "error": {"code": "driver_unknown", "message": "No shipped driver profile has that id."},
        "drivers": [PLAYWRIGHT],
    }
    _record(monkeypatch, [refusal])
    status = cli.main(["guard", "browser", "explain", "--driver", "browser.example", "--tool", "open", "--json"])
    error = json.loads(capsys.readouterr().out)["error"]
    assert (status, error["code"]) == (2, "driver_unknown")
    assert PLAYWRIGHT in error["message"]


def test_shipped_profiles_explain_through_the_native_runtime(capsys: pytest.CaptureFixture[str]) -> None:
    status = native_runtime_status()
    if not (status.available and status.compatible):
        pytest.skip("native runtime not built in this environment")
    assert _explain("--tool", "browser_snapshot", "--json") == 0
    result = json.loads(capsys.readouterr().out)
    assert result["action"]["intent"] == "browser.inspect"
    assert result["decision"]["action"] == "warn"
    assert result["grant"]["eligible"] is True
    assert _explain("--tool", "browser_evaluate", "--args", '{"function": "() => 1"}', "--json") == 0
    result = json.loads(capsys.readouterr().out)
    assert result["decision"]["action"] not in {"allow", "warn"}
    assert result["grant"]["eligible"] is False
