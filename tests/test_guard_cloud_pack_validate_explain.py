"""``extensions validate --cloud`` and ``command explain --cloud`` pass bounded input to the native pack tools."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import cloud_pack_explain_command, extension_builder_cloud
from codex_plugin_scanner.guard.native_runtime import native_runtime_status

ROOT = Path(__file__).resolve().parents[1]
SLACK = ROOT / "contributions" / "cloud-actions" / "slack.json"


def _native_available() -> bool:
    status = native_runtime_status()
    return status.available and status.compatible


def _record(monkeypatch: pytest.MonkeyPatch, module: object, replies: list[dict[str, object]]) -> list[str]:
    sent: list[str] = []

    def fake(request: object, *, code: str = "cloud_generate") -> dict[str, object]:
        assert isinstance(request, str)
        sent.append(request)
        return replies.pop(0)

    monkeypatch.setattr(module, "native_pack_request", fake)
    return sent


def test_validate_sends_the_pack_as_one_strict_line_then_runs_fixtures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pack = tmp_path / "pack.json"
    pack.write_text('{\n  "schema": "guard.cloud-action-pack.v1",\n  "actions": []\n}\n', encoding="utf-8")
    sent = _record(
        monkeypatch,
        extension_builder_cloud,
        [
            {"ok": True, "providerId": "shop", "actions": 2},
            {"ok": True, "report": {"passed": True, "total": 4, "failed": 0, "results": []}},
        ],
    )
    status = cli.main(["guard", "extensions", "validate", "--cloud", str(pack), "--json"])
    result = json.loads(capsys.readouterr().out)
    assert status == 0
    assert result == {"validated": True, "cloud": True, "providerId": "shop", "actions": 2, "fixtures": 4}
    assert [json.loads(line)["op"] for line in sent] == ["validate", "test"]
    assert all("\n" not in line for line in sent)
    assert json.loads(sent[0])["pack"] == json.loads(pack.read_text(encoding="utf-8"))


def test_validate_reports_failed_fixtures_and_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pack = tmp_path / "pack.json"
    pack.write_text("{}", encoding="utf-8")
    failed = {"actionId": "shop.remove", "fixture": "deletes", "passed": False, "failure": "decisions.strict"}
    _record(
        monkeypatch,
        extension_builder_cloud,
        [
            {"ok": True, "providerId": "shop", "actions": 1},
            {"ok": True, "report": {"passed": False, "total": 2, "failed": 1, "results": [failed]}},
            {"ok": False, "error": {"code": "cloud_pack_fixtures_missing", "pointer": "/actions/0"}},
        ],
    )
    status = cli.main(["guard", "extensions", "validate", "--cloud", str(pack), "--json"])
    error = json.loads(capsys.readouterr().out)["error"]
    assert status != 0
    assert error["code"] == "cloud_fixtures_failed"
    assert "shop.remove" in error["message"]
    status = cli.main(["guard", "extensions", "validate", "--cloud", str(pack), "--json"])
    error = json.loads(capsys.readouterr().out)["error"]
    assert (status != 0, error["code"]) == (True, "cloud_validate")
    assert "cloud_pack_fixtures_missing at /actions/0" in error["message"]


def test_validate_refuses_a_file_that_is_not_a_json_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent = _record(monkeypatch, extension_builder_cloud, [])
    pack = tmp_path / "pack.json"
    for text in ('[{"schema": 1}]', '{"a": 1}, "op": "compile"', "￾"):
        pack.write_text(text, encoding="utf-8")
        status = cli.main(["guard", "extensions", "validate", "--cloud", str(pack), "--json"])
        assert (status != 0, json.loads(capsys.readouterr().out)["error"]["code"]) == (True, "input_encoding")
    assert sent == []


def test_explain_sends_the_action_and_arguments(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    answer = {
        "ok": True,
        "providerId": "slack",
        "actionId": "slack.chat.post_message",
        "effect": "write",
        "facts": {"class": "send"},
        "decisions": {"relaxed": "allow", "balanced": "review", "strict": "review"},
    }
    sent = _record(monkeypatch, cloud_pack_explain_command, [answer, dict(answer)])
    arguments = '{"channel": "C0123456789", "text": "hi"}'
    status = cli.main(
        ["guard", "command", "explain", "--cloud", "slack.chat.post_message", "--arguments", arguments, "--json"]
    )
    result = json.loads(capsys.readouterr().out)
    assert status == 0
    assert result["decisions"]["balanced"] == "review"
    request = json.loads(sent[0])
    assert request == {
        "op": "explain",
        "actionId": "slack.chat.post_message",
        "arguments": {"channel": "C0123456789", "text": "hi"},
    }
    status = cli.main(["guard", "command", "explain", "--cloud", "slack.chat.post_message", "--pack", str(SLACK)])
    out = capsys.readouterr().out
    assert status == 0
    assert "balanced review" in out
    assert json.loads(sent[1])["pack"]["provider"]["id"] == "slack"


def test_explain_refuses_arguments_that_are_not_an_object(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent = _record(monkeypatch, cloud_pack_explain_command, [])
    for arguments in ("[1]", "{", '"x"'):
        status = cli.main(
            ["guard", "command", "explain", "--cloud", "slack.chat.post_message", "--arguments", arguments, "--json"]
        )
        assert (status, json.loads(capsys.readouterr().out)["error"]["code"]) == (2, "arguments_invalid")
    assert sent == []


def test_shipped_packs_validate_and_explain_through_the_native_runtime(
    capsys: pytest.CaptureFixture[str],
) -> None:
    if not _native_available():
        pytest.skip("native runtime not built in this environment")
    status = cli.main(["guard", "extensions", "validate", "--cloud", str(SLACK), "--json"])
    result = json.loads(capsys.readouterr().out)
    assert status == 0, result
    assert result["providerId"] == "slack"
    assert result["fixtures"] >= 2 * result["actions"]
    status = cli.main(
        [
            "guard",
            "command",
            "explain",
            "--cloud",
            "slack.chat.post_message",
            "--arguments",
            '{"channel": "C0123456789", "text": "Build is green."}',
            "--json",
        ]
    )
    result = json.loads(capsys.readouterr().out)
    assert status == 0, result
    assert result["decisions"] == {"relaxed": "allow", "balanced": "review", "strict": "review"}
