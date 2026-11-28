"""``extensions generate|validate --provider`` hand a manifest to the native provider commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import extension_builder_provider
from codex_plugin_scanner.guard.native_runtime import native_runtime_status

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "provider_integrations" / "exampleshield" / "manifest.json"
RECORDINGS = '{\n  "schema": "guard.provider-recordings.v1",\n  "recordings": []\n}\n'
REPORT = {
    "ok": True,
    "provider_id": "provider.exampleshield",
    "passed": False,
    "recordings": 9,
    "corpus_rows": 40,
    "checks": [
        {"id": "compile", "passed": True, "problems": []},
        {"id": "recordings", "passed": False, "problems": ["browser.origin-reputation: no recording answers ok"]},
    ],
}


def run(command: str, arguments: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, object]]:
    status = cli.main(["guard", "extensions", command, *arguments, "--json"])
    return status, json.loads(capsys.readouterr().out)


def generate_args(output: Path) -> list[str]:
    return ["--provider", "--from", "manifest", "--input", str(FIXTURE), "--output", str(output)]


def test_provider_generate_sends_the_manifest_and_writes_the_checked_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake(command: str, request: dict[str, object], *, code: str) -> dict[str, object]:
        sent.append((command, request))
        return {"ok": True, "provider_id": "provider.exampleshield", "recordings": 0, "recordingsText": RECORDINGS}

    monkeypatch.setattr(extension_builder_provider, "_native", fake)
    output = tmp_path / "new-provider" / "recordings.json"
    status, result = run("generate", generate_args(output), capsys)
    assert status == 0, result
    assert sent == [("provider-recordings-draft", {"manifest": FIXTURE.read_text(encoding="utf-8")})]
    assert output.read_text(encoding="utf-8") == RECORDINGS
    assert result["providerId"] == "provider.exampleshield"

    status, error = run("generate", generate_args(output), capsys)
    assert status != 0
    assert error["error"]["code"] == "output_exists"


def test_provider_generate_refuses_other_inputs_modes_and_native_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "recordings.json"
    wrong_source = ["--provider", "--from", "mcp", "--input", str(FIXTURE), "--output", str(output)]
    assert run("generate", wrong_source, capsys)[1]["error"]["code"] == "provider_source"
    without_flag = ["--from", "manifest", "--input", str(FIXTURE), "--output", str(output)]
    assert run("generate", without_flag, capsys)[1]["error"]["code"] == "provider_source"
    assert run("generate", [*generate_args(output), "--browser"], capsys)[1]["error"]["code"] == "builder_mode"

    def refuse(command: str, request: dict[str, object], *, code: str) -> dict[str, object]:
        return {"ok": False, "error": {"code": "provider_integration_hosts_invalid", "message": "x"}}

    monkeypatch.setattr(extension_builder_provider, "_native", refuse)
    status, error = run("generate", generate_args(output), capsys)
    assert status != 0
    assert error["error"]["code"] == "provider_generate"
    assert "provider_integration_hosts_invalid" in error["error"]["message"]
    assert not output.exists()


def test_provider_validate_runs_conformance_and_fails_on_a_failed_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent: list[tuple[str, dict[str, object]]] = []

    def fake(command: str, request: dict[str, object], *, code: str) -> dict[str, object]:
        sent.append((command, request))
        return REPORT

    monkeypatch.setattr(extension_builder_provider, "_native", fake)
    recordings = tmp_path / "recordings.json"
    status, result = run("validate", ["--provider", str(FIXTURE), "--recordings", str(recordings)], capsys)
    assert status == 1
    assert result["passed"] is False
    assert sent == [("provider-conformance", {"manifest": str(FIXTURE), "recordings": str(recordings)})]

    status = cli.main(["guard", "extensions", "validate", "--provider", str(FIXTURE)])
    text = capsys.readouterr().out
    assert status == 1
    assert "FAIL  recordings" in text
    assert "no recording answers ok" in text

    assert (
        run("validate", ["--browser", str(FIXTURE), "--recordings", str(recordings)], capsys)[1]["error"]["code"]
        == "builder_mode"
    )


def test_provider_generate_and_validate_through_the_native_runtime(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = native_runtime_status()
    if not status.available or not status.compatible:
        pytest.skip("native runtime not built in this environment")
    output = tmp_path / "recordings.json"
    code, result = run("generate", generate_args(output), capsys)
    assert code == 0, result
    drafted = json.loads(output.read_text(encoding="utf-8"))
    assert len(drafted["recordings"]) == result["recordings"] == 3 + 1 + 5
    code, result = run("validate", ["--provider", str(FIXTURE), "--recordings", str(output)], capsys)
    assert code == 0, result
    assert result["passed"] is True
    assert [check["id"] for check in result["checks"]] == [
        "compile",
        "recordings",
        "share-set",
        "no-added-prompt",
        "bounded-prompt",
    ]
