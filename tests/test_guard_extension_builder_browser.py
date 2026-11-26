"""``extensions generate|validate --browser`` hand files to the native ``browser-driver`` command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import extension_builder_browser
from codex_plugin_scanner.guard.native_runtime import native_runtime_status

TOOLS = '{"tools": [{"name": "page_navigate", "inputSchema": {"properties": {"url": {}}}}, {"name": "frobnicate"}]}'
PROFILE = {"schemaVersion": "guard.browser-driver.v1", "id": "browser.example-pilot", "tools": [{}, {}]}
DRAFT = {
    "ok": True,
    "profile": PROFILE,
    "profileText": json.dumps(PROFILE, indent=2) + "\n",
    "proposals": [{"tool": "page_navigate", "verb": "Navigate", "evidence": "navigate"}],
    "notes": [
        {"code": "verb_unknown", "tool": "frobnicate"},
        {"code": "tool_name_unsupported", "tool": "BadName"},
        {"code": "tool_limit", "tool": "page_extra"},
    ],
}


def run(command: str, arguments: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, object]]:
    status = cli.main(["guard", "extensions", command, *arguments, "--json"])
    return status, json.loads(capsys.readouterr().out)


def tool_list(tmp_path: Path) -> Path:
    path = tmp_path / "tools.json"
    path.write_text(TOOLS, encoding="utf-8")
    return path


def generate_args(tmp_path: Path, output: Path) -> list[str]:
    return [
        "--browser",
        "--from",
        "mcp",
        "--input",
        str(tool_list(tmp_path)),
        "--output",
        str(output),
        "--slug",
        "example-pilot",
        "--server",
        "example-pilot",
    ]


def test_browser_generate_sends_the_tool_list_and_writes_the_profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent: list[dict[str, object]] = []

    def fake(request: dict[str, object], *, code: str) -> dict[str, object]:
        sent.append(request)
        return DRAFT

    monkeypatch.setattr(extension_builder_browser, "native_browser_request", fake)
    output = tmp_path / "browser.example-pilot.json"
    status, result = run(
        "generate",
        [*generate_args(tmp_path, output), "--name", "Example Pilot", "--publisher-name", "Example Org"],
        capsys,
    )
    assert status == 0, result
    assert sent == [
        {
            "op": "generate",
            "document": TOOLS,
            "slug": "example-pilot",
            "server": "example-pilot",
            "name": "Example Pilot",
            "publisher": "Example Org",
        }
    ]
    assert output.read_text(encoding="utf-8") == DRAFT["profileText"]
    assert result["driverId"] == "browser.example-pilot"
    assert result["tools"] == 2
    assert result["notes"] == DRAFT["notes"]


def test_browser_generate_text_output_names_skipped_tools(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(extension_builder_browser, "native_browser_request", lambda request, *, code: DRAFT)
    output = tmp_path / "browser.example-pilot.json"
    status = cli.main(["guard", "extensions", "generate", *generate_args(tmp_path, output)])
    text = capsys.readouterr().out
    assert status == 0, text
    assert "page_navigate: Navigate (navigate)" in text
    assert "Skipped BadName" in text
    assert "Skipped page_extra: a profile holds at most 256 tools." in text


def test_browser_generate_text_output_escapes_rejected_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    hostile = "Bad\x1b[2K\rName" + "x" * 200
    draft = {**DRAFT, "notes": [{"code": "tool_name_unsupported", "tool": hostile}]}
    monkeypatch.setattr(extension_builder_browser, "native_browser_request", lambda request, *, code: draft)
    output = tmp_path / "browser.example-pilot.json"
    status = cli.main(["guard", "extensions", "generate", *generate_args(tmp_path, output)])
    text = capsys.readouterr().out
    assert status == 0, text
    assert "\x1b" not in text
    assert "Skipped Bad?[2K?Name" in text
    assert "x" * 81 not in text
    assert "...: Guard tool names are at most 64 characters" in text


def test_browser_generate_refuses_a_reply_without_profile_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    reply = {key: value for key, value in DRAFT.items() if key != "profileText"}
    monkeypatch.setattr(extension_builder_browser, "native_browser_request", lambda request, *, code: reply)
    output = tmp_path / "out.json"
    status, error = run("generate", generate_args(tmp_path, output), capsys)
    assert (status != 0, error["error"]["code"]) == (True, "browser_generate")
    assert not output.exists()


def test_browser_generate_refuses_wrong_inputs_and_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(extension_builder_browser, "native_browser_request", lambda request, *, code: DRAFT)
    output = tmp_path / "out.json"
    args = generate_args(tmp_path, output)
    status, error = run("generate", [*args[:2], "openapi", *args[3:]], capsys)
    assert (status != 0, error["error"]["code"]) == (True, "browser_source")
    status, error = run("generate", args[:-2], capsys)
    assert (status != 0, error["error"]["code"]) == (True, "missing_metadata")
    status, error = run("generate", [*args, "--cloud"], capsys)
    assert (status != 0, error["error"]["code"]) == (True, "builder_mode")
    output.write_text("{}", encoding="utf-8")
    status, error = run("generate", args, capsys)
    assert (status != 0, error["error"]["code"]) == (True, "output_exists")
    assert output.read_text(encoding="utf-8") == "{}"


def test_browser_generate_reports_native_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    refusal = {"ok": False, "error": {"code": "browser_driver_reserved_name_claimed"}}
    monkeypatch.setattr(extension_builder_browser, "native_browser_request", lambda request, *, code: refusal)
    output = tmp_path / "out.json"
    status, error = run("generate", generate_args(tmp_path, output), capsys)
    assert status != 0
    assert error["error"]["code"] == "browser_generate"
    assert "browser_driver_reserved_name_claimed" in str(error)
    assert not output.exists()


def test_browser_validate_sends_the_profile_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent: list[dict[str, object]] = []
    reply = {
        "ok": True,
        "id": "browser.example-pilot",
        "tools": 2,
        "verbs": {"Navigate": 1, "Other": 1},
        "otherTools": ["frobnicate"],
        "firstPartyOverlap": [],
        "profileMode": "unknown",
    }
    monkeypatch.setattr(
        extension_builder_browser, "native_browser_request", lambda request, *, code: sent.append(request) or reply
    )
    profile = tmp_path / "browser.example-pilot.json"
    profile.write_text('{"id": "browser.example-pilot"}\n', encoding="utf-8")
    status, result = run("validate", ["--browser", str(profile)], capsys)
    assert status == 0, result
    assert sent == [{"op": "validate", "profile": '{"id": "browser.example-pilot"}\n'}]
    assert result["otherTools"] == ["frobnicate"]
    assert result["profileMode"] == "unknown"

    refusal = {"ok": False, "error": {"code": "browser_driver_publisher_verification_unproven"}}
    monkeypatch.setattr(extension_builder_browser, "native_browser_request", lambda request, *, code: refusal)
    status, error = run("validate", ["--browser", str(profile)], capsys)
    assert status != 0
    assert error["error"]["code"] == "browser_validate"
    assert "browser_driver_publisher_verification_unproven" in str(error)


def test_browser_generate_and_validate_through_the_native_runtime(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = native_runtime_status()
    if not status.available or not status.compatible:
        pytest.skip("native runtime not built in this environment")
    output = tmp_path / "browser.example-pilot.json"
    code, result = run("generate", generate_args(tmp_path, output), capsys)
    assert code == 0, result
    profile = json.loads(output.read_text(encoding="utf-8"))
    assert profile["publisher"]["verified"] is False
    assert profile["profileMode"] == {"default": "unknown"}
    code, result = run("validate", ["--browser", str(output)], capsys)
    assert code == 0, result
    assert result["otherTools"] == ["frobnicate"]
