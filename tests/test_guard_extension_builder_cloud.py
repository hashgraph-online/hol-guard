"""``extensions generate --cloud`` hands the input to the native drafter and writes its pack."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import extension_builder_cloud
from codex_plugin_scanner.guard.native_runtime import native_runtime_status

PET_SHOP = Path(__file__).parent / "fixtures" / "cloud_pack_generate" / "pet-shop.openapi.json"
DRAFT = {
    "ok": True,
    "pack": {"schema": "guard.cloud-action-pack.v1", "actions": [{"actionId": "pet-shop.list_pets"}]},
    "proposals": [{"actionId": "pet-shop.list_pets", "class": "read", "evidence": ["method:GET"]}],
    "notes": [{"code": "argument_skipped", "at": "/openapi/paths/~1pets/get/parameters/X-Request-Id"}],
}


def run(arguments: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, object]]:
    status = cli.main(["guard", "extensions", "generate", *arguments, "--json"])
    return status, json.loads(capsys.readouterr().out)


def test_cloud_generate_sends_the_file_text_and_writes_the_draft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent: list[dict[str, object]] = []

    def fake(request: dict[str, object]) -> dict[str, object]:
        sent.append(request)
        return DRAFT

    monkeypatch.setattr(extension_builder_cloud, "native_pack_request", fake)
    output = tmp_path / "pet-shop.json"
    status, result = run(
        ["--cloud", "--from", "openapi", "--input", str(PET_SHOP), "--output", str(output), "--slug", "pet-shop"],
        capsys,
    )
    assert status == 0
    assert sent == [
        {
            "op": "generate",
            "from": "openapi",
            "document": PET_SHOP.read_text(encoding="utf-8"),
            "providerId": "pet-shop",
        }
    ]
    assert json.loads(output.read_text(encoding="utf-8")) == DRAFT["pack"]
    assert result["actions"] == 1
    assert result["notes"] == DRAFT["notes"]


def test_cloud_generate_passes_mcp_identity_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sent: list[dict[str, object]] = []
    monkeypatch.setattr(extension_builder_cloud, "native_pack_request", lambda request: sent.append(request) or DRAFT)
    listing = tmp_path / "tools.json"
    listing.write_text('{"tools": [{"name": "list_files"}]}', encoding="utf-8")
    status, _ = run(
        [
            "--cloud",
            "--from",
            "mcp",
            "--input",
            str(listing),
            "--output",
            str(tmp_path / "files.json"),
            "--slug",
            "files",
            "--name",
            "Files",
            "--host",
            "mcp.files.example",
            "--auth-mode",
            "oauth2",
        ],
        capsys,
    )
    assert status == 0
    assert sent[0]["host"] == "mcp.files.example"
    assert sent[0]["authMode"] == "oauth2"
    assert sent[0]["providerName"] == "Files"


def test_cloud_generate_refuses_wrong_sources_and_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(extension_builder_cloud, "native_pack_request", lambda request: DRAFT)
    output = tmp_path / "out.json"
    common = ["--input", str(PET_SHOP), "--output", str(output), "--slug", "pet-shop"]
    status, error = run(["--cloud", "--from", "cli", *common], capsys)
    assert (status != 0, error["error"]["code"]) == (True, "cloud_source")
    status, error = run(["--from", "openapi", *common], capsys)
    assert (status != 0, error["error"]["code"]) == (True, "cloud_source")
    output.write_text("{}", encoding="utf-8")
    status, error = run(["--cloud", "--from", "openapi", *common], capsys)
    assert (status != 0, error["error"]["code"]) == (True, "output_exists")
    assert output.read_text(encoding="utf-8") == "{}"


def test_cloud_generate_reports_native_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    refusal = {"ok": False, "error": {"code": "generate_openapi_server_invalid", "pointer": "/openapi/servers"}}
    monkeypatch.setattr(extension_builder_cloud, "native_pack_request", lambda request: refusal)
    output = tmp_path / "out.json"
    status, error = run(
        ["--cloud", "--from", "openapi", "--input", str(PET_SHOP), "--output", str(output), "--slug", "shop"],
        capsys,
    )
    assert status != 0
    assert error["error"]["code"] == "cloud_generate"
    assert "generate_openapi_server_invalid" in str(error)
    assert not output.exists()


def test_cloud_generate_drafts_through_the_native_runtime(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    status = native_runtime_status()
    if not status.available or not status.compatible:
        pytest.skip("native runtime not built in this environment")
    output = tmp_path / "pet-shop.json"
    code, result = run(
        ["--cloud", "--from", "openapi", "--input", str(PET_SHOP), "--output", str(output), "--slug", "pet-shop"],
        capsys,
    )
    assert code == 0, result
    pack = json.loads(output.read_text(encoding="utf-8"))
    assert {action["actionId"] for action in pack["actions"]} >= {"pet-shop.list_pets", "pet-shop.remove_pet"}
    assert all(action["fixtures"] == [] for action in pack["actions"])
