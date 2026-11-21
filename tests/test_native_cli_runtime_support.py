"""Public native CLI support boundaries and physical retirement coverage."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_cli_runtime_support as client

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "rust/crates/guard-runtime/tests/fixtures/cli_runtime_support_vectors.json"


@pytest.mark.parametrize("reply", [{}, {"result": {}, "extra": True}])
def test_transport_rejects_malformed_bound_payload(monkeypatch: pytest.MonkeyPatch, reply: dict[str, Any]) -> None:
    monkeypatch.setattr(client, "native_runner_authority", lambda *args: reply)
    with pytest.raises(ValueError, match="native_cli_runtime_support_result_invalid"):
        client.cli_runtime_support("remote_url", {"value": "https://example.com/mcp"})


def test_transport_never_recovers_from_native_unavailability(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(*args: object) -> dict[str, Any]:
        raise ValueError("native_runner_authority_unavailable")

    monkeypatch.setattr(client, "native_runner_authority", unavailable)
    with pytest.raises(ValueError, match="native_runner_authority_unavailable"):
        client.cli_runtime_support("remote_url", {"value": "https://example.com/mcp"})


def test_retired_bodies_are_absent_and_originals_are_identified() -> None:
    contract = json.loads((ROOT / "docs/guard/contracts/python-capability-ownership.v1.json").read_text())
    fixture = json.loads(FIXTURE.read_text())
    for record in contract["retired_bodies"]:
        if record["path"] not in fixture["source_hashes"]:
            continue
        assert fixture["source_hashes"][record["path"]] == record["source_sha256"]
        source = (ROOT / record["path"]).read_bytes()
        assert hashlib.sha256(source).hexdigest() != record["source_sha256"]
        tree = ast.parse(source)
        identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        identifiers.update(node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.ClassDef)))
        assert not identifiers.intersection(record["forbidden_symbols"])
        original_names = set(fixture["source_identifiers"][record["path"]])
        assert original_names.intersection(record["forbidden_symbols"])
        assert all((ROOT / path).is_file() for path in record["native_replacements"])


@pytest.mark.usefixtures("native_hook_force")
def test_original_vectors_through_one_bound_public_request_each(tmp_path: Path) -> None:
    fixture = json.loads(FIXTURE.read_text())
    for case in fixture["cases"]:
        if case["operation"] == "selection_fixture":
            continue
        assert (
            client.cli_runtime_support(case["operation"], case["params"], guard_home=tmp_path / "guard")
            == case["expected"]
        )


@pytest.mark.usefixtures("native_hook_force")
def test_copilot_resolution_returns_only_needed_identity_and_metadata(tmp_path: Path) -> None:
    config = tmp_path / ".mcp.json"
    config.write_text(
        json.dumps(
            {
                "servers": {
                    "demo": {
                        "url": "https://example.com/mcp",
                        "env": {"TOKEN": "configured-credential"},
                        "tools": {"echo": {"schema": {"type": "object"}, "description": "Echo"}},
                    }
                }
            }
        )
    )
    result = client.cli_runtime_support(
        "resolve_tool",
        {
            "home_dir": str(tmp_path),
            "workspace": str(tmp_path),
            "caller_cwd": str(tmp_path),
            "launch_cwd": str(tmp_path),
            "preferred": "cli",
            "environment": {"TOKEN": "ambient-credential"},
            "payload": {"tool_name": "mcp_demo_echo"},
        },
        guard_home=tmp_path / "guard",
    )
    assert result["tool_name"] == "echo"
    assert result["metadata"] == {"schema": {"type": "object"}, "description": "Echo"}
    assert result["server"] == {"server_name": "demo", "source_scope": "project", "config_path": str(config)}
    assert "server_config" not in result["server"]
    serialized = json.dumps(result)
    assert "configured-credential" not in serialized
    assert "ambient-credential" not in serialized
