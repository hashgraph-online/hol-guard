"""MCP proxy safe-alternative answers and their receipt and inbox evidence."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import approvals, mcp_tool_calls
from codex_plugin_scanner.guard.proxy import runtime_mcp, runtime_mcp_projection
from codex_plugin_scanner.guard.tool_decision_evidence import tool_decision_scanner_evidence

FIXTURE = Path(__file__).parent / "fixtures" / "mcp_relay" / "safe_alternative_block_vectors.json"
TOKEN = "guard-approval-context:v1:token"
ARTIFACT = SimpleNamespace(
    harness="codex",
    artifact_id="codex:project:workspace-files:delete_secret_file",
    name="workspace-files:delete_secret_file",
    artifact_type="mcp_tool_call",
    source_scope="project",
    config_path="/work/.codex/config.toml",
)
PARAMS = {"name": "delete_secret_file", "arguments": {"path": ".env", "force": True}}


def _vectors() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class _Projector:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home

    def project(self, tool_name: str, params: object, artifact: object = None) -> SimpleNamespace:
        projected = artifact is not None
        return SimpleNamespace(
            safe_arguments={"safe": tool_name},
            safe_params={"name": tool_name},
            display_launch_target=f"workspace-files:{tool_name}",
            browser_intent=None,
            risk_categories=("destructive", "secrets") if projected else (),
            risk_summary="Deletes a sensitive file." if projected else "",
        )


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    calls: list[tuple[str, dict[str, Any]]] = []

    def block(**kwargs: Any) -> None:
        calls.append(("block", {key: value for key, value in kwargs.items() if key != "now"}))

    def review(**kwargs: Any) -> list[dict[str, object]]:
        calls.append(("review", kwargs))
        return []

    monkeypatch.setattr(runtime_mcp_projection, "McpCallProjector", _Projector)
    monkeypatch.setattr(mcp_tool_calls, "block_tool_call", block)
    monkeypatch.setattr(runtime_mcp, "block_tool_call", block)
    monkeypatch.setattr(approvals, "record_unprompted_review", review)
    return calls


def _proxy(tmp_path: Path, store: object, server: str) -> Any:
    proxy = object.__new__(runtime_mcp.RuntimeMcpGuardProxy)
    proxy.config = SimpleNamespace(blocked_request_mode="safe-alternative", receipt_redaction_level="partial")
    proxy.store = store
    proxy.harness = "codex"
    proxy.server_name = server
    proxy.config_path = ARTIFACT.config_path
    proxy._call_projector = _Projector(tmp_path)
    return proxy


def _proxy_answer(tmp_path: Path, store: object, tool: str, server: str, signals: tuple[str, ...]) -> Any:
    decision = mcp_tool_calls.ToolCallDecision(
        action="review",
        source="policy",
        signals=signals,
        summary="summary",
        risk_categories=("destructive",),
        policy_action="review",
    )
    response, _event = _proxy(tmp_path, store, server)._queue_approval_center_response(
        message_id=7,
        artifact=ARTIFACT,
        artifact_hash=TOKEN,
        tool_name=tool,
        signals=decision.signals,
        params={**PARAMS, "name": tool},
        scanner_evidence=tool_decision_scanner_evidence(decision),
        policy_action="review",
    )
    return response


@pytest.mark.parametrize("vector", _vectors()["vectors"], ids=lambda vector: str(vector["name"]))
def test_the_fixture_holds_the_proxy_block(
    tmp_path: Path, recorded: list[tuple[str, dict[str, Any]]], vector: dict[str, Any]
) -> None:
    response = _proxy_answer(tmp_path, object(), vector["tool"], vector["server"], tuple(vector["signals"]))

    assert response["error"] == {"code": -32001, "message": vector["message"], "data": _vectors()["data"]}


def test_the_proxy_records_a_safe_alternative_block_and_silent_review(
    tmp_path: Path, recorded: list[tuple[str, dict[str, Any]]]
) -> None:
    store = object()
    signals = ("MCP tool call deletes files.", "Target path looks sensitive.")
    _proxy_answer(tmp_path, store, "delete_secret_file", "workspace-files", signals)
    assert [kind for kind, _ in recorded] == ["block", "review"]
    [(_, block), (_, review)] = recorded
    assert block["decision_source"] == "policy-safe-alternative"
    assert block["risk_categories"] == ("destructive", "secrets")
    assert review["redaction_level"] == "partial"
    [item] = review["evaluation"]["artifacts"]
    assert item["risk_summary"] == "Deletes a sensitive file."
