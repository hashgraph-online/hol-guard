"""A queued tools/call the relay blocks under ``safe-alternative`` matches the proxy.

The proxy answers a call it would queue for approval, under the default
``blocked_request_mode``, with the safe-alternative block, a
``policy-safe-alternative`` receipt and a silent inbox row. The resident
answers the block; the shared fixture holds the proxy's message, which the
Rust side asserts too. The daemon's drain then writes the receipt and the row
from the resident's evidence with the same recorder calls the proxy makes.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import approvals, mcp_tool_calls, native_mcp_tool_call_identity
from codex_plugin_scanner.guard.daemon.mcp_relay_evidence_drain import _decision, record_mcp_relay_evidence
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


def _wire_decision(**fields: object) -> dict[str, object]:
    return {
        "action": "review",
        "policy_action": "review",
        "source": "policy",
        "signals": ["MCP tool call deletes files.", "Target path looks sensitive."],
        "summary": "summary",
        "risk_categories": ["destructive"],
        "normalization_reason_code": None,
        "original_action": None,
        "approval_reuse_status": None,
        "approval_reuse_reason_code": None,
        "current_action": None,
        "saved_action": None,
        "pending_approval_reuse_decision": None,
        "approval_reuse_claim_disposition": None,
        "post_claim_revalidated": False,
        "post_claim_authority": None,
        **fields,
    }


def _record(**fields: object) -> dict[str, object]:
    return {
        "kind": "mcp_tool_call",
        "harness": "codex",
        "outcome": "block",
        "decision_source": "policy-safe-alternative",
        "policy_action": "review",
        "tool_name": "delete_secret_file",
        "params": PARAMS,
        "arguments": {"format": "mapping", "entries": [["path", ".env"], ["force", True]]},
        "identity": {"wire": True},
        "decision": _wire_decision(),
        "review": {"redaction_level": "partial"},
        **fields,
    }


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

    def decode(payload: object, *, expect_hash: bool, token: bool) -> SimpleNamespace:
        assert payload == {"wire": True} and expect_hash and token
        return SimpleNamespace(artifact=ARTIFACT, artifact_hash=TOKEN)

    def block(**kwargs: Any) -> None:
        calls.append(("block", {key: value for key, value in kwargs.items() if key != "now"}))

    def review(**kwargs: Any) -> list[dict[str, object]]:
        calls.append(("review", kwargs))
        return []

    monkeypatch.setattr(native_mcp_tool_call_identity, "_decode", decode)
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
    decision = _decision(_wire_decision(signals=list(signals)))
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


def test_the_drain_records_what_the_proxy_records(tmp_path: Path, recorded: list[tuple[str, dict[str, Any]]]) -> None:
    store = object()
    signals = tuple(_wire_decision()["signals"])  # type: ignore[arg-type]
    _proxy_answer(tmp_path, store, "delete_secret_file", "workspace-files", signals)
    proxied = list(recorded)
    recorded.clear()

    assert record_mcp_relay_evidence(store, tmp_path, _record())

    assert [kind for kind, _ in recorded] == ["block", "review"]
    assert recorded == proxied
    [(_, block), (_, review)] = recorded
    assert block["decision_source"] == "policy-safe-alternative"
    assert block["risk_categories"] == ("destructive", "secrets")
    assert review["redaction_level"] == "partial"
    [item] = review["evaluation"]["artifacts"]
    assert item["risk_summary"] == "Deletes a sensitive file."


def test_a_review_row_failure_keeps_the_block(
    tmp_path: Path, recorded: list[tuple[str, dict[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    def unwritten(**_kwargs: object) -> list[dict[str, object]]:
        # `record_unprompted_review` swallows its store errors and returns [].
        return []

    monkeypatch.setattr(approvals, "record_unprompted_review", unwritten)

    assert record_mcp_relay_evidence(object(), tmp_path, _record())
    assert [kind for kind, _ in recorded] == ["block"]


@pytest.mark.parametrize(
    "fields",
    [
        {"review": {"redaction_level": "secret"}},
        {"review": {"redaction_level": "full", "extra": 1}},
        {"review": "full"},
        {"review": None},
        {"decision_source": "policy-block"},
        {"decision_source": "policy"},
        {"outcome": "forward", "policy_action": "allow"},
        {"policy_action": "allow"},
    ],
)
def test_a_safe_alternative_record_the_proxy_could_not_have_written_is_dropped(
    tmp_path: Path, recorded: list[tuple[str, dict[str, Any]]], fields: dict[str, object]
) -> None:
    assert not record_mcp_relay_evidence(object(), tmp_path, _record(**fields))
    assert recorded == []


def test_a_safe_alternative_block_needs_its_review(tmp_path: Path, recorded: list[tuple[str, dict[str, Any]]]) -> None:
    unreviewed = _record()
    del unreviewed["review"]

    assert not record_mcp_relay_evidence(object(), tmp_path, unreviewed)
    assert recorded == []
