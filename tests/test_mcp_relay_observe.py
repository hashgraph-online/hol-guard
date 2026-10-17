"""An observed tools/call the relay forwards matches the proxy's observe forward.

Under ``mode = "observe"`` the proxy forwards a call it would have stopped for
approval (``_observe_tool_forward``) and records an allow receipt under the
``policy-observe`` decision source, with the resident's ``observe_mode`` item
after the decision's own evidence. It queues no inbox row. The resident
answers that forward natively; the daemon's drain then writes the receipt from
the resident's evidence with the same recorder call the proxy makes.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import approvals, mcp_tool_calls, native_mcp_tool_call_identity
from codex_plugin_scanner.guard.daemon.mcp_relay_evidence_drain import _decision, record_mcp_relay_evidence
from codex_plugin_scanner.guard.native_mcp_proxy_decision import tool_facts
from codex_plugin_scanner.guard.proxy import runtime_mcp, runtime_mcp_projection

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
MESSAGE = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": PARAMS}
RESPONSE = {"jsonrpc": "2.0", "id": 7, "result": {"content": []}}
# The resident's `observe_tool_forward` answer for an observed review, as the
# relay's own observe route reads it (`mcp_relay_decide_observe_tests.rs`).
OBSERVE_ITEM = {"source": "observe_mode", "observed_policy_action": "review", "authoritative_action": "allow"}
OBSERVED = {
    "observe_override": True,
    "executed_action": "allow",
    "observed_policy_action": "review",
    "evidence_append": [OBSERVE_ITEM],
}


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
        "outcome": "forward",
        "decision_source": "policy-observe",
        "policy_action": "allow",
        "tool_name": "delete_secret_file",
        "params": PARAMS,
        "arguments": {"format": "mapping", "entries": [["path", ".env"], ["force", True]]},
        "identity": {"wire": True},
        "decision": _wire_decision(),
        "evidence_append": [OBSERVE_ITEM],
        **fields,
    }


class _Projector:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home

    def project(self, tool_name: str, params: object, artifact: object = None) -> SimpleNamespace:
        assert artifact is None
        return SimpleNamespace(safe_arguments={"safe": tool_name}, safe_params={"name": tool_name})


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    calls: list[tuple[str, dict[str, Any]]] = []

    def decode(payload: object, *, expect_hash: bool, token: bool) -> SimpleNamespace:
        assert payload == {"wire": True} and expect_hash and token
        return SimpleNamespace(artifact=ARTIFACT, artifact_hash=TOKEN)

    def recorder(kind: str) -> Any:
        def record(**kwargs: Any) -> list[dict[str, object]]:
            calls.append((kind, {key: value for key, value in kwargs.items() if key != "now"}))
            return []

        return record

    monkeypatch.setattr(native_mcp_tool_call_identity, "_decode", decode)
    monkeypatch.setattr(runtime_mcp_projection, "McpCallProjector", _Projector)
    for module in (mcp_tool_calls, runtime_mcp):
        monkeypatch.setattr(module, "allow_tool_call", recorder("allow"))
        monkeypatch.setattr(module, "block_tool_call", recorder("block"))
    monkeypatch.setattr(approvals, "record_unprompted_review", recorder("review"))
    return calls


def _observe(tmp_path: Path, store: object) -> tuple[Any, dict[str, Any]]:
    decision = _decision(_wire_decision())
    authority = runtime_mcp._ToolCallAuthority(  # pyright: ignore[reportPrivateUsage]
        artifact=ARTIFACT,  # type: ignore[arg-type]
        artifact_hash=TOKEN,
        decision=decision,
        catalog_generation=1,
        catalog_state=object(),  # type: ignore[arg-type]
        catalog_fingerprint="fingerprint",
    )
    proxy: Any = object.__new__(runtime_mcp.RuntimeMcpGuardProxy)
    proxy.config = SimpleNamespace(blocked_request_mode="safe-alternative", receipt_redaction_level="partial")
    proxy.store = store
    proxy.harness = "codex"
    proxy.server_name = "workspace-files"
    proxy.config_path = ARTIFACT.config_path
    proxy._call_projector = _Projector(tmp_path)
    proxy._drain_and_validate_catalog_authority = lambda **_kwargs: True
    proxy._resolve_tool_call_authority = lambda **_kwargs: authority

    def native_decide(query: dict[str, object], **_kwargs: object) -> dict[str, object]:
        assert query == {"check": "observe_tool_forward", "fresh": tool_facts(decision)}
        return OBSERVED

    proxy._native_decide = native_decide
    proxy._forward_message = lambda *_args, **_kwargs: RESPONSE
    return proxy._observe_tool_forward(
        message=MESSAGE,
        params=PARAMS,
        tool_name="delete_secret_file",
        arguments=PARAMS["arguments"],
        authority=authority,
        decision_scanner_evidence=(),
        child_stdin=None,
        child_stdout=None,
        client_input=None,
        server_output=None,
    )


def test_the_drain_records_what_the_proxy_observe_forward_records(
    tmp_path: Path, recorded: list[tuple[str, dict[str, Any]]]
) -> None:
    store = object()
    response, _event = _observe(tmp_path, store)
    assert response == RESPONSE
    proxied = list(recorded)
    recorded.clear()

    assert record_mcp_relay_evidence(store, tmp_path, _record())

    # One allow receipt and no inbox row, from either side.
    assert [kind for kind, _ in recorded] == ["allow"]
    assert recorded == proxied
    [(_, allow)] = recorded
    assert allow["remember"] is False
    assert allow["decision_source"] == "policy-observe"
    assert allow["policy_action"] == "allow"
    assert allow["risk_categories"] == ("destructive",)
    assert allow["additional_scanner_evidence"][-1] == OBSERVE_ITEM


def test_an_observed_forward_without_an_override_records_no_observe_item(
    tmp_path: Path, recorded: list[tuple[str, dict[str, Any]]]
) -> None:
    assert record_mcp_relay_evidence(object(), tmp_path, _record(policy_action="warn", evidence_append=[]))

    [(kind, allow)] = recorded
    assert kind == "allow"
    assert allow["policy_action"] == "warn"
    assert OBSERVE_ITEM not in allow["additional_scanner_evidence"]


def test_an_observed_forward_the_proxy_could_not_have_written_is_dropped(
    tmp_path: Path, recorded: list[tuple[str, dict[str, Any]]]
) -> None:
    # Observe only ever executes as allow or warn.
    assert not record_mcp_relay_evidence(object(), tmp_path, _record(policy_action="review"))
    assert not record_mcp_relay_evidence(object(), tmp_path, _record(review={"redaction_level": "partial"}))
    assert recorded == []
