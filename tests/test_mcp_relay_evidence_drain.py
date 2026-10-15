from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls, native_mcp_tool_call_identity
from codex_plugin_scanner.guard.daemon import hook_direct_evidence_drain
from codex_plugin_scanner.guard.daemon.mcp_relay_evidence_drain import (
    is_mcp_relay_evidence,
    record_mcp_relay_evidence,
)
from codex_plugin_scanner.guard.proxy import runtime_mcp_projection

ARTIFACT = SimpleNamespace(harness="codex")
TOKEN = "guard-approval-context:v1:token"


def _decision(action: str = "allow", **fields: object) -> dict[str, object]:
    return {
        "action": action,
        "source": "policy",
        "signals": ["signal"],
        "summary": "summary",
        "risk_categories": ["network"],
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
        "decision_source": "policy",
        "policy_action": "allow",
        "tool_name": "read",
        "params": {"name": "read", "arguments": {"a": 1, "b": 2}},
        "arguments": {"format": "mapping", "entries": [["b", 2], ["a", 1]]},
        "identity": {"wire": True},
        "decision": _decision(),
        **fields,
    }


class _Projector:
    projected: ClassVar[list[tuple[str, object]]] = []

    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home

    def project(self, tool_name: str, params: object) -> SimpleNamespace:
        _Projector.projected.append((tool_name, params))
        return SimpleNamespace(safe_arguments={"safe": True})


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    recorded: list[tuple[str, dict[str, Any]]] = []
    _Projector.projected = []

    def decode(payload: object, *, expect_hash: bool, token: bool) -> SimpleNamespace:
        assert payload == {"wire": True} and expect_hash and token
        return SimpleNamespace(artifact=ARTIFACT, artifact_hash=TOKEN)

    monkeypatch.setattr(native_mcp_tool_call_identity, "_decode", decode)
    monkeypatch.setattr(runtime_mcp_projection, "McpCallProjector", _Projector)
    monkeypatch.setattr(mcp_tool_calls, "allow_tool_call", lambda **kwargs: recorded.append(("allow", kwargs)))
    monkeypatch.setattr(mcp_tool_calls, "block_tool_call", lambda **kwargs: recorded.append(("block", kwargs)))
    return recorded


def test_a_forward_is_recorded_as_the_proxy_allow(tmp_path: Path, calls: list[tuple[str, dict[str, Any]]]) -> None:
    store = object()

    assert record_mcp_relay_evidence(store, tmp_path, _record())

    [(kind, recorded)] = calls
    assert kind == "allow"
    assert recorded["store"] is store
    assert recorded["artifact"] is ARTIFACT
    assert recorded["artifact_hash"] == TOKEN
    assert recorded["remember"] is False
    assert recorded["decision_source"] == "policy"
    assert recorded["policy_action"] == "allow"
    assert recorded["signals"] == ("signal",)
    assert recorded["risk_categories"] == ("network",)
    assert recorded["arguments"] == {"safe": True}
    assert recorded["additional_scanner_evidence"] == ()
    [(tool_name, params)] = _Projector.projected
    assert tool_name == "read"
    assert isinstance(params, dict) and list(params["arguments"]) == ["b", "a"]


@pytest.mark.parametrize("policy_action", ["block", "sandbox-required"])
def test_a_block_is_recorded_as_the_proxy_block(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], policy_action: str
) -> None:
    record = _record(
        outcome="block",
        decision_source="policy-block",
        policy_action=policy_action,
        decision=_decision("block"),
    )

    assert record_mcp_relay_evidence(object(), tmp_path, record)

    [(kind, recorded)] = calls
    assert kind == "block"
    assert "remember" not in recorded
    assert recorded["decision_source"] == "policy-block"
    assert recorded["policy_action"] == policy_action


@pytest.mark.parametrize(
    "fields",
    [
        {"harness": "claude-code"},
        {"outcome": "defer"},
        {"policy_action": "block"},
        {"outcome": "block", "decision_source": "policy", "policy_action": "block"},
        {"outcome": "block", "decision_source": "policy-block", "policy_action": "allow"},
        {"tool_name": "write"},
        {"params": ["read"]},
        {"decision": _decision(post_claim_revalidated=True, post_claim_authority="fresh")},
        {"decision": {"action": "allow"}},
        {"arguments": {"format": "mapping", "entries": [["a", 1]]}},
        {"arguments": {"format": "mapping", "entries": [["a", 1], ["b", 3]]}},
    ],
)
def test_a_record_the_proxy_could_not_have_written_is_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], fields: dict[str, object]
) -> None:
    assert not record_mcp_relay_evidence(object(), tmp_path, _record(**fields))
    assert calls == []


def test_a_claimed_call_appends_the_post_claim_evidence(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]]
) -> None:
    appended = [{"kind": "post_claim", "context_matches": True}]

    assert record_mcp_relay_evidence(object(), tmp_path, _record(evidence_append=appended))

    [(kind, recorded)] = calls
    assert kind == "allow"
    assert recorded["additional_scanner_evidence"] == tuple(appended)


@pytest.mark.parametrize("appended", [{"kind": "post_claim"}, ["post_claim"], None])
def test_a_malformed_post_claim_evidence_drops_the_record(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], appended: object
) -> None:
    assert not record_mcp_relay_evidence(object(), tmp_path, _record(evidence_append=appended))
    assert calls == []


def test_a_record_with_unknown_or_missing_fields_is_dropped(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]]
) -> None:
    extra = {**_record(), "extra": 1}
    missing = _record()
    del missing["arguments"]

    assert not record_mcp_relay_evidence(object(), tmp_path, extra)
    assert not record_mcp_relay_evidence(object(), tmp_path, missing)
    assert calls == []


def test_a_recorder_failure_drops_the_record(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(**_kwargs: object) -> None:
        raise ValueError("approval gate")

    monkeypatch.setattr(mcp_tool_calls, "allow_tool_call", fail)

    assert not record_mcp_relay_evidence(object(), tmp_path, _record())


def test_the_drain_routes_relay_records_to_the_relay_recorder(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]]
) -> None:
    host = SimpleNamespace(store=object(), guard_home=tmp_path)

    assert is_mcp_relay_evidence(_record())
    assert not is_mcp_relay_evidence({"event": "PreToolUse"})
    assert hook_direct_evidence_drain.record_direct_hook_evidence(host, _record())  # type: ignore[arg-type]
    assert [kind for kind, _ in calls] == ["allow"]
