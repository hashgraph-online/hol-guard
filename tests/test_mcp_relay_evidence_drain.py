from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest

from codex_plugin_scanner.guard import mcp_tool_calls, native_mcp_tool_call_identity
from codex_plugin_scanner.guard.approval_gate_types import ApprovalGateError
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


@pytest.mark.parametrize("field", ["approval_center_url", "review_url", "request_id"])
def test_an_approval_the_agent_could_not_act_on_drops_the_record(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], field: str
) -> None:
    approval = {
        "approval_center_url": "http://127.0.0.1:8787",
        "review_url": "http://127.0.0.1:8787/requests/req-1",
        "request_id": "req-1",
        "workspace": None,
        "notices": [],
        field: "   ",
    }
    record = _record(
        outcome="block",
        policy_action="review",
        decision_source="approval-center-pending",
        approval=approval,
    )

    assert not record_mcp_relay_evidence(object(), tmp_path, record)
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


def test_an_inline_approved_forward_remembers_its_allow(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]]
) -> None:
    record = _record(decision_source="inline-approved", remember=True)

    assert record_mcp_relay_evidence(object(), tmp_path, record)

    [(remembered_kind, remembered), (kind, recorded)] = calls
    assert remembered_kind == "allow"
    assert remembered["remember"] is True
    assert remembered["emit_runtime_evidence"] is False
    assert remembered["decision_source"] == "inline-approved"
    # The receipt follows, as `_allow_and_forward` writes it after the forward.
    assert kind == "allow"
    assert recorded["remember"] is False
    assert "emit_runtime_evidence" not in recorded


def test_a_closed_gate_costs_the_memory_not_the_receipt(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    def allow_tool_call(**kwargs: Any) -> None:
        if kwargs.get("remember"):
            raise ApprovalGateError("approval_gate_locked", "locked")
        calls.append(("allow", kwargs))

    monkeypatch.setattr(mcp_tool_calls, "allow_tool_call", allow_tool_call)

    assert record_mcp_relay_evidence(object(), tmp_path, _record(decision_source="inline-approved", remember=True))

    [(kind, recorded)] = calls
    assert kind == "allow"
    assert recorded["remember"] is False


def test_a_refused_memory_write_costs_the_memory_not_the_receipt(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The call was forwarded, so no failure of the policy write loses its receipt."""

    def allow_tool_call(**kwargs: Any) -> None:
        if kwargs.get("remember"):
            raise sqlite3.OperationalError("database is locked")
        calls.append(("allow", kwargs))

    monkeypatch.setattr(mcp_tool_calls, "allow_tool_call", allow_tool_call)

    assert record_mcp_relay_evidence(object(), tmp_path, _record(decision_source="inline-approved", remember=True))

    [(kind, recorded)] = calls
    assert kind == "allow"
    assert recorded["remember"] is False


@pytest.mark.parametrize(
    "fields",
    [
        {"remember": True},
        {"decision_source": "inline-approved", "remember": False},
        {"decision_source": "inline-approved", "remember": "yes"},
        {
            "outcome": "block",
            "decision_source": "inline-denied",
            "policy_action": "block",
            "decision": _decision("block"),
            "remember": True,
        },
    ],
)
def test_only_an_inline_approved_forward_remembers_its_allow(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], fields: dict[str, object]
) -> None:
    assert not record_mcp_relay_evidence(object(), tmp_path, _record(**fields))
    assert calls == []


@pytest.mark.parametrize("decision_source", ["inline-denied", "inline-invalid"])
def test_a_refused_inline_prompt_blocks_the_call_on_its_own(
    tmp_path: Path, calls: list[tuple[str, dict[str, Any]]], decision_source: str
) -> None:
    record = _record(
        outcome="block",
        decision_source=decision_source,
        policy_action="block",
        decision=_decision("block"),
    )

    assert record_mcp_relay_evidence(object(), tmp_path, record)

    [(kind, recorded)] = calls
    assert kind == "block"
    assert recorded["decision_source"] == decision_source


def test_a_refused_inline_prompt_carries_no_inbox_row(tmp_path: Path, calls: list[tuple[str, dict[str, Any]]]) -> None:
    record = _record(
        outcome="block",
        decision_source="inline-denied",
        policy_action="block",
        decision=_decision("block"),
        review={"redaction_level": "full"},
    )

    assert not record_mcp_relay_evidence(object(), tmp_path, record)
    assert calls == []
