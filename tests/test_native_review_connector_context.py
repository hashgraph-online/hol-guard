"""A connector-setup review carries its connector into the queue call that stores it."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import hook_native_review_approval as review
from codex_plugin_scanner.guard.local_cli_hook import SetupConnector
from codex_plugin_scanner.guard.models import GuardApprovalRequest

_CLI_ID = "local-cli.lanectl-0123abcd"
_HASH = "a" * 64
_CONNECTOR = SetupConnector(
    cli_id=_CLI_ID,
    identity_hash=_HASH,
    name="lanectl",
    surface="cli",
    queue_group_id=f"connector:{_HASH}:0123456789abcdef",
)


class _ApprovalStore:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}
        self.options: list[dict[str, object]] = []

    def add_approval_request(self, request: GuardApprovalRequest, _now: str) -> str:
        request_id = request.request_id
        self.rows[request_id] = {
            "request_id": request_id,
            "queue_group_id": request.queue_group_id,
            "raw_command_text": request.raw_command_text,
            "trigger_summary": "A new local tool wants to run",
            "why_now": None,
        }
        return request_id

    def get_approval_request(self, request_id: str) -> dict[str, object]:
        return self.rows[request_id]

    def queue_native_review(self, review: dict[str, object], now: str, **options: object) -> dict[str, object]:
        self.options.append(options)
        return self.get_approval_request(self.add_approval_request(SimpleNamespace(**review), now))  # type: ignore[arg-type]


def _native_request(harness: str, payload: dict[str, object], review: dict[str, object], **_k: object) -> dict:
    """The request the resident builds from the ``review_request`` query, reduced to what these tests read."""

    request_id = review["request_id"]
    tool_input = payload["tool_input"]
    assert isinstance(tool_input, dict)
    return {
        "request_id": request_id,
        "harness": harness,
        "artifact_id": f"{harness}:native-pretool:Bash",
        "artifact_name": "Bash",
        "artifact_hash": review["review_binding"] or request_id,
        "policy_action": "review",
        "recommended_scope": "artifact",
        "changed_fields": ["native_pre_tool"],
        "source_scope": "harness",
        "config_path": review["guard_home"],
        "review_command": f"hol-guard approvals approve {request_id}",
        "approval_url": f"{review['approval_center_url']}/requests/{request_id}",
        "workspace": None,
        "artifact_type": "tool_call",
        "launch_target": tool_input["command"],
        "risk_summary": "Needs review.",
        "action_envelope_json": {},
        "raw_command_text": tool_input["command"],
        "queue_group_id": review["queue_group_id"],
    }


def _queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, connector: SetupConnector | None
) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    store = _ApprovalStore()
    monkeypatch.setattr(review, "native_review_policy_binding", lambda **_kwargs: None)
    monkeypatch.setattr(review, "native_review_query", _native_request)
    monkeypatch.setattr(review, "native_review_hint_ask", lambda *_a, **_k: None)
    queued = review.queue_native_pre_tool_review(
        store,
        harness="codex",
        payload={"tool_name": "Bash", "tool_input": {"command": "lanectl status"}, "cwd": str(tmp_path)},
        native_result={"reason_code": "native_command_review_required", "reason": "Needs review."},
        native_receipt=None,
        workspace=tmp_path,
        guard_home=tmp_path / "guard",
        exact_token=None,
        review_binding="binding",
        approval_center_url="http://guard.example.test",
        connector=connector,
    )
    return queued, store.options


def test_a_queued_connector_review_keeps_its_context_in_the_queue_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    queued, options = _queue(tmp_path, monkeypatch, _CONNECTOR)

    assert queued is not None and queued["queue_group_id"] == _CONNECTOR.queue_group_id
    assert [call["connector_context"] for call in options] == [{"cli_id": _CLI_ID, "identity_hash": _HASH}]


def test_an_ordinary_review_queues_no_connector_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    queued, options = _queue(tmp_path, monkeypatch, None)

    assert queued is not None
    assert [call["connector_context"] for call in options] == [None]
