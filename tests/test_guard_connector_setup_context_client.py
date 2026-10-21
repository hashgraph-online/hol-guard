"""The connector setup context client, and the review queue that calls it."""

from __future__ import annotations

import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import connector_setup_context as context
from codex_plugin_scanner.guard.connector_setup_context import (
    CONNECTOR_SETUP_CONTEXT_FEATURE,
    ConnectorSetupAdvice,
    record_connector_setup_context,
    scrub_connector_context_text,
)
from codex_plugin_scanner.guard.daemon import hook_native_review_approval as review
from codex_plugin_scanner.guard.daemon import native_review_connector
from codex_plugin_scanner.guard.local_cli_hook import SetupConnector
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

_CLI_ID = "local-cli.lanectl-0123abcd"
_HASH = "a" * 64
_CONNECTOR = SetupConnector(
    cli_id=_CLI_ID,
    identity_hash=_HASH,
    name="lanectl",
    surface="cli",
    queue_group_id=f"connector:{_HASH}:0123456789abcdef",
)


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "cli_id": _CLI_ID,
        "identity_hash": _HASH,
        "surface": "cli",
        "first_blocked_cause": "connect_loopback",
        "resolution_state": "unset",
        "allowed_alternatives": {"tools": [], "subcommands": ["status"], "catalog_contributions": []},
        "card_recommendation": {"kind": "cli-capability", "capability": "loopback-network", "preselected": False},
    }
    payload.update(overrides)
    return payload


class _Resident:
    """A resident that answers like the real one, from the request it was sent."""

    def __init__(self, *, status: str = "ok", code: str = "ok", payload: object = None, **tamper: object) -> None:
        self.status, self.code, self.payload, self.tamper = status, code, payload, tamper
        self.calls: list[dict[str, object]] = []

    def __call__(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        request = kwargs["request"]
        assert isinstance(request, dict)
        reply: dict[str, object] = {
            "schema": "guard-connector-setup-context-result.v1",
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": self.status,
            "code": self.code,
            "payload": _payload() if self.payload is None else self.payload,
        }
        reply.update(self.tamper)
        return reply


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    repaired: list[bool] = []

    @contextmanager
    def gate(_home: Path, *, exclusive: bool) -> Iterator[None]:
        assert exclusive is False
        yield

    monkeypatch.setattr(context, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(context.store_storage_gate, "hold_storage_gate", gate)
    return SimpleNamespace(
        path=tmp_path / "guard.db",
        guard_home=tmp_path,
        guard_source="local",
        _repair_store_permissions=lambda: repaired.append(True),
        repaired=repaired,
    )


def _call(store: SimpleNamespace, **fields: object) -> ConnectorSetupAdvice | None:
    return record_connector_setup_context(store, cli_id=_CLI_ID, identity_hash=_HASH, **fields)  # pyright: ignore[reportArgumentType]


def test_the_call_names_the_op_the_feature_and_what_it_scrubbed(
    store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    resident = _Resident()
    monkeypatch.setattr(context, "_resident_request", resident)

    advice = _call(
        store,
        first_blocked_cause="connect_loopback",
        trigger_summary="lanectl reached https://u:p@mcp.example.test/hook?t=1",
        why_now="Authorization: Bearer abcdef0123456789",
        harness="codex",
        workspace_label="app",
    )

    (call,) = resident.calls
    assert call["operation"] == "connector_setup_context"
    assert call["required_feature"] == CONNECTOR_SETUP_CONTEXT_FEATURE == "connector-setup-context-v1"
    assert call["response_schema"] == "guard-connector-setup-context-result.v1"
    request = call["request"]
    assert isinstance(request, dict)
    assert request["schema"] == "guard-connector-setup-context-request.v1"
    assert request["cli_id"] == _CLI_ID and request["identity_hash"] == _HASH
    assert request["first_blocked_cause"] == "connect_loopback"
    assert request["trigger_summary"] == "lanectl reached https://mcp.example.test/hook"
    assert "abcdef0123456789" not in str(request["why_now"])
    assert request["harness"] == "codex" and request["workspace_label"] == "app"
    assert isinstance(request["observed_at"], str) and str(request["observed_at"]).endswith("+00:00")
    assert advice is not None
    assert (advice.cli_id, advice.identity_hash, advice.surface) == (_CLI_ID, _HASH, "cli")
    assert advice.first_blocked_cause == "connect_loopback"
    assert advice.resolution_state == "unset"
    assert advice.allowed_alternatives.subcommands == ("status",)
    assert advice.card_recommendation["capability"] == "loopback-network"
    assert advice.card_recommendation["preselected"] is False
    assert store.repaired == [True]


def test_an_unknown_cause_is_refused_before_any_call(store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _Resident()
    monkeypatch.setattr(context, "_resident_request", resident)

    with pytest.raises(ValueError, match="invalid_first_blocked_cause"):
        _call(store, first_blocked_cause="sudo")

    assert resident.calls == []


def test_the_wait_never_exceeds_the_callers_budget(store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _Resident()
    monkeypatch.setattr(context, "_resident_request", resident)

    assert _call(store, budget_seconds=0.75) is not None

    assert resident.calls[0]["timeout_seconds"] == 0.75


@pytest.mark.parametrize("budget", [0.0, -1.0])
def test_a_spent_budget_makes_no_call(store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, budget: float) -> None:
    resident = _Resident()
    monkeypatch.setattr(context, "_resident_request", resident)

    assert _call(store, budget_seconds=budget) is None
    assert resident.calls == []


def test_without_a_resident_there_is_no_advice(store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _Resident()
    monkeypatch.setattr(context, "_resident_request", resident)
    monkeypatch.setattr(context, "ensure_resident_prerequisite", lambda _home: False)

    assert _call(store) is None
    assert resident.calls == []


def test_an_unanswered_call_gives_no_advice(store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(context, "_resident_request", lambda **_kwargs: None)

    assert _call(store) is None


@pytest.mark.parametrize(
    "tamper",
    [
        {"schema": "other.v1"},
        {"request_id": "another"},
        {"request_sha256": "sha256:" + "0" * 64},
        {"status": "error", "code": "native_connector_setup_context_schema_outdated"},
        {"status": "ok", "code": "other"},
    ],
)
def test_a_reply_that_is_not_ours_or_not_ok_gives_no_advice(
    store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, tamper: dict[str, object]
) -> None:
    monkeypatch.setattr(context, "_resident_request", _Resident(**tamper))

    assert _call(store) is None


def test_a_payload_that_is_not_an_object_gives_no_advice(
    store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(context, "_resident_request", _Resident(payload="not an object"))

    assert _call(store) is None


@pytest.mark.parametrize(
    "payload",
    [
        _payload(cli_id="local-cli.other-1"),
        _payload(identity_hash="b" * 64),
        _payload(resolution_state="approved"),
        _payload(surface=None),
        _payload(first_blocked_cause=3),
        _payload(allowed_alternatives=None),
        _payload(card_recommendation={"kind": "mcp-tools", "preselected": True}),
        _payload(card_recommendation={"kind": "mcp-tools"}),
    ],
)
def test_advice_for_another_connector_or_one_that_preselects_is_refused(
    store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]
) -> None:
    monkeypatch.setattr(context, "_resident_request", _Resident(payload=payload))

    assert _call(store) is None


def test_the_mcp_advice_lists_the_tools_it_allows(store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _payload(
        surface="mcp",
        first_blocked_cause=None,
        resolution_state="allowed",
        allowed_alternatives={"tools": ["search", 4, "read"], "subcommands": [], "catalog_contributions": []},
        card_recommendation={
            "kind": "mcp-tools",
            "seen_tools": ["search"],
            "seen_tools_action": "allow",
            "other_tools_action": "review",
            "preselected": False,
        },
    )
    monkeypatch.setattr(context, "_resident_request", _Resident(payload=payload))

    advice = _call(store)

    assert advice is not None
    assert advice.surface == "mcp" and advice.first_blocked_cause is None
    assert advice.resolution_state == "allowed"
    assert advice.allowed_alternatives.tools == ("search", "read")
    assert advice.card_recommendation["seen_tools_action"] == "allow"
    assert advice.card_recommendation["other_tools_action"] == "review"


def test_a_store_failure_raises_as_a_store_call_would(store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        context, "_resident_request", _Resident(status="error", code="native_guard_store_value_error", payload={})
    )

    with pytest.raises(ValueError):
        _call(store)


def test_an_expired_operation_deadline_stops_before_the_call(
    store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    resident = _Resident()
    monkeypatch.setattr(context, "_resident_request", resident)
    monkeypatch.setattr(context, "sqlite_operation_deadline_monotonic", lambda: time.monotonic() - 1)

    with pytest.raises(TimeoutError):
        _call(store)

    assert resident.calls == []


def test_a_live_deadline_caps_the_wait(store: SimpleNamespace, monkeypatch: pytest.MonkeyPatch) -> None:
    resident = _Resident()
    monkeypatch.setattr(context, "_resident_request", resident)
    monkeypatch.setattr(context, "sqlite_operation_deadline_monotonic", lambda: time.monotonic() + 0.5)

    _call(store)

    timeout = resident.calls[0]["timeout_seconds"]
    assert isinstance(timeout, float) and 0 < timeout <= 0.5


@pytest.mark.parametrize(
    ("raw", "kept", "dropped"),
    [
        (
            "open https://user:pw@mcp.example.test/v1/tools?token=abc#frag now",
            "https://mcp.example.test/v1/tools",
            "pw@",
        ),
        ("a http://mcp.example.test?q=1 b", "http://mcp.example.test b", "q=1"),
        ("password: hunter2value ok", "ok", "hunter2value"),
        ("  runs\n\tlanectl \x07 sync  ", "runs lanectl sync", "\x07"),
    ],
)
def test_context_text_keeps_no_credential_query_or_control_character(raw: str, kept: str, dropped: str) -> None:
    text = scrub_connector_context_text(raw, limit=240)

    assert text is not None and kept in text and dropped not in text


def test_context_text_is_capped_and_empty_text_is_none() -> None:
    assert len(scrub_connector_context_text("é" * 500, limit=240) or "") == 240
    assert scrub_connector_context_text(" \n ", limit=80) is None
    assert scrub_connector_context_text(None, limit=80) is None
    assert scrub_connector_context_text(12, limit=80) is None


def _stored(**fields: object) -> dict[str, object]:
    return {
        "request_id": "abc",
        "trigger_summary": "A new local tool wants to run",
        "why_now": "It has not been set up",
        "raw_command_text": "lanectl status --verbose",
        **fields,
    }


def _record(
    monkeypatch: pytest.MonkeyPatch,
    *,
    reason_code: object = "native_command_review_required",
    stored: Mapping[str, object] | None = None,
    workspace: Path | None = Path("/work/app"),
    deadline: float | None = None,
) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    def fake(_store: object, **kwargs: object) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(context, "record_connector_setup_context", fake)
    native_review_connector.record_native_review_connector_context(
        object(),
        connector=_CONNECTOR,
        native_result={"reason_code": reason_code},
        stored=_stored() if stored is None else stored,
        harness="codex",
        workspace=workspace,
        deadline=deadline,
    )
    return calls


@pytest.mark.parametrize(
    ("reason_code", "cause"),
    [
        ("native_workspace_containment_executable_outside_roots", "exec_outside_roots"),
        ("native_command_review_required", "unrecognised_tool"),
        ("native_network_review", None),
        (None, None),
    ],
)
def test_the_review_reason_names_the_first_cause(
    monkeypatch: pytest.MonkeyPatch, reason_code: str | None, cause: str | None
) -> None:
    (call,) = _record(monkeypatch, reason_code=reason_code)

    assert call["first_blocked_cause"] == cause
    assert call["cli_id"] == _CLI_ID and call["identity_hash"] == _HASH
    assert call["harness"] == "codex"
    assert call["workspace_label"] == "app"
    assert call["trigger_summary"] == "A new local tool wants to run"
    assert call["why_now"] == "It has not been set up"


def test_review_wording_that_repeats_an_operand_is_not_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    stored = _stored(trigger_summary="lanectl ran with --verbose", why_now="")

    (call,) = _record(monkeypatch, stored=stored)

    assert call["trigger_summary"] is None
    assert call["why_now"] is None


def test_a_review_without_a_workspace_has_no_workspace_label(monkeypatch: pytest.MonkeyPatch) -> None:
    (call,) = _record(monkeypatch, workspace=None)

    assert call["workspace_label"] is None


def test_the_hook_deadline_caps_the_context_write(monkeypatch: pytest.MonkeyPatch) -> None:
    (call,) = _record(monkeypatch, deadline=time.monotonic() + 3.0)

    budget = call["budget_seconds"]
    assert isinstance(budget, float) and 0.0 < budget < 3.0


@pytest.mark.parametrize("remaining", [0.0, 0.3, -2.0])
def test_a_nearly_spent_hook_deadline_skips_the_context_write(
    monkeypatch: pytest.MonkeyPatch, remaining: float
) -> None:
    assert _record(monkeypatch, deadline=time.monotonic() + remaining) == []


@pytest.mark.parametrize("error", [OSError("x"), RuntimeError("x"), ValueError("x"), TimeoutError("x")])
def test_a_failed_context_record_never_blocks_the_review(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    def fail(_store: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(context, "record_connector_setup_context", fail)

    assert (
        native_review_connector.record_native_review_connector_context(
            object(),
            connector=_CONNECTOR,
            native_result={"reason_code": "native_command_review_required"},
            stored=_stored(),
            harness="codex",
            workspace=None,
        )
        is None
    )


class _ApprovalStore:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, object]] = {}

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


def _queue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, connector: SetupConnector | None, deadline: float | None = None
) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    recorded: list[dict[str, object]] = []

    def record(_store: object, **kwargs: object) -> None:
        recorded.append(kwargs)

    monkeypatch.setattr(review, "record_native_review_connector_context", record)
    monkeypatch.setattr(review, "native_review_policy_binding", lambda **_kwargs: None)
    monkeypatch.setattr(review, "_native_review_action_envelope", lambda **_kwargs: {})
    monkeypatch.setattr(review, "native_review_hint", lambda *_a, **_k: None)
    queued = review.queue_native_pre_tool_review(
        _ApprovalStore(),
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
        deadline=deadline,
    )
    return queued, recorded


def test_a_queued_connector_review_records_its_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    queued, recorded = _queue(tmp_path, monkeypatch, _CONNECTOR)

    assert queued is not None and queued["queue_group_id"] == _CONNECTOR.queue_group_id
    (call,) = recorded
    assert call["connector"] == _CONNECTOR
    assert call["harness"] == "codex" and call["workspace"] == tmp_path
    stored = call["stored"]
    assert isinstance(stored, dict) and stored["request_id"] == queued["request_id"]


def test_a_queued_connector_review_passes_the_hook_deadline_on(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    deadline = time.monotonic() + 5.0

    _queued, recorded = _queue(tmp_path, monkeypatch, _CONNECTOR, deadline)

    assert [call["deadline"] for call in recorded] == [deadline]


def test_an_ordinary_review_records_no_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    queued, recorded = _queue(tmp_path, monkeypatch, None)

    assert queued is not None
    assert recorded == []
