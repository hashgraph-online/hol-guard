"""The Python allow-hint client builds the resident query and presents only a bound, valid hint.

Which permissions let a command run is decided by the resident
(``extension_allow_hint``) and pinned by the Rust op's own tests and by
``test_guard_extension_allow_hint.py`` against the real runtime. These tests
pin the request the client builds, the cheap pre-filter that spares the resident
a question on the allow path, and the refusal of every reply that is not a bound,
strictly shaped hint: there is no Python answer to fall back to.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard import native_daemon_route as route
from codex_plugin_scanner.guard import native_extension_allow_hint as client
from codex_plugin_scanner.guard import native_resident_decision as shared
from codex_plugin_scanner.guard.native_command_model import _canonical_command_from_native
from codex_plugin_scanner.guard.runtime import extension_allow_hint as hint_module
from codex_plugin_scanner.guard.runtime.command_evaluation import CommandEvaluationInput
from tests.native_command_test_support import real_native_review_fixture
from tests.native_extension_control_support import UNBOUND_DIGEST, bound_reply

pytestmark = pytest.mark.native_route_unpinned

COMMAND = "git add src/app.py"
RESULT_SCHEMA = "guard-extension-allow-hint-result.v1"
HINT: dict[str, object] = {
    "schema": "guard.extension-allow-hint.v1",
    "permission_ids": ["command.git.permission.add"],
    "rule_ids": ["command.git.add"],
    "extension_ids": ["command.git"],
    "relied_permission_ids": [],
    "catalog_digest": "a" * 64,
}


_ENTRIES: dict[Path, CommandEvaluationInput] = {}


@pytest.fixture(autouse=True)
def _entry_before_the_scripted_resident(tmp_path: Path) -> Iterator[None]:
    # The evaluation snapshot's digest comes from the real resident, so the
    # entry is built before a test replaces the resident with a scripted one.
    _ENTRIES[tmp_path] = _build_entry(tmp_path)
    yield
    del _ENTRIES[tmp_path]


def _entry(tmp_path: Path) -> CommandEvaluationInput:
    return _ENTRIES[tmp_path]


def _build_entry(tmp_path: Path) -> CommandEvaluationInput:
    fixture = real_native_review_fixture(COMMAND, cwd=tmp_path, home_dir=tmp_path)
    canonical = _canonical_command_from_native(COMMAND, fixture.payload["command_model"])
    assert canonical is not None
    return CommandEvaluationInput(
        command_text=COMMAND,
        canonical_command=canonical,
        native_extension_evidence=fixture.payload,
        extension_control_snapshot=fixture.snapshot,
        cwd=tmp_path,
        home_dir=tmp_path,
    )


class _Resident:
    """A scripted resident: every ask is recorded and answered by ``reply``."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.transport_kwargs: list[dict[str, Any]] = []


def _resident(monkeypatch: pytest.MonkeyPatch, reply: Callable[[dict[str, Any]], object]) -> _Resident:
    resident = _Resident()
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=object(),
        capabilities=SimpleNamespace(features={"resident-protocol-v2", client.EXTENSION_ALLOW_HINT_FEATURE}),
    )

    def transport(*, request: dict[str, Any], **kwargs: object) -> object:
        resident.requests.append(request)
        resident.transport_kwargs.append(dict(kwargs))
        return reply(request)

    monkeypatch.setattr(shared, "native_runtime_status", lambda: status)
    monkeypatch.setattr(shared, "_resolve_digest_home", lambda _home: Path("/tmp/extension-allow-hint-home"))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(shared, "record_resident", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(route, "_resident_request", transport)
    return resident


def _answers(hint: object) -> Callable[[dict[str, Any]], object]:
    return lambda request: bound_reply(request, {"kind": "allow_hint", "hint": hint}, schema=RESULT_SCHEMA)


def test_the_client_sends_the_evaluation_inputs_and_returns_a_valid_hint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    resident = _resident(monkeypatch, _answers(dict(HINT)))
    entry = _entry(tmp_path)

    hint = client.native_extension_allow_hint(entry, guard_home=tmp_path)

    assert hint == HINT
    assert len(resident.requests) == 1
    request = resident.requests[0]
    assert request["schema"] == "guard-extension-allow-hint-request.v1"
    query = cast(dict[str, Any], request["query"])
    assert set(query) == {
        "kind",
        "command_text",
        "canonical_command",
        "native_extension_evidence",
        "control_snapshot",
        "cwd",
        "home_dir",
    }
    assert query["kind"] == "allow_hint"
    assert query["command_text"] == COMMAND
    assert query["cwd"] == str(tmp_path)
    assert query["home_dir"] == str(tmp_path)
    kwargs = resident.transport_kwargs[0]
    assert kwargs["operation"] == "extension_allow_hint"
    assert kwargs["required_feature"] == client.EXTENSION_ALLOW_HINT_FEATURE
    assert kwargs["response_schema"] == RESULT_SCHEMA


def test_a_null_hint_is_no_hint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    resident = _resident(monkeypatch, _answers(None))

    assert client.native_extension_allow_hint(_entry(tmp_path), guard_home=tmp_path) is None
    assert len(resident.requests) == 1


def test_a_deadline_bounds_the_ask_and_becomes_a_relative_reduction_budget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    resident = _resident(monkeypatch, _answers(None))
    entry = _entry(tmp_path)

    client.native_extension_allow_hint(entry, guard_home=tmp_path)
    client.native_extension_allow_hint(entry, guard_home=tmp_path, deadline=time.monotonic() + 3.0)
    client.native_extension_allow_hint(entry, guard_home=tmp_path, deadline=time.monotonic() + 3600.0)

    unbounded, bounded, capped = resident.requests
    assert "reduction_budget_ms" not in cast(dict[str, Any], unbounded["query"])
    assert resident.transport_kwargs[0]["timeout_seconds"] == pytest.approx(5.0, abs=0.1)
    # The ask never outlives the deadline, and its reduction budget leaves slack
    # for the resident to answer the verified full set.
    assert 0 < resident.transport_kwargs[1]["timeout_seconds"] <= 3.0
    bounded_budget = cast(dict[str, Any], bounded["query"])["reduction_budget_ms"]
    assert 0 < bounded_budget < resident.transport_kwargs[1]["timeout_seconds"] * 1000
    assert resident.transport_kwargs[2]["timeout_seconds"] == pytest.approx(5.0, abs=0.1)
    assert cast(dict[str, Any], capped["query"])["reduction_budget_ms"] == 3000


@pytest.mark.parametrize("offset", [-1.0, 0.0])
def test_a_spent_deadline_asks_nothing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, offset: float) -> None:
    resident = _resident(monkeypatch, _answers(dict(HINT)))

    hint = client.native_extension_allow_hint(_entry(tmp_path), guard_home=tmp_path, deadline=time.monotonic() + offset)

    assert hint is None
    assert resident.requests == []


def test_the_client_never_sends_a_request_the_resident_refuses_as_too_large() -> None:
    assert client._MAX_REQUEST_BYTES == 1024 * 1024  # pyright: ignore[reportPrivateUsage]


def test_a_hint_naming_more_than_three_permissions_is_no_hint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def hint_with(count: int) -> dict[str, object]:
        return {**HINT, "permission_ids": [f"command.git.permission.p{index}" for index in range(count)]}

    _resident(monkeypatch, _answers(hint_with(3)))
    assert client.native_extension_allow_hint(_entry(tmp_path), guard_home=tmp_path) == hint_with(3)

    _resident(monkeypatch, _answers(hint_with(4)))
    assert client.native_extension_allow_hint(_entry(tmp_path), guard_home=tmp_path) is None


@pytest.mark.parametrize(
    "hint",
    [
        {**HINT, "surprise": True},
        {key: value for key, value in HINT.items() if key != "relied_permission_ids"},
        {**HINT, "schema": "guard.extension-allow-hint.v2"},
        {**HINT, "permission_ids": []},
        {**HINT, "permission_ids": ["not-a-command-id"]},
        {**HINT, "permission_ids": "command.git.permission.add"},
        {**HINT, "relied_permission_ids": [f"command.git.permission.p{index}" for index in range(13)]},
        {**HINT, "catalog_digest": "short"},
        {**HINT, "catalog_digest": 7},
        ["command.git.permission.add"],
        "hint",
    ],
)
def test_a_malformed_hint_is_no_hint(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, hint: object) -> None:
    _resident(monkeypatch, _answers(hint))

    assert client.native_extension_allow_hint(_entry(tmp_path), guard_home=tmp_path) is None


@pytest.mark.parametrize(
    "reply",
    [
        lambda request: bound_reply(
            request, {"kind": "allow_hint", "hint": None}, schema=RESULT_SCHEMA, status="error"
        ),
        lambda request: bound_reply(
            request,
            {"kind": "allow_hint", "hint": None},
            schema=RESULT_SCHEMA,
            status="error",
            code="native_extension_allow_hint_too_large",
        ),
        lambda request: bound_reply(
            request, {"kind": "allow_hint", "hint": None}, schema=RESULT_SCHEMA, request_sha256=UNBOUND_DIGEST
        ),
        lambda request: bound_reply(
            request, {"kind": "allow_hint", "hint": None}, schema=RESULT_SCHEMA, request_id="another-request"
        ),
        lambda request: bound_reply(request, {"kind": "allow_hint", "hint": None}, schema="guard-other-result.v1"),
        lambda request: bound_reply(request, {"kind": "compose", "hint": None}, schema=RESULT_SCHEMA),
        lambda request: bound_reply(request, {"kind": "allow_hint"}, schema=RESULT_SCHEMA),
        lambda request: bound_reply(request, {"kind": "allow_hint", "hint": None, "extra": 1}, schema=RESULT_SCHEMA),
        lambda request: bound_reply(
            request, {"kind": "allow_hint", "hint": dict(HINT)}, schema=RESULT_SCHEMA, code="x"
        ),
        lambda _request: None,
        lambda _request: "not a reply",
    ],
)
def test_an_unbound_or_refused_reply_is_no_hint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reply: Callable[[dict[str, Any]], object]
) -> None:
    _resident(monkeypatch, reply)

    assert client.native_extension_allow_hint(_entry(tmp_path), guard_home=tmp_path) is None


def test_an_unavailable_resident_is_no_hint_and_never_recomputed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    resident = _resident(monkeypatch, _answers(dict(HINT)))
    monkeypatch.setattr(shared, "ensure_resident_prerequisite", lambda _home: False)

    assert client.native_extension_allow_hint(_entry(tmp_path), guard_home=tmp_path) is None
    assert resident.requests == []


REVIEW_EVIDENCE: dict[str, object] = {
    "minimum_action": "review",
    "reason_code": "native_command_review_required",
}


def _stub_evaluation(action: str) -> Any:
    return SimpleNamespace(decision_plane=SimpleNamespace(action=action), command=object())


def _recording_client(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def ask(entry: CommandEvaluationInput, **kwargs: object) -> dict[str, object]:
        calls.append({"entry": entry, **kwargs})
        return dict(HINT)

    monkeypatch.setattr(hint_module, "native_extension_allow_hint", ask)
    return calls


@pytest.mark.parametrize("action", ["allow", "block", "deny"])
def test_a_command_that_is_not_held_for_review_costs_no_resident_question(
    monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    calls = _recording_client(monkeypatch)

    hint = hint_module.compute_extension_allow_hint(
        _stub_evaluation(action),
        command_text=COMMAND,
        snapshot=SimpleNamespace(authority_failure=None, awaiting_enrollment=False),
        native_evidence={},
    )

    assert hint is None
    assert calls == []


def test_an_authority_failure_costs_no_resident_question(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _recording_client(monkeypatch)

    hint = hint_module.compute_extension_allow_hint(
        _stub_evaluation("review"),
        command_text=COMMAND,
        snapshot=SimpleNamespace(authority_failure="unavailable", awaiting_enrollment=False),
        native_evidence=dict(REVIEW_EVIDENCE),
    )

    assert hint is None
    assert calls == []


@pytest.mark.parametrize("action", ["allow", "block", "review"])
def test_a_device_that_never_enrolled_asks_the_resident_whatever_it_answered_locally(
    monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    calls = _recording_client(monkeypatch)
    snapshot = SimpleNamespace(authority_failure="unavailable", awaiting_enrollment=True)

    hint = hint_module.compute_extension_allow_hint(
        _stub_evaluation(action),
        command_text=COMMAND,
        snapshot=snapshot,
        native_evidence=dict(REVIEW_EVIDENCE),
    )

    assert hint == HINT
    assert len(calls) == 1
    assert calls[0]["entry"].extension_control_snapshot is snapshot


@pytest.mark.parametrize(
    "evidence",
    [
        {**REVIEW_EVIDENCE, "minimum_action": "block"},
        {**REVIEW_EVIDENCE, "reason_code": "native_sensitive_access_review"},
        {"minimum_action": "review"},
        {},
    ],
)
def test_a_fixed_floor_review_costs_no_resident_question(
    monkeypatch: pytest.MonkeyPatch, evidence: dict[str, object]
) -> None:
    calls = _recording_client(monkeypatch)

    hint = hint_module.compute_extension_allow_hint(
        _stub_evaluation("review"),
        command_text=COMMAND,
        snapshot=SimpleNamespace(authority_failure=None, awaiting_enrollment=False),
        native_evidence=evidence,
    )

    assert hint is None
    assert calls == []


@pytest.mark.parametrize("action", ["review", "require-reapproval"])
def test_a_held_review_asks_the_resident_with_its_home_and_deadline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, action: str
) -> None:
    calls = _recording_client(monkeypatch)
    deadline = time.monotonic() + 1.0
    snapshot = SimpleNamespace(authority_failure=None, awaiting_enrollment=False)

    hint = hint_module.compute_extension_allow_hint(
        _stub_evaluation(action),
        command_text=COMMAND,
        snapshot=snapshot,
        native_evidence=dict(REVIEW_EVIDENCE),
        cwd=tmp_path,
        home_dir=tmp_path,
        guard_home=tmp_path / "guard-home",
        deadline=deadline,
    )

    assert hint == HINT
    assert len(calls) == 1
    assert calls[0]["guard_home"] == tmp_path / "guard-home"
    assert calls[0]["deadline"] == deadline
    entry = calls[0]["entry"]
    assert entry.command_text == COMMAND
    assert entry.native_extension_evidence == REVIEW_EVIDENCE
    assert entry.extension_control_snapshot is snapshot
    assert entry.cwd == tmp_path
    assert entry.home_dir == tmp_path


def test_the_shim_keeps_no_decision_logic() -> None:
    assert not hasattr(hint_module, "evaluate_command")
    assert not hasattr(hint_module, "MAX_HINT_PERMISSIONS")
