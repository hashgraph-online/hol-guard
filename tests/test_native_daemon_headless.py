"""Headless app action responses are decided by the native runtime.

The vectors were recorded from the retired Python response builders (see
``scripts/record_daemon_headless_vectors.py``) and are shared with the Rust
crate, so a divergence here means the resident or the transport changed
behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_daemon_handler as transport
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from codex_plugin_scanner.guard.native_daemon_handler import NativeDaemonHandlerError
from codex_plugin_scanner.guard.runtime import runner

pytestmark = pytest.mark.native_route_unpinned

_DOCUMENT = json.loads(
    (
        Path(__file__).parent.parent
        / "rust"
        / "crates"
        / "guard-runtime"
        / "tests"
        / "fixtures"
        / "daemon_headless_vectors.json"
    ).read_text(encoding="utf-8")
)
_VECTORS = _DOCUMENT["vectors"]


def _error(raw: dict[str, object]) -> Exception:
    message = str(raw["message"])
    return {
        "authorization_expired": runner.GuardSyncAuthorizationExpiredError(message),
        "not_configured": runner.GuardSyncNotConfiguredError(message),
        "not_available": runner.GuardSyncNotAvailableError(message, retryable=bool(raw["retryable"])),
        "other": RuntimeError(message),
    }[str(raw["error"])]


def _call(vector: dict[str, object], guard_home: Path) -> object:
    kind, raw = vector["query"]["kind"], vector["raw"]
    if kind == "headless_error":
        return transport.native_headless_action_error(raw["operation"], raw["error_code"], guard_home=guard_home)
    if kind == "headless_cursor_surface":
        return transport.native_headless_cursor_surface_error(guard_home=guard_home)
    if kind == "headless_state":
        return transport.native_headless_action_state(
            raw["harness"], raw["operation"], raw["result"], guard_home=guard_home
        )
    if kind == "detection_statuses":
        return transport.native_detection_app_statuses(raw["values"], guard_home=guard_home)
    return transport.native_supply_chain_error(raw["operation"], _error(raw), guard_home=guard_home)


def test_vectors_were_recorded_from_the_base_commit_and_cover_every_kind() -> None:
    assert len(_VECTORS) > 1500
    assert len(_DOCUMENT["base_commit"]) == 40
    assert {vector["query"]["kind"] for vector in _VECTORS} == {
        "headless_error",
        "headless_cursor_surface",
        "headless_state",
        "detection_statuses",
        "supply_chain_sync_error",
    }


def test_responses_match_recorded_vectors(native_approval_reuse_runtime: Path) -> None:
    mismatches = []
    for vector in _VECTORS:
        expected = vector["expected"]
        answer = _call(vector, native_approval_reuse_runtime)
        if expected["outcome"] == "reject":
            matches = answer == (expected["status"], expected["body"])
        elif vector["query"]["kind"] == "detection_statuses":
            matches = answer == expected["fields"]["app_statuses"]
        else:
            matches = answer == expected["fields"]
        if not matches:
            mismatches.append(vector["name"])
    assert mismatches == []


def test_the_transport_sends_the_recorded_queries(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class CapturedError(Exception):
        pass

    def capture(query: dict[str, object], *_args: object, **_kwargs: object) -> None:
        raise CapturedError(query)

    monkeypatch.setattr(transport, "_decide", capture)
    for vector in _VECTORS:
        with pytest.raises(CapturedError) as captured:
            _call(vector, tmp_path)
        assert captured.value.args[0] == vector["query"], vector["name"]


@pytest.mark.parametrize(
    ("kind", "outcome", "fields"),
    [
        ("headless_error", "proceed", {}),
        ("supply_chain_sync_error", "proceed", {}),
        ("headless_cursor_surface", "proceed", {}),
        ("headless_state", "reject", {}),
        ("detection_statuses", "reject", {}),
        ("headless_state", "proceed", {"app_status": "protected"}),
        (
            "headless_state",
            "proceed",
            {"app_status": "protected", "message": "m", "outcome": "o", "proof_status": "p", "retryable": 1},
        ),
        ("detection_statuses", "proceed", {"app_statuses": [1]}),
        ("detection_statuses", "proceed", {"app_statuses": "protected"}),
    ],
)
def test_bound_replies_with_unusable_shapes_raise(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str, outcome: str, fields: dict[str, object]
) -> None:
    def answer(query, guard_home, shape, validate, **_kwargs):  # type: ignore[no-untyped-def]
        validate({"kind": kind, "outcome": outcome, "status": 400, "body": {}, "fields": fields})
        raise AssertionError("an unusable reply was accepted")

    monkeypatch.setattr(transport, "_decide", answer)
    with pytest.raises(NativeDaemonHandlerError):
        transport.native_headless_action_error("install", "missing_harness", guard_home=tmp_path)


def test_a_status_count_that_differs_from_the_request_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        transport,
        "_ask",
        lambda *_a, **_k: transport.HandlerDecision("proceed", 200, {}, {"app_statuses": ["protected"]}),
    )
    with pytest.raises(NativeDaemonHandlerError):
        transport.native_detection_app_statuses(["a", "b"], guard_home=tmp_path)


def test_a_failed_action_answers_503_when_the_resident_cannot_answer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise NativeDaemonHandlerError("native_daemon_handler_unavailable")

    monkeypatch.setattr(transport, "_decide", unavailable)
    handler = object.__new__(_GuardDaemonHandler)
    handler.server = SimpleNamespace(store=SimpleNamespace(guard_home=tmp_path))  # type: ignore[assignment]
    status, payload = handler._headless_app_action_payload(action_path="connect", payload={})
    assert (status, payload) == (503, {"error": "native_handler_policy_unavailable"})
