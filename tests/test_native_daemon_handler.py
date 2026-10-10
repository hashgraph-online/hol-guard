"""Daemon handler request validation is answered by the native runtime.

The vectors were recorded from the retired Python handler methods (see
``scripts/record_daemon_handler_vectors.py``) and are shared with the Rust
crate, so a divergence here means the resident or the transport changed
behaviour.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_daemon_handler as handler_transport
from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler
from codex_plugin_scanner.guard.native_daemon_handler import NativeDaemonHandlerError

pytestmark = pytest.mark.native_route_unpinned

_DOCUMENT = json.loads(
    (
        Path(__file__).parent.parent
        / "rust"
        / "crates"
        / "guard-runtime"
        / "tests"
        / "fixtures"
        / "daemon_handler_vectors.json"
    ).read_text(encoding="utf-8")
)
_VECTORS = _DOCUMENT["vectors"]


def _ask(vector: dict[str, object], guard_home: Path) -> handler_transport.HandlerDecision:
    kind, raw = vector["query"]["kind"], vector["raw"]
    if kind in ("policy_upsert", "policy_clear", "requests_clear", "bulk_allow"):
        return handler_transport.native_body_handler(kind, raw, guard_home=guard_home)
    if kind == "requests_list":
        return handler_transport.native_requests_list(raw["query"], guard_home=guard_home)
    if kind == "events_cursor":
        return handler_transport.native_events_cursor(raw["query"], guard_home=guard_home)
    return handler_transport.native_harness_action(raw["action"], raw["payload"], guard_home=guard_home)


def test_vectors_were_recorded_from_the_base_commit_and_cover_every_kind() -> None:
    assert len(_VECTORS) > 1000
    assert len(_DOCUMENT["base_commit"]) == 40
    kinds = {vector["query"]["kind"] for vector in _VECTORS}
    assert kinds == {
        "policy_upsert",
        "policy_clear",
        "requests_clear",
        "bulk_allow",
        "requests_list",
        "harness_action",
        "events_cursor",
    }


def test_decisions_match_recorded_vectors(native_approval_reuse_runtime: Path) -> None:
    mismatches = []
    for vector in _VECTORS:
        expected = vector["expected"]
        decision = _ask(vector, native_approval_reuse_runtime)
        if (
            (decision.outcome, decision.status) != (expected["outcome"], expected["status"])
            or (decision.rejected and decision.body != expected["body"])
            or (not decision.rejected and decision.fields != expected["fields"])
        ):
            mismatches.append(vector["name"])
    assert mismatches == []


def test_unusable_replies_raise_instead_of_deciding(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def refuse(*_args: object, **_kwargs: object) -> None:
        raise NativeDaemonHandlerError("native_daemon_handler_unavailable")

    monkeypatch.setattr(handler_transport, "_decide", refuse)
    with pytest.raises(NativeDaemonHandlerError):
        handler_transport.native_requests_list("limit=5", guard_home=tmp_path)


def test_handler_fails_closed_with_a_503_when_the_resident_cannot_answer(tmp_path: Path) -> None:
    handler = object.__new__(_GuardDaemonHandler)
    handler.server = SimpleNamespace(store=SimpleNamespace(guard_home=tmp_path))  # type: ignore[assignment]
    written: list[tuple[int, dict[str, object]]] = []
    handler._write_json = lambda payload, status=200, **_kwargs: written.append((status, payload))  # type: ignore[method-assign]

    def unavailable() -> handler_transport.HandlerDecision:
        raise NativeDaemonHandlerError("native_daemon_handler_unavailable")

    assert handler._native_handler_decision(unavailable) is None
    assert written == [(503, {"error": "native_handler_policy_unavailable"})]
    rejection = handler_transport.HandlerDecision("reject", 400, {"error": "x"}, {})
    assert handler._native_handler_decision(lambda: rejection) is None
    assert written[-1] == (400, {"error": "x"})
    proceed = handler_transport.HandlerDecision("proceed", 200, {}, {"a": 1})
    assert handler._native_handler_decision(lambda: proceed) is proceed
