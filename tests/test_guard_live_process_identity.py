"""Process-bound proof for suspended hook continuation."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import cast

from codex_plugin_scanner.guard.live_process_identity import current_process_identity, process_identity_matches


def test_current_process_identity_matches_only_the_exact_live_process() -> None:
    identity = current_process_identity()

    assert identity is not None
    assert process_identity_matches(identity) is True
    assert process_identity_matches({**identity, "startToken": "reused-process"}) is False


def test_process_start_query_consumes_the_original_deadline(monkeypatch):
    from codex_plugin_scanner.guard import live_process_identity as module
    from codex_plugin_scanner.guard.mdm import runtime_request

    clock, requests = {"value": 100.0}, []
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["value"])

    def answer(_feature, _command, request, **kwargs):
        assert kwargs["deadline"] == 100.125
        body = request()
        requests.append(body)
        clock["value"] += body["timeout_ms"] / 1000
        return {"start_token": "posix:fixture start"}

    monkeypatch.setattr(runtime_request, "runtime_answer", answer)
    assert module.process_start_token(123, deadline_monotonic=100.125) is None
    assert requests == [{"schema": "process-identity.v1", "op": "start_token", "pid": 123, "timeout_ms": 125}]
    assert module.process_start_token(123, deadline_monotonic=100.125) is None
    assert len(requests) == 1, "an expired process query must not start another child"


def test_a_query_without_a_deadline_is_bounded_end_to_end(monkeypatch):
    from codex_plugin_scanner.guard import live_process_identity as module
    from codex_plugin_scanner.guard.mdm import runtime_request

    monkeypatch.setattr(module.time, "monotonic", lambda: 100.0)
    seen = []

    def answer(_feature, _command, _request, **kwargs):
        seen.append(kwargs)
        return None

    monkeypatch.setattr(runtime_request, "runtime_answer", answer)
    assert module.process_owner_marker(123) is None
    assert module.process_start_token(123, deadline_monotonic=200.0) is None
    assert module.process_start_token(123, deadline_monotonic=101.0) is None
    assert [kwargs.get("deadline") for kwargs in seen] == [103.0, 103.0, 101.0]
    assert all(kwargs.get("timeout_seconds") is None for kwargs in seen)


def test_no_runtime_proves_no_identity(monkeypatch):
    from codex_plugin_scanner.guard import live_process_identity as module
    from codex_plugin_scanner.guard.mdm import runtime_request

    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: None)
    assert module.current_process_identity() is None
    assert module.process_owner_marker(123) is None
    assert module.process_identity_matches({"pid": 123, "startToken": "posix:x"}) is False


def test_process_identity_rejects_unbound_or_extended_payloads() -> None:
    assert process_identity_matches(None) is False
    assert process_identity_matches({"pid": 1}) is False
    assert process_identity_matches({"pid": True, "startToken": "invalid"}) is False
    assert process_identity_matches({"pid": 1, "startToken": "invalid", "extra": True}) is False


def test_process_identity_stops_matching_after_the_process_exits() -> None:
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import json,time; "
                "from codex_plugin_scanner.guard.live_process_identity import current_process_identity; "
                "print(json.dumps(current_process_identity()), flush=True); time.sleep(30)"
            ),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        serialized_identity = cast(str, child.stdout.readline())
        identity = cast(object, json.loads(serialized_identity))
        assert process_identity_matches(identity) is True
    finally:
        child.terminate()
        _ = child.wait(timeout=5)

    assert process_identity_matches(identity) is False
