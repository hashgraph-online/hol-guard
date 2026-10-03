"""Process-bound proof for suspended hook continuation."""

from __future__ import annotations

import json
import subprocess
import sys
from typing import cast

import pytest

from codex_plugin_scanner.guard.live_process_identity import current_process_identity, process_identity_matches


def test_current_process_identity_matches_only_the_exact_live_process() -> None:
    identity = current_process_identity()

    assert identity is not None
    assert process_identity_matches(identity) is True
    assert process_identity_matches({**identity, "startToken": "reused-process"}) is False


@pytest.mark.skipif(sys.platform == "win32", reason="models POSIX process identity query")
def test_process_start_query_consumes_the_original_deadline(monkeypatch):
    from codex_plugin_scanner.guard import live_process_identity as module

    clock, timeouts = {"value": 100.0}, []
    monkeypatch.setattr(module.time, "monotonic", lambda: clock["value"])
    monkeypatch.setattr(module, "_linux_proc_stat", lambda _pid: None)
    monkeypatch.setattr(module, "_trusted_posix_ps_path", lambda: "/usr/bin/ps")

    def query(*args, **kwargs):
        timeouts.append(kwargs["timeout"])
        clock["value"] += kwargs["timeout"]
        return subprocess.CompletedProcess(args, 0, stdout="fixture start\n")

    monkeypatch.setattr(module.subprocess, "run", query)
    assert module.process_start_token(123, deadline_monotonic=100.125) is None
    assert timeouts == [0.125]
    assert module.process_start_token(123, deadline_monotonic=100.125) is None
    assert timeouts == [0.125], "an expired process query must not start another child"


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
