from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import native_slo_daemon_fixture as fixture
from scripts.native_slo_failure import FixtureFailureError, failure_evidence


@pytest.mark.skipif(
    os.name == "nt", reason="POSIX fake process launch; production uses the tested Windows Job launcher"
)
def test_private_fixture_control_uses_separate_process_and_acknowledged_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ready = {
        "state": "ready",
        "root": str(tmp_path),
        "workspace": str(tmp_path),
        "guard_home": str(tmp_path),
        "readiness_ms": 10,
        "port": 8123,
        "auth_token": "synthetic-private-token",
    }
    program = f"""
import json, sys
print({json.dumps(json.dumps(ready))}, flush=True)
for line in sys.stdin:
    op=json.loads(line)['op']
    if op=='snapshot':
        print(json.dumps({{'routes': {{'native_resident': 1}}}}), flush=True)
    elif op=='close':
        print(json.dumps({{'closed': True}}), flush=True)
        break
"""
    launched: list[subprocess.Popen[bytes]] = []

    def spawn(*_args: object, **_kwargs: object) -> tuple[object, None, None]:
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", program],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        launched.append(process)
        return process, None, None

    monkeypatch.setattr(fixture, "_spawn_hook_process", spawn)
    with fixture.DaemonFixture(tmp_path / "unused-runtime") as session:
        assert session.pid != os.getpid()
        assert session.startup_ms > 0
        assert session.control("snapshot") == {"routes": {"native_resident": 1}}
        assert session.daemon._server.auth_token == "synthetic-private-token"
    assert launched[0].poll() == 0
    session.close()


def test_progress_does_not_extend_control_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    times = iter((10.0, 11.0, 12.0))
    monkeypatch.setattr(fixture.time, "monotonic", lambda: next(times))
    session = fixture.DaemonFixture(Path("unused"))
    observed: list[float] = []

    def receive(*, timeout: float) -> bytes:
        observed.append(timeout)
        if len(observed) == 1:
            return b'{"state":"progress","stage":"start"}'
        return b'{"state":"ready"}'

    monkeypatch.setattr(session._responses, "get", receive)
    assert session._receive(30.0) == {"state": "ready"}
    assert observed == [29.0, 28.0]
    assert session._stage == "start"


def test_startup_stack_survives_fixed_deadline_without_paths_or_raw_output() -> None:
    session = fixture.DaemonFixture(Path("unused"))
    stack = [{"origin": "store_connection_schema._initialize_serialized_once", "line": 580}]
    session._responses.put_nowait(
        json.dumps({"state": "startup_diagnostic", "stage": "construct_store", "stack": stack}).encode()
    )
    with pytest.raises(FixtureFailureError) as failure:
        session._receive(0.0)
    evidence = failure_evidence(failure.value)
    assert evidence["reason"] == "qualification_fixture.daemon_fixture_deadline_at_construct_store"
    assert evidence["startup_stack"] == stack
    with pytest.raises(queue.Empty):
        session._responses.get_nowait()


@pytest.mark.parametrize(
    "stack",
    (
        [{"origin": "/home/private/stack.py", "line": 3}],
        [{"origin": "safe.code", "line": 3, "locals": "private-value"}],
        [{"origin": "safe.code", "line": 3}] * 9,
    ),
)
def test_startup_diagnostics_reject_paths_frame_data_and_unbounded_stacks(stack: object) -> None:
    session = fixture.DaemonFixture(Path("unused"))
    session._responses.put_nowait(
        json.dumps({"state": "startup_diagnostic", "stage": "construct_store", "stack": stack}).encode()
    )
    with pytest.raises((RuntimeError, ValueError)):
        session._receive(0.0)
