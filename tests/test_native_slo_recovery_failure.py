"""A serial recovery failure retains its own observation and remains a failure."""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import bench_guard_native_installed_slo as bench
from scripts import native_slo_daemon_fixture as remote
from scripts import native_slo_session as local
from scripts.native_slo_adapter import Observation
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_observation_failure import capture_recovery_observation, retain_failed_recovery_observation


@pytest.mark.parametrize("kind", ("local", "remote"))
@pytest.mark.parametrize(
    "allowed,route,overloaded",
    ((True, "native_fail_safe", False), (False, "native_resident", False), (False, "native_fail_safe", True)),
)
def test_recovery_failure_retains_actual_response_and_counts_without_retry(
    tmp_path, monkeypatch, kind, allowed, route, overloaded
):
    counts = {"native_resident": 0, "native_fail_safe": 0}
    calls = []
    metrics = SimpleNamespace(snapshot=lambda: {"routes": dict(counts)})
    worker = SimpleNamespace(metrics=metrics)
    private_reason = "private_identity_marker"
    response = {
        "decision": "allow" if allowed else "deny",
        "policy_action": "allow" if allowed else "block",
        "reason_code": "daemon_capacity" if overloaded else private_reason,
    }

    def request(*_args, **_kwargs):
        calls.append("observe")
        observed_route = "native_resident" if len(calls) == 1 else route
        counts[observed_route] += 1
        if len(calls) == 1:
            return {"decision": "allow", "policy_action": "allow"}
        return dict(response)

    session: Any = (local.AdapterSession if kind == "local" else remote.DaemonFixture).__new__(
        local.AdapterSession if kind == "local" else remote.DaemonFixture
    )
    session.root = session.workspace = session.guard_home = tmp_path
    session.daemon = SimpleNamespace(_server=SimpleNamespace(hook_worker=worker))
    session._owner_thread_id = threading.get_ident()
    session._connection = None

    def stop():
        calls.append("stop")
        return True

    session.stop_resident = stop
    if kind == "remote":
        session.request = lambda *_args, **_kwargs: (request(), 1.0)
        monkeypatch.setattr(remote, "wait_for_route_corpus", lambda *_args, **_kwargs: metrics.snapshot())
    else:
        monkeypatch.setattr(local, "_request", request)
    with pytest.raises(FixtureFailureError, match="recovery sample 0 failed") as error:
        bench._run_recovery(session, 1)
    detail = json.loads(json.dumps(failure_evidence(error.value)))
    assert calls == ["observe", "stop", "observe"]
    assert detail["sample_index"] == 0
    assert detail["sample_phase"] == "resident_recovery"
    assert detail["completed_sample_counts"] == {"recovery": 0}
    assert detail["route"] == route and detail["allowed"] is allowed
    assert detail["overloaded"] is overloaded and detail["resident_stop_contained"] is True
    assert detail["routes_before"]["native_resident"] == 1
    assert sum(detail["routes_after"].values()) == 2
    assert detail["observed_semantics"]["delivered"]["decision"] == response["decision"]
    assert len(detail["observed_semantics"]["delivered"]["reason_code_digest"]) == 64
    assert private_reason not in json.dumps(detail)


def test_recovery_capture_is_thread_local_scoped_and_cleared() -> None:
    failed = Observation("claude-code", "PostToolUse", "1k", 1, "native_fail_safe", True)
    with capture_recovery_observation() as detail:
        retain_failed_recovery_observation(
            failed, {"decision": "allow"}, {"native_resident": 1}, {"native_resident": 1, "native_fail_safe": 1}
        )
        original = json.loads(json.dumps(detail))
        thread = threading.Thread(
            target=retain_failed_recovery_observation,
            args=(failed, {"decision": "deny"}, {"native_resident": 99}, {"native_resident": 100}),
        )
        thread.start()
        thread.join(timeout=1)
        assert not thread.is_alive()
        assert detail == original
        with capture_recovery_observation() as nested:
            assert nested == {}
        assert detail == original
    retain_failed_recovery_observation(failed, {"decision": "deny"}, {}, {})
    assert detail == original
    with capture_recovery_observation() as fresh:
        assert fresh == {}


def test_successful_recovery_does_not_create_failure_evidence() -> None:
    allowed = Observation("claude-code", "PostToolUse", "1k", 1, "native_resident", True)
    with capture_recovery_observation() as detail:
        retain_failed_recovery_observation(allowed, {"decision": "allow"}, {}, {"native_resident": 1})
        assert detail == {}
