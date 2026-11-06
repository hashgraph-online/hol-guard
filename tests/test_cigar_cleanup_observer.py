"""Teardown observation preserves calls, bounded output and private metadata."""

from __future__ import annotations

import gc
import json
import threading
import weakref
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.cigar_cleanup_observer import CleanupObserver


class Process:
    pid = 8675309

    def poll(self):
        return None


class Client:
    _process = None
    _state_dir = Path("/private/credential-bearing-state")


def observer(**options):
    return CleanupObserver(Path("/installed"), Path("/repo"), **options)


@pytest.mark.parametrize("raises", [False, True])
def test_original_result_and_exception_identity_survive_private_arguments(raises):
    recorded = observer()
    value = object()
    error = RuntimeError("private exception text")

    def original(*args, **options):
        assert args == ("private request",) and options == {"key": "private credential"}
        assert recorded._lock.acquire(blocking=False)
        recorded._lock.release()
        if raises:
            raise error
        return value

    operation = recorded.observe(original, "stop_clients")
    if raises:
        with pytest.raises(RuntimeError) as caught:
            operation("private request", key="private credential")
        assert caught.value is error
    else:
        assert operation("private request", key="private credential") is value
    encoded = json.dumps(recorded.report())
    assert "private" not in encoded and "credential" not in encoded
    assert recorded.report()["events"][0]["raised"] is raises


def test_incomplete_observation_cannot_replace_the_original_result():
    recorded = observer()
    value = object()
    assert recorded.observe(lambda *_args: value, "client_close")(object()) is value
    assert not recorded.report()["profile_complete"]
    assert recorded.report()["dropped"] == {"observation_error": 1}


def test_event_overflow_never_skips_the_underlying_operation():
    recorded = observer(limit=1)
    called = []
    operation = recorded.observe(lambda: called.append(True), "stop_clients")
    operation()
    operation()
    assert called == [True, True]
    assert len(recorded.report()["events"]) == 1
    assert recorded.report()["dropped"] == {"events": 1}


def test_process_correlation_keeps_only_weak_references():
    recorded = observer()
    client = Client()
    process = Process()

    def start(value):
        value._process = process
        return True

    assert recorded.client_start(start)(client)
    client_ref, process_ref = weakref.ref(client), weakref.ref(process)
    del client
    process = None
    gc.collect()
    assert client_ref() is None and process_ref() is None
    encoded = json.dumps(recorded.report())
    assert "8675309" not in encoded and "credential-bearing" not in encoded


def test_final_roles_use_the_original_snapshot_without_a_new_sample(monkeypatch):
    recorded = observer()
    client, process = Client(), Process()

    def start(value):
        value._process = process
        return True

    recorded.client_start(start)(client)
    sampler = SimpleNamespace(
        _lock=threading.Lock(),
        _live_descendants={
            (process.pid, ("private start",)): "native_runtime",
            (99, ("private other",)): "native_runtime",
        },
        sample=lambda: pytest.fail("must not replace the original final snapshot"),
    )
    pools = SimpleNamespace(_CLIENTS_LOCK=threading.Lock(), _CLIENT_POOLS={})
    monkeypatch.setattr(recorded, "_stacks", lambda: [])
    recorded.snapshot("after_finish_cleanup", pools, sampler)
    row = recorded.report()["snapshots"][0]
    assert row["original_final_live_roles"] == {"known_client_stream": 1, "other_native": 1}
    assert row["original_final_live_client_scopes"] == {"1": 1}
    encoded = json.dumps(recorded.report())
    assert "private" not in encoded and str(process.pid) not in encoded


def test_arbitrary_operation_labels_and_payload_fields_refuse():
    recorded = observer()
    with pytest.raises(ValueError):
        recorded.observe(lambda: None, "private label")
    with pytest.raises(ValueError):
        recorded.event("client_close", secret="private content")
    with pytest.raises(ValueError):
        recorded.event("stop_resident", status=["private content"])
