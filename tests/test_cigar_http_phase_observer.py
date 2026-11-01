"""Observer integrity: unchanged calls, private correlation and real tail sums."""

from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

import pytest

from scripts.cigar_http_phase_observer import PhaseObserver, summaries


@pytest.mark.parametrize("raises", [False, True])
def test_wrapper_preserves_results_and_exceptions_without_recording_arguments(raises):
    observer = PhaseObserver()
    sentinel = object()
    failure = ValueError("never-record-this-credential")

    def original(*args, **kwargs):
        assert args == (sentinel,) and kwargs == {"private_value": "never-record-this-credential"}
        if raises:
            raise failure
        return sentinel

    wrapped = observer.client(original)
    if raises:
        with pytest.raises(ValueError) as captured:
            wrapped(sentinel, private_value="never-record-this-credential")
        assert captured.value is failure
    else:
        assert wrapped(sentinel, private_value="never-record-this-credential") is sentinel
    report = observer.report()
    assert report["rows"][0]["outcome"] == ("raised" if raises else "returned")
    assert "never-record-this" not in json.dumps(report)
    assert not report["profile_complete"]


def test_connection_association_and_nested_server_phases_never_escape_into_report():
    observer = PhaseObserver()
    address = ("never-record-this-address", 9876)
    connection = SimpleNamespace(sock=SimpleNamespace(getsockname=lambda: address))
    handler = SimpleNamespace(client_address=address, path="/v1/daemon/identity-challenge")
    connect = observer.connect(lambda _connection: None)
    state = observer.client_phase(lambda: object(), "state")
    send = observer.client_phase(lambda: None, "send")
    headers = observer.client_phase(lambda: None, "headers")
    native = observer.server_phase(lambda _handler: None, "server_native")
    identity_write = observer.server_phase(lambda _handler: None, "write")
    server_challenge = observer.server_phase(lambda h: identity_write(h), "server_challenge")
    server_hook = observer.server_phase(lambda h: (native(h), identity_write(h)), "server_hook")
    route = observer.server_context_phase(lambda: object(), "route")
    post = observer.server_phase(
        lambda h: (route(), server_challenge(h) if h.path == "/v1/daemon/identity-challenge" else server_hook(h)),
        "post",
    )

    def challenge():
        connect(connection)
        send()
        post(handler)
        headers()

    def request():
        state()
        observer.client_phase(challenge, "client_challenge")()
        observer.client_phase(lambda: None, "client_verify")()
        state()
        send()
        handler.path = "/v1/hooks/claude-code?private_value=never-record-this-credential"
        post(handler)
        headers()
        observer.client_phase(lambda: None, "client_hook_body")()

    observer.checkpoint()
    observer.checkpoint()
    observer.client(request)()
    observer.checkpoint()
    observer.checkpoint()
    observer.after_summary()
    report = observer.report()
    assert report["profile_complete"]
    assert report["remaining_links"] == 0
    assert report["rows"][0]["stage"] == "http_1"
    phases = report["rows"][0]["phases"]
    assert all(len(phases[name]) == 1 for name in ("server_challenge", "server_hook", "server_native"))
    assert "server_identity_write" in phases and "server_hook_write" in phases
    assert "never-record-this-address" not in json.dumps(report)
    assert "never-record-this-credential" not in json.dumps(report)
    assert "9876" not in json.dumps({"phases": list(phases)})


def test_full_observer_calls_original_without_holding_its_metadata_lock():
    observer = PhaseObserver(maximum_requests=1)
    observer.client(lambda: None)()
    acquired = threading.Event()

    def original():
        def second_thread():
            with observer.lock:
                acquired.set()

        worker = threading.Thread(target=second_thread, daemon=True)
        worker.start()
        worker.join(timeout=1)
        assert acquired.is_set()
        return "unchanged-result"

    assert observer.client(original)() == "unchanged-result"
    report = observer.report()
    assert report["dropped"] == {"requests": 1}
    assert not report["profile_complete"]


def test_tail_components_come_from_the_actual_slowest_request():
    rows = [
        {
            "stage": "http_1",
            "outcome": "returned",
            "total": {"wall_ns": 100_000_000, "cpu_ns": 0},
            "phases": {
                "client_state_initial": [{"wall_ns": 10_000_000, "cpu_ns": 0}],
                "client_challenge": [{"wall_ns": 80_000_000, "cpu_ns": 0}],
            },
        },
        {
            "stage": "http_1",
            "outcome": "returned",
            "total": {"wall_ns": 90_000_000, "cpu_ns": 0},
            "phases": {"client_state_initial": [{"wall_ns": 85_000_000, "cpu_ns": 0}]},
        },
    ]
    rows.extend(
        {"stage": "http_1", "outcome": "returned", "total": {"wall_ns": 5_000_000, "cpu_ns": 0}, "phases": {}}
        for _ in range(18)
    )
    report = summaries(rows)["http_1"]
    assert report["tail_requests"] == 1
    assert report["tail_mean_total_wall_ms"] == 100
    assert report["tail_mean_client_components_ms"]["client_state_initial"] == 10
    assert report["tail_mean_client_components_ms"]["client_challenge"] == 80
    assert report["tail_mean_other_client_wall_ms"] == 10


def test_phase_sample_overflow_never_changes_the_original_call_result():
    observer = PhaseObserver()
    original = observer.client_phase(lambda: 123, "client_verify")
    observer.client(lambda: [original() for _ in range(20)])()
    report = observer.report()
    assert len(report["rows"][0]["phases"]["client_verify"]) == 16
    assert report["dropped"] == {"phase_samples": 4}
    assert not report["profile_complete"]


def test_arbitrary_labels_cannot_be_used_to_record_content():
    observer = PhaseObserver()
    with pytest.raises(AssertionError):
        observer.client_phase(lambda: None, "never-record-this-credential")


def test_worker_delay_uses_owned_connection_metadata_without_addresses():
    observer = PhaseObserver()
    request = object()
    address = ("never-record-this-address", 9876)
    server = SimpleNamespace(
        unclassified_watchdog_thread=threading.current_thread(),
        request_capacity_lock=threading.Lock(),
        request_accepted_at={id(request): time.monotonic() - 0.025},
    )
    connection = SimpleNamespace(sock=SimpleNamespace(getsockname=lambda: address))
    worker = observer.server_worker(lambda s, r, a: (s is server, r is request, a is address))
    submit = observer.server_submit(worker)

    def original():
        observer.connect(lambda _: None)(connection)
        return submit(server, request, address)

    assert observer.client(original)() == (True, True, True)
    report = observer.report()
    metadata = report["rows"][0]["connection"]
    assert metadata["watchdog_submission"] is True
    assert metadata["accepted_to_worker_ns"] >= 25_000_000
    assert "never-record-this-address" not in json.dumps(report)
