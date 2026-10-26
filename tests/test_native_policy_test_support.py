from __future__ import annotations

import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_test_support as support


def test_readiness_failure_reports_only_bounded_known_worker_locations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()
    worker = threading.Thread(target=release.wait)
    worker.start()
    calls: list[object] = []
    publisher = SimpleNamespace(
        _thread=worker,
        last_error="private exception payload",
        start=lambda: calls.append("start"),
        wait_until_ready=lambda deadline: calls.append(deadline) or False,
        close=lambda: calls.append("close"),
    )
    frame = None
    for number in range(12):
        frame = SimpleNamespace(
            f_code=SimpleNamespace(
                co_filename="/private/sensitive/home/" + "w" * 200 + ".py",
                co_name="publish_" + "f" * 200,
            ),
            f_lineno=number,
            f_back=frame,
            f_locals={"secret": "private local payload"},
        )
    monkeypatch.setattr(support.sys, "_current_frames", lambda: {worker.ident: frame, -1: object()})
    monkeypatch.setattr(support.sys, "platform", "linux")
    times = iter([100.0, 103.0])
    monkeypatch.setattr(support.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(support, "GuardStore", lambda home: home)
    monkeypatch.setattr(support, "get_native_policy_snapshot_publisher", lambda store: publisher)
    try:
        with pytest.raises(AssertionError) as failure, support.native_policy_snapshot(tmp_path):
            pytest.fail("an unready snapshot must not be yielded")
        message = str(failure.value)
        assert calls == ["start", 103.0, "close"]
        assert "wait_seconds=3.000 last_error=unavailable worker_alive=true" in message
        assert message.count("publish_") == 6
        assert ":11 <- " in message
        assert len(message.encode("ascii")) <= 1070
        assert "/" not in message
        assert "private" not in message
        assert "sensitive" not in message
        assert "payload" not in message
        assert "w" * 81 not in message
        assert "f" * 65 not in message
    finally:
        release.set()
        worker.join(timeout=1)


@pytest.mark.parametrize("missing_worker", [True, False])
def test_startup_diagnostics_unavailable_does_not_expose_errors(
    monkeypatch: pytest.MonkeyPatch, missing_worker: bool
) -> None:
    def unavailable(self: object) -> object:
        raise RuntimeError("private exception payload")

    publisher = SimpleNamespace(_thread=None if missing_worker else threading.Thread())
    monkeypatch.setattr(support.threading.Thread, "is_alive", unavailable)
    assert support._publisher_startup_diagnostics(publisher, 3.0) == (
        "wait_seconds=3.000 last_error=unavailable worker_alive=unavailable worker_stack=unavailable"
    )


def test_success_does_not_collect_startup_diagnostics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = {"generation": 1}
    publisher = SimpleNamespace(
        start=lambda: None,
        wait_until_ready=lambda deadline: True,
        current_snapshot=lambda: snapshot,
        close=lambda: None,
    )
    monkeypatch.setattr(support, "GuardStore", lambda home: home)
    monkeypatch.setattr(support, "get_native_policy_snapshot_publisher", lambda store: publisher)
    monkeypatch.setattr(support, "_publisher_startup_diagnostics", lambda *args: pytest.fail("success diagnostics"))
    with support.native_policy_snapshot(tmp_path) as actual:
        assert actual is snapshot


def test_startup_diagnostics_handles_worker_attribute_errors() -> None:
    class UnavailablePublisher:
        @property
        def _thread(self) -> object:
            raise RuntimeError("private attribute payload")

    assert support._publisher_startup_diagnostics(UnavailablePublisher(), 3.0) == (
        "wait_seconds=3.000 last_error=unavailable worker_alive=unavailable worker_stack=unavailable"
    )


@pytest.mark.parametrize("stopped_during_snapshot", [False, True])
def test_startup_diagnostics_discards_stopped_worker_identity(
    monkeypatch: pytest.MonkeyPatch, stopped_during_snapshot: bool
) -> None:
    worker = threading.Thread(target=lambda: None)
    worker.start()
    worker.join(timeout=1)
    assert worker.ident is not None
    if stopped_during_snapshot:
        monkeypatch.setattr(support.threading.Thread, "is_alive", lambda self: True)
        monkeypatch.setattr(support.sys, "_current_frames", lambda: {worker.ident: object()})
        monkeypatch.setattr(support.threading, "enumerate", lambda: [])
    else:
        monkeypatch.setattr(support.sys, "_current_frames", lambda: pytest.fail("stopped worker stack read"))
    assert support._publisher_startup_diagnostics(SimpleNamespace(_thread=worker), 3.0) == (
        f"wait_seconds=3.000 last_error=unavailable "
        f"worker_alive={str(stopped_during_snapshot).lower()} worker_stack=unavailable"
    )


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (None, "none"),
        ("native_policy_snapshot_expired", "native_policy_snapshot_expired"),
        ("native_command_program_binding_mismatch", "native_command_program_binding_mismatch"),
        ("native_policy_snapshot_resident_changed", "native_policy_snapshot_resident_changed"),
        ("private_payload_with_only_allowed_characters", "unavailable"),
        ("native_policy_snapshot_expired_private_payload", "unavailable"),
        ("private exception payload", "unavailable"),
    ],
)
def test_startup_error_reports_only_exact_known_codes(error: object, expected: str) -> None:
    publisher = SimpleNamespace(last_error=error)
    assert support._publisher_startup_error(publisher) == expected
    assert f"last_error={expected} " in support._publisher_startup_diagnostics(publisher, 3.0)


def test_startup_error_getter_failure_is_unavailable() -> None:
    class UnavailablePublisher:
        @property
        def last_error(self) -> object:
            raise RuntimeError("private getter payload")

    assert support._publisher_startup_error(UnavailablePublisher()) == "unavailable"
