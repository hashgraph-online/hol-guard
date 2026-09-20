"""Finite readiness diagnostics preserve transport and test budgets."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_policy_test_support as support
from codex_plugin_scanner.guard.native_resident_client import record_native_resident_client_failure_code


@pytest.mark.parametrize("result", [None, b"synthetic response"])
def test_transport_arguments_result_and_worker_failure_are_preserved(result: bytes | None) -> None:
    diagnostic = support._PublicationDiagnostics()
    sentinel = object()
    calls = []
    responses = []

    def client(**kwargs):
        calls.append(kwargs)
        record_native_resident_client_failure_code("native_client_timed_out")
        return result

    worker = threading.Thread(target=lambda: responses.append(diagnostic.call(client, payload=sentinel, deadline=7)))
    worker.start()
    worker.join()
    assert calls == [{"payload": sentinel, "deadline": 7}]
    assert responses == [result]
    assert diagnostic.describe(None) == "publisher=missing; transport=native_client_timed_out; started=1; completed=1"
    record_native_resident_client_failure_code("native_client_exit_nonzero")
    assert "native_client_timed_out" in diagnostic.describe(None)


def test_transport_exception_is_not_replaced_and_untrusted_text_is_not_rendered() -> None:
    diagnostic = support._PublicationDiagnostics()
    failure = RuntimeError("private-message-canary")

    def client(**_kwargs):
        record_native_resident_client_failure_code("private-transport-canary")
        raise failure

    with pytest.raises(RuntimeError) as caught:
        diagnostic.call(client, payload=b"private-payload-canary")
    assert caught.value is failure
    assert diagnostic.describe("private-publisher-canary") == "publisher=other; transport=other; started=1; completed=1"


def test_completed_failure_survives_a_later_success_and_counters_are_bounded() -> None:
    diagnostic = support._PublicationDiagnostics()

    def client(**_kwargs):
        if diagnostic._started == 1:
            record_native_resident_client_failure_code("native_client_timed_out")
        return b"synthetic"

    for _ in range(1001):
        diagnostic.call(client)
    assert diagnostic.describe(None) == (
        "publisher=missing; transport=native_client_timed_out; started=999; completed=999"
    )


class _Publisher:
    def __init__(self, *, ready: bool, snapshot: object, injected: bool = False) -> None:
        self.ready = ready
        self.snapshot = snapshot
        self._client_request = (lambda **_kwargs: b"injected") if injected else None
        self.last_error = "private-publisher-canary"
        self.started = False
        self.closed = False
        self.deadlines = []

    def start(self):
        self.started = True

    def wait_until_ready(self, deadline):
        self.deadlines.append(deadline)
        return self.ready

    def current_snapshot(self):
        return self.snapshot

    def close(self):
        self.closed = True


@pytest.mark.parametrize("platform,budget", [("linux", 3.0), ("win32", 25.0)])
@pytest.mark.parametrize("injected", [False, True])
def test_readiness_failure_keeps_original_budget_and_restores_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, budget: float, injected: bool
) -> None:
    publisher = _Publisher(ready=False, snapshot=None, injected=injected)
    previous = publisher._client_request
    monkeypatch.setattr(support, "get_native_policy_snapshot_publisher", lambda _store: publisher)
    monkeypatch.setattr(support.sys, "platform", platform)
    monkeypatch.setattr(support.time, "monotonic", lambda: 100.0)
    with (
        pytest.raises(AssertionError, match="native policy publisher was not ready: publisher=other") as caught,
        support.native_policy_snapshot(tmp_path),
    ):
        pytest.fail("Unavailable publication cannot yield authority")
    assert "private-publisher-canary" not in str(caught.value)
    assert publisher.started and publisher.closed
    assert publisher.deadlines == [100.0 + budget]
    assert publisher._client_request is previous


@pytest.mark.parametrize("snapshot", [None, {"generation": 4}])
def test_ready_snapshot_predicate_and_cleanup_are_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, snapshot: object
) -> None:
    publisher = _Publisher(ready=True, snapshot=snapshot)
    monkeypatch.setattr(support, "get_native_policy_snapshot_publisher", lambda _store: publisher)
    if snapshot is None:
        with (
            pytest.raises(AssertionError, match="native policy publisher returned no ACKed snapshot"),
            support.native_policy_snapshot(tmp_path),
        ):
            pytest.fail("Missing snapshot cannot yield authority")
    else:
        with support.native_policy_snapshot(tmp_path) as actual:
            assert actual is snapshot
    assert publisher.closed and publisher._client_request is None


def test_original_client_is_restored_when_close_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    publisher = _Publisher(ready=True, snapshot={"generation": 4})
    failure = RuntimeError("synthetic close failure")

    def close():
        publisher.closed = True
        raise failure

    monkeypatch.setattr(publisher, "close", close)
    monkeypatch.setattr(support, "get_native_policy_snapshot_publisher", lambda _store: publisher)
    with pytest.raises(RuntimeError) as caught, support.native_policy_snapshot(tmp_path):
        pass
    assert caught.value is failure
    assert publisher.closed and publisher._client_request is None


def test_actual_publisher_error_survives_original_epoch_reset(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
    from codex_plugin_scanner.guard.store import GuardStore

    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path))
    original = publisher._record_error
    diagnostic = support.PublicationLifecycleObservation()
    try:
        with diagnostic.attach(publisher):
            publisher._record_error("native_resident_start_timeout")
            publisher.request_publish()
            assert publisher.last_error is None and publisher._epoch == 1
            report = diagnostic.describe(publisher)
            assert "last_publisher=native_resident_start_timeout; error_epoch=0; epoch=1; error_events=1" in report
            assert "initial_publisher=missing" in report
            assert not publisher._started and publisher._thread is None
        assert publisher._record_error == original
        assert "_record_error" not in vars(publisher)
    finally:
        publisher.close()


def test_initial_error_and_post_attach_error_are_distinct(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
    from codex_plugin_scanner.guard.store import GuardStore

    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path))
    diagnostic = support.PublicationLifecycleObservation()
    try:
        publisher._record_error("native_policy_snapshot_integrity_key_unavailable")
        with diagnostic.attach(publisher):
            publisher.request_publish()
            report = diagnostic.describe(publisher)
            assert "initial_publisher=native_policy_snapshot_integrity_key_unavailable" in report
            assert "last_publisher=missing; error_epoch=missing; epoch=1; error_events=0" in report
    finally:
        publisher.close()


def test_lifecycle_delegates_exact_error_and_exception_and_restores_instance_override() -> None:
    from types import SimpleNamespace

    failure = RuntimeError("private-error-canary")
    calls = []

    def record(error):
        calls.append(error)
        raise failure

    publisher = SimpleNamespace(_record_error=record, _epoch=4, last_error=None)
    diagnostic = support.PublicationLifecycleObservation()
    with pytest.raises(RuntimeError) as caught, diagnostic.attach(publisher):
        publisher._record_error("private-publisher-canary")
    assert caught.value is failure
    assert calls == ["private-publisher-canary"]
    assert publisher._record_error is record
    assert "last_publisher=other; error_epoch=4; epoch=4; error_events=1" in diagnostic.describe(publisher)
    assert "private-" not in diagnostic.describe(publisher)


def test_lifecycle_preserves_injected_return_value() -> None:
    from types import SimpleNamespace

    result = object()
    publisher = SimpleNamespace(_record_error=lambda error: result, _epoch=0, last_error=None)
    with support.PublicationLifecycleObservation().attach(publisher):
        assert publisher._record_error("native_resident_start_timeout") is result


def test_lifecycle_captured_callback_can_complete_after_detachment() -> None:
    from types import SimpleNamespace

    started, release = threading.Event(), threading.Event()
    calls = []

    def record(error):
        started.set()
        assert release.wait(2)
        calls.append(error)

    publisher = SimpleNamespace(_record_error=record, _epoch=4, last_error=None)
    diagnostic = support.PublicationLifecycleObservation()
    with diagnostic.attach(publisher):
        captured = publisher._record_error
        worker = threading.Thread(target=lambda: captured("native_resident_start_timeout"))
        worker.start()
        assert started.wait(2)
    assert publisher._record_error is record
    release.set()
    worker.join(2)
    assert not worker.is_alive() and calls == ["native_resident_start_timeout"]
    assert "last_publisher=native_resident_start_timeout" in diagnostic.describe(publisher)


def test_lifecycle_does_not_replace_a_later_observer() -> None:
    from types import SimpleNamespace

    publisher = SimpleNamespace(_record_error=lambda error: None, _epoch=0, last_error=None)

    def later(error):
        return None

    with support.PublicationLifecycleObservation().attach(publisher):
        publisher._record_error = later
    assert publisher._record_error is later


def test_lifecycle_nested_attachment_restores_outer_then_original() -> None:
    from types import SimpleNamespace

    def original(error):
        return None

    publisher = SimpleNamespace(_record_error=original, _epoch=0, last_error=None)
    outer, inner = support.PublicationLifecycleObservation(), support.PublicationLifecycleObservation()
    with outer.attach(publisher):
        outer_callback = publisher._record_error
        with inner.attach(publisher):
            publisher._record_error("native_resident_start_timeout")
        assert publisher._record_error is outer_callback
    assert publisher._record_error is original
    assert "error_events=1" in outer.describe(publisher) and "error_events=1" in inner.describe(publisher)


def test_lifecycle_unknown_values_do_not_invoke_conversion_or_hashing() -> None:
    from types import SimpleNamespace

    class Hostile(str):
        def __hash__(self):
            pytest.fail("Diagnostic value was hashed")

        def __str__(self):
            pytest.fail("Diagnostic value was rendered")

    value = Hostile("native_resident_start_timeout")
    publisher = SimpleNamespace(_record_error=lambda error: None, _epoch=value, last_error=value)
    diagnostic = support.PublicationLifecycleObservation()
    with diagnostic.attach(publisher):
        publisher._record_error(value)
    assert diagnostic.describe(publisher) == (
        "lifecycle_attached=True; initial_publisher=other; last_publisher=other; "
        "error_epoch=missing; epoch=missing; error_events=1"
    )
    assert support._finite_failure(value) == "other"


def test_lifecycle_epochs_and_event_counts_are_bounded() -> None:
    from types import SimpleNamespace

    publisher = SimpleNamespace(_record_error=lambda error: None, _epoch=10_000, last_error=None)
    diagnostic = support.PublicationLifecycleObservation()
    with diagnostic.attach(publisher):
        for _ in range(1001):
            publisher._record_error("native_resident_start_timeout")
    assert "error_epoch=999; epoch=999; error_events=999" in diagnostic.describe(publisher)


def test_every_added_finite_error_has_an_exact_existing_source_literal() -> None:
    import ast
    import re

    root = Path(__file__).resolve().parents[1]
    literals = set()
    for path in (root / "src/codex_plugin_scanner/guard").glob("native_policy*.py"):
        if path.name == "native_policy_test_support.py":
            continue
        literals.update(
            node.value
            for node in ast.walk(ast.parse(path.read_text()))
            if isinstance(node, ast.Constant) and type(node.value) is str
        )
    for path in (root / "rust/crates/guard-runtime/src").glob("managed_resident*.rs"):
        literals.update(re.findall(r'"(native_[a-z0-9_]+)"', path.read_text()))
    added = support._PUBLISHER_FAILURE_CODES - support._DIAGNOSTIC_FAILURE_CODES
    assert added <= literals


@pytest.mark.parametrize(
    ("health", "transport", "expected"),
    [
        (
            "native_command_control_mutation_in_progress",
            None,
            "health=native_command_control_mutation_in_progress; transport=missing",
        ),
        (
            "native_resident_unavailable",
            "native_client_timed_out",
            "health=native_resident_unavailable; transport=native_client_timed_out",
        ),
        ("private-health-canary", "private-transport-canary", "health=other; transport=other"),
    ],
)
def test_completed_review_diagnostic_uses_only_finite_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    health: str,
    transport: str | None,
    expected: str,
) -> None:
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import native_runtime

    monkeypatch.setattr(native_runtime, "native_runtime_health", lambda _: SimpleNamespace(reason=health))
    monkeypatch.setattr(support, "native_resident_client_failure_code", lambda: transport)
    assert support.native_review_diagnostic(tmp_path) == expected
