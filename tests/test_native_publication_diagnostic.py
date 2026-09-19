from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from codex_plugin_scanner.guard.native_resident_client import record_native_resident_client_failure_code
from scripts import native_publication_diagnostic as diagnostic


@pytest.mark.parametrize("result", [None, b"private-response-canary"])
def test_worker_outcome_is_observed_without_changing_arguments_or_result(monkeypatch, result):
    publisher = SimpleNamespace(_client_request=None)
    marker = object()
    calls = []

    def transport(**kwargs):
        calls.append(kwargs)
        record_native_resident_client_failure_code("native_client_timed_out")
        return result

    monkeypatch.setattr(diagnostic, "native_resident_client_request", transport)
    with diagnostic.observe_publication(publisher) as observation:
        returned = []
        worker = threading.Thread(target=lambda: returned.append(publisher._client_request(payload=marker, deadline=4)))
        worker.start()
        worker.join()
        record_native_resident_client_failure_code("native_client_exit_nonzero")
        assert returned == [result]
        assert calls == [{"payload": marker, "deadline": 4}]
        assert observation.describe(None).endswith("transport=native_client_timed_out; started=1; completed=1")
        assert "window=after_daemon_construction" in observation.describe(None)
    assert publisher._client_request is None


def test_exception_identity_and_observer_restoration_are_preserved(monkeypatch):
    publisher = SimpleNamespace(_client_request=None)
    failure = RuntimeError("private-error-canary")

    def transport(**kwargs):
        record_native_resident_client_failure_code("private-token-canary")
        raise failure

    monkeypatch.setattr(diagnostic, "native_resident_client_request", transport)
    with pytest.raises(RuntimeError) as caught, diagnostic.observe_publication(publisher) as observation:
        publisher._client_request(payload=b"private-payload-canary")
    assert caught.value is failure
    assert publisher._client_request is None
    assert observation.describe("private-path-canary").endswith(
        "publisher=other; transport=other; started=1; completed=1"
    )


def test_existing_injected_client_is_not_replaced_or_claimed_observed():
    def client(**kwargs):
        return None

    publisher = SimpleNamespace(_client_request=client)
    with diagnostic.observe_publication(publisher) as observation:
        assert publisher._client_request is client
        assert "attached=False" in observation.describe(None)
        assert "started=0; completed=0" in observation.describe(None)
    assert publisher._client_request is client


def test_unknown_publisher_has_no_new_client_or_start_side_effect():
    publisher = SimpleNamespace()
    with diagnostic.observe_publication(publisher) as observation:
        assert not observation.attached
    assert vars(publisher) == {}


def test_string_subclasses_and_arbitrary_objects_are_not_interpreted():
    class Hostile(str):
        def __hash__(self):
            pytest.fail("Untrusted diagnostic value was hashed")

        def __str__(self):
            pytest.fail("Untrusted diagnostic value was rendered")

    assert diagnostic._finite_code(Hostile("native_client_timed_out")) == "other"
    assert diagnostic._finite_code(object()) == "other"


def test_retry_success_does_not_erase_completed_failure_and_counters_are_bounded(monkeypatch):
    publisher = SimpleNamespace(_client_request=None)
    codes = iter(["native_client_timed_out"] + [None] * 1000)

    monkeypatch.setattr(diagnostic, "native_resident_client_failure_code", lambda: next(codes))

    def transport(**kwargs):
        return b"synthetic"

    monkeypatch.setattr(diagnostic, "native_resident_client_request", transport)
    with diagnostic.observe_publication(publisher) as observation:
        for _ in range(1001):
            publisher._client_request()
        assert observation.describe(None).endswith("transport=native_client_timed_out; started=999; completed=999")


def test_attach_and_detach_neither_wait_for_nor_replace_an_already_captured_call(monkeypatch):
    publisher = SimpleNamespace(_client_request=None)
    started, release = threading.Event(), threading.Event()
    results = []

    def transport(**kwargs):
        started.set()
        assert release.wait(2)
        return b"synthetic"

    monkeypatch.setattr(diagnostic, "native_resident_client_request", transport)
    with diagnostic.observe_publication(publisher) as observation:
        captured = publisher._client_request
        worker = threading.Thread(target=lambda: results.append(captured()))
        worker.start()
        assert started.wait(2)
        assert observation.describe(None).endswith("started=1; completed=0")
    assert publisher._client_request is None
    release.set()
    worker.join(2)
    assert not worker.is_alive() and results == [b"synthetic"]


@pytest.mark.parametrize("ready,elapsed", [(True, 0.1), (False, 0.401), (True, 0.401)])
def test_actual_slo_barrier_preserves_predicates_budget_and_lifecycle(monkeypatch, ready, elapsed):
    from scripts import native_slo_session as session_module

    publisher = SimpleNamespace(_client_request=None, last_error="private-error-canary")
    events = []
    publisher.register_workspace = lambda workspace: events.append(("register", workspace))

    def prepare(workspace, *, deadline):
        events.append((workspace, deadline))
        return {} if ready else None

    daemon = SimpleNamespace(
        start=lambda: events.append("start"),
        port=1,
        _server=SimpleNamespace(
            hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=prepare)
        ),
    )
    session = object.__new__(session_module.AdapterSession)
    session.daemon, session.workspace = cast(Any, daemon), Path("synthetic-workspace")
    monotonic = iter([100.0, 100.401])
    perf = iter([100.0, 100.0 + elapsed])
    monkeypatch.setattr(session_module.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(session_module.time, "perf_counter", lambda: next(perf))
    monkeypatch.setattr(session_module, "HTTPConnection", lambda *args, **kwargs: object())
    if ready and elapsed <= 0.4:
        session.start()
    else:
        with pytest.raises(RuntimeError) as caught:
            session.start()
        assert "private-error-canary" not in str(caught.value)
        assert ("native readiness exceeded budget" if ready else "native policy was not ready") in str(caught.value)
    assert events == ["start", ("register", session.workspace), (session.workspace, 100.4)]
    assert publisher._client_request is None


def test_actual_auto_probe_failure_retains_budget_and_cleanup(tmp_path, monkeypatch):
    from ci.native_runtime import probe_native_default_auto as probe

    publisher = SimpleNamespace(_client_request=None, last_error="private-path-canary")
    events = []

    def prepare(workspace, *, deadline):
        events.append((workspace, deadline))
        return None

    daemon = SimpleNamespace(
        start=lambda: events.append("start"),
        stop=lambda: events.append("stop"),
        _server=SimpleNamespace(
            hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=prepare)
        ),
    )
    ticks = iter([100.0, 100.401])
    monkeypatch.setattr(probe.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(probe, "GuardStore", lambda *args: object())
    monkeypatch.setattr(probe, "GuardDaemonServer", lambda *args, **kwargs: daemon)
    monkeypatch.setattr(probe, "_ownership_routes", lambda: {})
    with pytest.raises(RuntimeError) as caught:
        probe._installed_hook_corpus(tmp_path)
    assert "private-path-canary" not in str(caught.value)
    assert "'policy_ready': False" in str(caught.value)
    assert events == ["start", (tmp_path / "hook-workspace", 100.4), "stop"]
    assert publisher._client_request is None


@pytest.mark.parametrize("stage", ["initial", "later_with_cleanup_failure"])
def test_actual_auto_failure_long_traceback_contains_only_finite_diagnostic(tmp_path, stage):
    source = tmp_path / "test_failure.py"
    source.write_text(
        "import os\nfrom types import SimpleNamespace\n"
        "from ci.native_runtime import probe_native_default_auto as p\n"
        "def test_failure(tmp_path, monkeypatch):\n"
        "    publisher=SimpleNamespace(_client_request=None,last_error=os.environ['SYNTHETIC_PRIVATE_VALUE'])\n"
        "    worker=SimpleNamespace(policy_snapshot_publisher=publisher,prepare_workspace_policy=lambda *a,**k:None)\n"
        "    daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker),start=lambda:None,stop=lambda:None)\n"
        "    monkeypatch.setattr(p,'GuardStore',lambda *a:object())\n"
        "    monkeypatch.setattr(p,'GuardDaemonServer',lambda *a,**k:daemon)\n"
        "    monkeypatch.setattr(p,'_ownership_routes',lambda:{})\n"
        + (
            "    worker.prepare_workspace_policy=lambda *a,**k:{}\n"
            "    daemon.stop=lambda:(_ for _ in ()).throw(OSError(os.environ['SYNTHETIC_PRIVATE_VALUE']))\n"
            "    monkeypatch.setattr(p,'_exercise_installed_routes',"
            "lambda *a:(_ for _ in ()).throw(RuntimeError('synthetic finite route failure')))\n"
            if stage == "later_with_cleanup_failure"
            else ""
        )
        + "    p._installed_hook_corpus(tmp_path)\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    root = Path(__file__).resolve().parents[1]
    environment["PYTHONPATH"] = os.pathsep.join([str(root / "src"), str(root)])
    environment["SYNTHETIC_PRIVATE_VALUE"] = "synthetic-private-token-93a149"
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--tb=long", str(source)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 1 and "1 failed" in output
    assert "publisher=other" in output
    assert environment["SYNTHETIC_PRIVATE_VALUE"] not in output


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_actual_later_route_failure_is_observed_and_not_masked(tmp_path, monkeypatch, capsys, cleanup_fails):
    from ci.native_runtime import probe_native_default_auto as probe

    original_failure = RuntimeError("synthetic finite route failure")
    publisher = SimpleNamespace(_client_request=None, last_error="private-publisher-canary")
    events = []

    def transport(**kwargs):
        record_native_resident_client_failure_code("native_client_timed_out")
        events.append("transport")
        return None

    def routes(*args):
        assert publisher._client_request is not None
        publisher._client_request(payload=b"private-payload-canary", deadline=7)
        events.append("route-failure")
        raise original_failure

    def stop():
        events.append("stop")
        if cleanup_fails:
            raise OSError("private-cleanup-canary")

    daemon = SimpleNamespace(
        start=lambda: events.append("start"),
        stop=stop,
        _server=SimpleNamespace(
            hook_worker=SimpleNamespace(
                policy_snapshot_publisher=publisher,
                prepare_workspace_policy=lambda *a, **k: {},
            )
        ),
    )
    monkeypatch.setattr(probe, "GuardStore", lambda *args: object())
    monkeypatch.setattr(probe, "GuardDaemonServer", lambda *args, **kwargs: daemon)
    monkeypatch.setattr(probe, "_ownership_routes", lambda: {})
    monkeypatch.setattr(probe, "_exercise_installed_routes", routes)
    monkeypatch.setattr(diagnostic, "native_resident_client_request", transport)
    with pytest.raises(RuntimeError) as caught:
        probe._installed_hook_corpus(tmp_path)
    assert caught.value is original_failure
    assert publisher._client_request is None
    assert events == ["start", "transport", "route-failure", "stop"]
    output = capsys.readouterr().err
    assert "transport=native_client_timed_out; started=1; completed=1" in output
    assert ("native_probe_cleanup=failed" in output) is cleanup_fails
    assert "private-" not in output


def test_cleanup_only_failure_is_still_propagated():
    failure = RuntimeError("synthetic cleanup failure")
    calls = []

    def cleanup():
        calls.append(1)
        raise failure

    with pytest.raises(RuntimeError) as caught, diagnostic.cleanup_preserving_failure(cleanup):
        pass
    assert caught.value is failure and calls == [1]


def test_slo_enter_keeps_original_failure_when_its_cleanup_fails(monkeypatch, capsys):
    from scripts.native_slo_session import AdapterSession

    original = RuntimeError("synthetic finite readiness failure")
    events = []

    def start(self):
        events.append("start")
        raise original

    def close(self):
        events.append("close")
        raise OSError("private-cleanup-canary")

    monkeypatch.setattr(AdapterSession, "start", start)
    monkeypatch.setattr(AdapterSession, "close", close)
    with pytest.raises(RuntimeError) as caught:
        object.__new__(AdapterSession).__enter__()
    assert caught.value is original and events == ["start", "close"]
    assert capsys.readouterr().err == "native_probe_cleanup=failed\n"


def test_failed_diagnostic_output_cannot_mask_original_exception(monkeypatch):
    class BrokenOutput:
        def write(self, value):
            raise RuntimeError("private-output-canary")

    original = ValueError("synthetic original failure")
    monkeypatch.setattr(diagnostic.sys, "stderr", BrokenOutput())
    with (
        pytest.raises(ValueError) as caught,
        diagnostic.cleanup_preserving_failure(lambda: (_ for _ in ()).throw(OSError("private-cleanup-canary"))),
    ):
        diagnostic.report_publication_failure(diagnostic.PublicationObservation(), SimpleNamespace(last_error=None))
        raise original
    assert caught.value is original


def test_installed_observer_retains_actual_publisher_error_after_reset(tmp_path, capsys):
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
    from codex_plugin_scanner.guard.store import GuardStore

    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path))
    original = publisher._record_error
    try:
        with diagnostic.observe_publication(publisher) as observation:
            publisher._record_error("native_resident_start_timeout")
            publisher.request_publish()
            diagnostic.report_publication_failure(observation, publisher)
            assert publisher.last_error is None and not publisher._started
        assert publisher._record_error == original and publisher._client_request is None
        output = capsys.readouterr().err
        assert "window=after_daemon_construction" in output
        assert "publisher=missing; transport=missing; started=0; completed=0" in output
        assert "last_publisher=native_resident_start_timeout; error_epoch=0; epoch=1; error_events=1" in output
    finally:
        publisher.close()


def test_actual_long_traceback_never_contains_retained_private_error(tmp_path):
    source = tmp_path / "test_lifecycle_failure.py"
    source.write_text(
        "import os\nfrom types import SimpleNamespace\n"
        "from scripts import native_publication_diagnostic as d\n"
        "def test_failure():\n"
        "    publisher=SimpleNamespace(_client_request=None,_epoch=0,last_error=None,_record_error=lambda value:None)\n"
        "    with d.observe_publication(publisher) as observation:\n"
        "        publisher._record_error(os.environ['SYNTHETIC_PRIVATE_VALUE'])\n"
        "        publisher._epoch=1\n"
        "        d.report_publication_failure(observation,publisher)\n"
        "        assert False, 'synthetic finite readiness failure'\n",
        encoding="utf-8",
    )
    config = tmp_path / "pytest.ini"
    config.write_text("[pytest]\n", encoding="utf-8")
    environment = dict(os.environ)
    root = Path(__file__).resolve().parents[1]
    environment["PYTHONPATH"] = os.pathsep.join([str(root / "src"), str(root)])
    environment["SYNTHETIC_PRIVATE_VALUE"] = "synthetic-private-token-392a14"
    environment.pop("PYTEST_ADDOPTS", None)
    environment.pop("PYTEST_PLUGINS", None)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--tb=long", "-c", str(config), str(source)],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 1 and "1 failed" in output
    assert "last_publisher=other; error_epoch=0; epoch=1; error_events=1" in output
    assert environment["SYNTHETIC_PRIVATE_VALUE"] not in output


@pytest.mark.parametrize("ready", [False, True])
@pytest.mark.parametrize("publisher_error", ["native_policy_authority_source_changed", "private-publisher-canary"])
@pytest.mark.parametrize("output_fails", [False, True])
def test_actual_slo_readiness_failure_emits_finite_lifecycle_and_preserves_original_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    ready: bool,
    publisher_error: str,
    output_fails: bool,
) -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
    from codex_plugin_scanner.guard.store import GuardStore
    from scripts import native_slo_session as session_module

    publisher = NativePolicySnapshotPublisher(store=GuardStore(tmp_path))
    original_record = publisher._record_error
    original_register = publisher.register_workspace
    events = []

    def register(workspace: Path) -> bool:
        events.append(("register", workspace))
        return original_register(workspace)

    monkeypatch.setattr(publisher, "register_workspace", register)

    def prepare(workspace: Path, *, deadline: float) -> dict[str, object] | None:
        events.append((workspace, deadline))
        publisher._record_error(publisher_error)
        publisher.request_publish()
        return {} if ready else None

    daemon = SimpleNamespace(
        start=lambda: events.append("start"),
        port=1,
        _server=SimpleNamespace(
            hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=prepare)
        ),
    )
    session = object.__new__(session_module.AdapterSession)
    session.daemon, session.workspace = cast(Any, daemon), Path("synthetic-workspace")
    monotonic = iter([100.0, 100.401])
    perf = iter([100.0, 100.401])
    monkeypatch.setattr(session_module.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(session_module.time, "perf_counter", lambda: next(perf))
    monkeypatch.setattr(session_module, "HTTPConnection", lambda *args, **kwargs: object())

    class BrokenOutput:
        def write(self, value: str) -> int:
            raise OSError("private-output-canary")

    observation = (
        "window=after_daemon_construction; attached=True; publisher=missing; transport=missing; started=0; completed=0"
    )
    original_error = (
        "native_installed_slo_failed: native readiness exceeded budget"
        if ready
        else "native_installed_slo_failed: native policy was not ready; " + observation
    )
    try:
        with monkeypatch.context() as output_patch:
            if output_fails:
                output_patch.setattr(diagnostic.sys, "stderr", BrokenOutput())
            with pytest.raises(RuntimeError) as caught:
                session.start()
        assert str(caught.value) == original_error
        assert events == ["start", ("register", session.workspace), (session.workspace, 100.4)]
        assert session.readiness_ms == pytest.approx(401.0)
        assert publisher._client_request is None and publisher._record_error == original_record
        # Real registration advances authority before prepare records its
        # refusal and requests the following publication.
        assert publisher.last_error is None and publisher._epoch == 2 and not publisher._started
        output = capsys.readouterr().err
        code = "other" if publisher_error.startswith("private-") else publisher_error
        expected = (
            "native_publication_observation: " + observation + "; "
            "lifecycle_attached=True; initial_publisher=missing; "
            f"last_publisher={code}; error_epoch=1; epoch=2; error_events=1; "
            "worker_started=no; worker_closed=no; worker_acked=no; worker_snapshot=missing; "
            "worker_thread=missing; worker_event=yes; worker_phase=unknown; worker_stack=unavailable; "
            "reservation_metadata_attached=False; reservation_metadata_checks=0; "
            "reservation_metadata_changed=0; reservation_metadata_kinds=none\n"
        )
        assert output == ("" if output_fails else expected)
        assert "private-" not in output
    finally:
        publisher.close()


def test_publisher_description_uses_exact_existing_publisher_vocabulary():
    observation = diagnostic.PublicationObservation()
    known = "native_policy_snapshot_integrity_key_unavailable"
    assert f"publisher={known};" in observation.describe(known)
    assert "publisher=other;" in observation.describe(known + ":private-suffix-canary")
    assert "private-suffix-canary" not in observation.describe(known + ":private-suffix-canary")


@pytest.mark.parametrize(
    "method,label,result,expected",
    [
        ("wait_until_ready", "readiness_wait", True, "ready"),
        ("wait_until_ready", "readiness_wait", False, "not_ready"),
        ("wait_until_ready", "readiness_wait", object(), "other"),
        ("current_snapshot_binding", "current_binding", {"private": "binding-canary"}, "present"),
        ("current_snapshot_binding", "current_binding", None, "missing"),
        ("current_snapshot_binding", "current_binding", b"private-binding-canary", "other"),
        ("current_snapshot", "fallback_snapshot", {"private": "snapshot-canary"}, "present"),
        ("current_snapshot", "fallback_snapshot", None, "missing"),
        ("_confirm_resident_fingerprint", "resident_confirmation", None, "missing"),
        ("_confirm_resident_fingerprint", "resident_confirmation", object(), "present"),
    ],
)
def test_readiness_observer_preserves_exact_call_and_result(method, label, result, expected):
    marker = object()
    calls = []

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        return result

    publisher = SimpleNamespace(_client_request=None, **{method: original})
    with diagnostic.observe_publication(publisher) as observation:
        returned = getattr(publisher, method)(marker, deadline=0.4)
        assert returned is result
        assert calls == [((marker,), {"deadline": 0.4})]
        description = observation.readiness.describe()
        assert f"{label}={expected}" in description
        assert "private" not in description and "canary" not in description
    assert getattr(publisher, method) is original


@pytest.mark.parametrize(
    "acked,snapshot,closed,epoch,expected",
    [
        (True, {"private": "snapshot-canary"}, False, 7, ("yes", "present", "no", "yes")),
        (False, None, False, 8, ("no", "missing", "no", "no")),
        (True, {"private": "snapshot-canary"}, True, 7, ("yes", "present", "yes", "yes")),
        ("private-acked", None, "private-closed", "private-epoch", ("unknown", "missing", "unknown", "unknown")),
    ],
)
def test_completed_publication_records_only_finite_post_return_flags(acked, snapshot, closed, epoch, expected):
    publisher = SimpleNamespace(_client_request=None, _epoch=7)
    calls = []

    def publish(*args, **kwargs):
        calls.append((args, kwargs))
        publisher._acked, publisher._snapshot, publisher._closed, publisher._epoch = acked, snapshot, closed, epoch
        return None

    publisher._publish_once = publish
    with diagnostic.observe_publication(publisher) as observation:
        assert publisher._publish_once(renew_after_generation=31) is None
        assert calls == [((), {"renew_after_generation": 31})]
        description = observation.readiness.describe()
        assert "publication=returned; publication_calls=1/1" in description
        for field, value in zip(("acked", "snapshot", "closed", "entry_epoch_unchanged"), expected, strict=True):
            assert f"publication_{field}={value}" in description
        assert "private" not in description and "31" not in description
    assert publisher._publish_once is publish


def test_readiness_observer_never_interprets_private_return_objects():
    class Hostile:
        def __bool__(self):
            pytest.fail("Private value was coerced")

        def __repr__(self):
            pytest.fail("Private value was rendered")

        def __eq__(self, other):
            pytest.fail("Private value was compared")

    value = Hostile()
    publisher = SimpleNamespace(_client_request=None, wait_until_ready=lambda: value)
    with diagnostic.observe_publication(publisher) as observation:
        assert publisher.wait_until_ready() is value
        assert "readiness_wait=other" in observation.readiness.describe()


@pytest.mark.parametrize(
    "failure", [RuntimeError("private-exception-canary"), KeyboardInterrupt("private-interrupt-canary")]
)
def test_readiness_observer_preserves_original_exception_identity(failure):
    calls = []

    def original(*args, **kwargs):
        calls.append(1)
        raise failure

    publisher = SimpleNamespace(_client_request=None, _publish_once=original)
    with diagnostic.observe_publication(publisher) as observation:
        with pytest.raises(type(failure)) as caught:
            publisher._publish_once()
        assert caught.value is failure and calls == [1]
        assert "publication=raised; publication_calls=1/1" in observation.readiness.describe()
        assert "private" not in observation.readiness.describe()
    assert publisher._publish_once is original


def test_readiness_observer_restores_descriptors_and_preserves_concurrent_replacement():
    class Publisher:
        _client_request = None

        def wait_until_ready(self):
            return True

        def current_snapshot_binding(self) -> dict[str, object] | None:
            return None

    publisher = Publisher()

    def replacement() -> dict[str, object]:
        return {"synthetic": True}

    with diagnostic.observe_publication(publisher) as observation:
        assert publisher.wait_until_ready() is True
        publisher.current_snapshot_binding = replacement
    assert "wait_until_ready" not in vars(publisher)
    assert publisher.current_snapshot_binding is replacement
    assert (
        "current_binding=unobserved; fallback_snapshot=unobserved; resident_confirmation=unobserved"
        in observation.readiness.describe()
    )


def test_readiness_observer_does_not_wait_for_a_captured_publication_on_detach():
    started, release = threading.Event(), threading.Event()
    calls = []

    def publish():
        calls.append(1)
        started.set()
        assert release.wait(2)

    publisher = SimpleNamespace(
        _client_request=None, _publish_once=publish, _epoch=1, _acked=False, _snapshot=None, _closed=False
    )
    with diagnostic.observe_publication(publisher) as observation:
        captured = publisher._publish_once
        worker = threading.Thread(target=captured)
        worker.start()
        assert started.wait(2)
        assert "publication=running; publication_calls=1/0" in observation.readiness.describe()
    assert publisher._publish_once is publish
    release.set()
    worker.join(2)
    assert not worker.is_alive() and calls == [1]
    assert "publication=returned; publication_calls=1/1" in observation.readiness.describe()


def test_failed_readiness_observation_does_not_change_the_original_result(monkeypatch):
    marker = object()
    calls = []

    def original(*args):
        calls.append(args)
        return marker

    publisher = SimpleNamespace(_client_request=None, current_snapshot_binding=original)
    with diagnostic.observe_publication(publisher) as observation:

        def fail(*args):
            raise RuntimeError("private-observer-canary")

        monkeypatch.setattr(observation.readiness, "_finish", fail)
        assert publisher.current_snapshot_binding(marker) is marker
        assert calls == [(marker,)]
        assert "private" not in observation.readiness.describe()


def test_readiness_observer_counters_remain_bounded():
    publisher = SimpleNamespace(_client_request=None, _publish_once=lambda: None)
    with diagnostic.observe_publication(publisher) as observation:
        for _ in range(1001):
            publisher._publish_once()
        assert "publication_calls=999/999" in observation.readiness.describe()


def test_actual_slo_refusal_emits_one_finite_observation_without_extra_calls(monkeypatch, capsys):
    from scripts import native_slo_session as session_module

    events = []
    publisher = SimpleNamespace(
        _client_request=None, _epoch=1, _acked=False, _snapshot=None, _closed=False, last_error=None
    )
    publisher.register_workspace = lambda workspace: events.append(("register", workspace))

    def publish():
        events.append("publish")
        publisher._epoch = 2

    def wait(deadline):
        events.append(("wait", deadline))
        return False

    def binding():
        events.append("binding")
        return None

    def fallback():
        events.append("fallback")
        return None

    publisher._publish_once, publisher.wait_until_ready = publish, wait
    publisher.current_snapshot_binding, publisher.current_snapshot = binding, fallback

    def prepare(workspace, *, deadline):
        events.append(("prepare", workspace, deadline))
        publisher._publish_once()
        assert publisher.wait_until_ready(deadline) is False
        assert publisher.current_snapshot_binding() is None
        return publisher.current_snapshot()

    session = object.__new__(session_module.AdapterSession)
    session.workspace = Path("synthetic-workspace")
    session.daemon = cast(
        Any,
        SimpleNamespace(
            start=lambda: events.append("start"),
            port=1,
            _server=SimpleNamespace(
                hook_worker=SimpleNamespace(policy_snapshot_publisher=publisher, prepare_workspace_policy=prepare)
            ),
        ),
    )
    monotonic, perf = iter([100.0, 100.401]), iter([100.0, 100.401])
    monkeypatch.setattr(session_module.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(session_module.time, "perf_counter", lambda: next(perf))
    monkeypatch.setattr(session_module, "HTTPConnection", lambda *args, **kwargs: object())
    with pytest.raises(RuntimeError) as caught:
        session.start()
    assert str(caught.value) == (
        "native_installed_slo_failed: native policy was not ready; "
        "window=after_daemon_construction; attached=True; publisher=missing; transport=missing; started=0; completed=0"
    )
    assert events == [
        "start",
        ("register", session.workspace),
        ("prepare", session.workspace, 100.4),
        "publish",
        ("wait", 100.4),
        "binding",
        "fallback",
    ]
    assert session.readiness_ms == pytest.approx(401.0)
    output = capsys.readouterr().err
    assert output.count("native_publication_observation: ") == 1
    assert "publication=returned; publication_calls=1/1" in output
    expected_flags = "; ".join(
        [
            "publication_acked=no",
            "publication_snapshot=missing",
            "publication_closed=no",
            "publication_entry_epoch_unchanged=no",
        ]
    )
    assert expected_flags in output
    assert "readiness_wait=not_ready; current_binding=missing; fallback_snapshot=missing" in output
    assert publisher._publish_once is publish and publisher.wait_until_ready is wait
    assert publisher.current_snapshot_binding is binding and publisher.current_snapshot is fallback
