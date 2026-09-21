from __future__ import annotations

import subprocess
import time
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.native_probe_receipts import receipt_corpus_is_complete, wait_for_receipt_corpus, wait_for_route_corpus


def test_receipt_corpus_complete_requires_processed_count() -> None:
    stats: Mapping[str, object] = {
        "receipt_accepted": 21,
        "receipt_processed": 20,
        "receipt_dropped": 0,
        "receipt_failures": 1,
        "receipt_durable_pending": 1,
    }
    assert not receipt_corpus_is_complete(stats, expected=21)
    assert receipt_corpus_is_complete(
        {
            "receipt_accepted": 21,
            "receipt_processed": 21,
            "receipt_dropped": 0,
            "receipt_failures": 2,
            "receipt_durable_pending": 0,
        },
        expected=21,
    )


def test_wait_for_receipt_corpus_polls_until_processed() -> None:
    snapshots = iter(
        (
            {
                "receipt_accepted": 21,
                "receipt_processed": 20,
                "receipt_dropped": 0,
                "receipt_failures": 1,
                "receipt_durable_pending": 1,
            },
            {
                "receipt_accepted": 21,
                "receipt_processed": 21,
                "receipt_dropped": 0,
                "receipt_failures": 2,
                "receipt_durable_pending": 0,
            },
        )
    )

    class FakeWriter:
        def stats(self) -> Mapping[str, object]:
            return next(snapshots)

    started = time.monotonic()
    complete = wait_for_receipt_corpus(FakeWriter(), expected=21, timeout_seconds=1.0)
    assert complete["receipt_processed"] == 21
    assert time.monotonic() - started < 1.0


def test_installed_corpus_waits_before_mode_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from ci.native_runtime import probe_native_default_auto as probe

    events: list[str] = []

    class DelayedMetrics:
        reads = 0

        def snapshot(self) -> Mapping[str, object]:
            self.reads += 1
            return {"routes": {"native_resident": min(19 + self.reads, 21)}}

    class CompleteWriter:
        def stats(self) -> Mapping[str, object]:
            return {
                "receipt_accepted": 21,
                "receipt_processed": 21,
                "receipt_dropped": 0,
                "receipt_durable_pending": 0,
                "receipt_deduped": 0,
                "receipt_failures": 0,
            }

    metrics = DelayedMetrics()
    worker = SimpleNamespace(
        metrics=metrics,
        policy_snapshot_publisher=SimpleNamespace(),
        prepare_workspace_policy=lambda *args, **kwargs: object(),
        test_oracle=None,
    )

    class FakeDaemon:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._server = SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=CompleteWriter())

        def start(self) -> None:
            events.append("started")

        def stop(self) -> None:
            events.append("stopped")

    def exercise_routes(daemon, guard_home, workspace, routes, route_receipts, reason_codes) -> None:
        route_receipts.extend({"route": "native_resident"} for _ in range(21))

    def exercise_modes(*args: object) -> dict[str, object]:
        assert metrics.reads >= 2, "Mode changes started before the last route was recorded"
        events.append("modes")
        return {}

    monkeypatch.setattr(probe, "GuardStore", lambda *args: object())
    monkeypatch.setattr(probe, "GuardDaemonServer", FakeDaemon)
    monkeypatch.setattr(probe, "_ownership_routes", lambda: {})
    monkeypatch.setattr(probe, "_exercise_installed_routes", exercise_routes)
    monkeypatch.setattr(probe, "_exercise_mode_invariants", exercise_modes)
    result = probe._installed_hook_corpus(tmp_path)
    assert result["native_resident_decisions"] == 21
    assert result["route_count"] == 21
    assert events == ["started", "modes", "stopped"]


def test_wait_for_route_corpus_observes_completion_before_snapshot() -> None:
    snapshots = iter(
        (
            {"routes": {"native_resident": 20}},
            {"routes": {"native_resident": 21}},
        )
    )

    class FakeMetrics:
        def snapshot(self) -> Mapping[str, object]:
            return next(snapshots)

    complete = wait_for_route_corpus(FakeMetrics(), expected=21, timeout_seconds=1.0)
    assert complete["routes"] == {"native_resident": 21}


def test_wait_for_route_corpus_does_not_hide_a_wrong_route() -> None:
    class FakeMetrics:
        def snapshot(self) -> Mapping[str, object]:
            return {"routes": {"native_resident": 20, "native_fail_safe": 1}}

    complete = wait_for_route_corpus(FakeMetrics(), expected=21)
    assert complete["routes"] == {"native_resident": 20, "native_fail_safe": 1}


def test_wait_for_route_corpus_timeout_preserves_incomplete_evidence() -> None:
    class FakeMetrics:
        def snapshot(self) -> Mapping[str, object]:
            return {"routes": {"native_resident": 20}}

    incomplete = wait_for_route_corpus(FakeMetrics(), expected=21, timeout_seconds=0)
    assert incomplete["routes"] == {"native_resident": 20}


@pytest.mark.parametrize(
    "snapshot",
    [
        None,
        {},
        {"routes": []},
        {"routes": {"native_resident": "21"}},
        {"routes": {"native_resident": True}},
        {"routes": {"native_resident": -1}},
    ],
)
def test_wait_for_route_corpus_rejects_invalid_metric_shapes(snapshot: object) -> None:
    class FakeMetrics:
        def snapshot(self) -> object:
            return snapshot

    with pytest.raises(RuntimeError, match="invalid route"):
        wait_for_route_corpus(FakeMetrics(), expected=21, timeout_seconds=0)


def test_wait_for_route_corpus_requires_a_snapshot_method() -> None:
    with pytest.raises(RuntimeError, match="snapshot"):
        wait_for_route_corpus(object(), expected=21)


@pytest.mark.parametrize("expected", [0, -1])
def test_wait_for_route_corpus_rejects_empty_inventory(expected: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        wait_for_route_corpus(object(), expected=expected)


@pytest.mark.parametrize("outcome", ["success", "failure", "timeout", "client_failure"])
def test_probe_closes_scoped_clients_before_stopping_resident(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    outcome: str,
) -> None:
    from ci.native_runtime import probe_native_default_auto as probe

    runtime = tmp_path / "hol-guard-runtime"
    guard_home = tmp_path / "guard-home"
    events: list[tuple[str, Path]] = []

    def close_clients(home: Path) -> bool:
        events.append(("close", home))
        if outcome == "client_failure":
            raise RuntimeError("client close failed")
        return True

    def stop_resident(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        assert events == [("close", guard_home)]
        assert command == (str(runtime), "resident-stop", "--state-dir", str(guard_home / "native-runtime"))
        assert kwargs == {"check": False, "capture_output": True, "timeout": 2}
        events.append(("stop", guard_home))
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(command, timeout=2)
        return subprocess.CompletedProcess(command, returncode=int(outcome == "failure"))

    monkeypatch.setattr(probe, "close_native_residents", close_clients)
    monkeypatch.setattr(probe, "_native_state_files", lambda _home: [tmp_path / "generation.json"])
    monkeypatch.setattr(probe.subprocess, "run", stop_resident)
    if outcome == "success":
        probe._stop_native_runtime(runtime, guard_home)
    elif outcome == "client_failure":
        with pytest.raises(RuntimeError, match="client close failed"):
            probe._stop_native_runtime(runtime, guard_home)
    else:
        with pytest.raises(RuntimeError, match="native resident stop did not complete"):
            probe._stop_native_runtime(runtime, guard_home)

    assert events == [("close", guard_home), ("stop", guard_home)]
    expected_error = {
        "success": "",
        "failure": "native_default_auto_probe_cleanup_failed: returncode=1\n",
        "timeout": "native_default_auto_probe_cleanup_timeout\n",
        "client_failure": "",
    }
    assert capsys.readouterr().err == expected_error[outcome]


@pytest.mark.parametrize("smoke_fails", [False, True])
@pytest.mark.parametrize("client_fails", [False, True])
def test_probe_cleans_both_homes_without_masking_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    smoke_fails: bool,
    client_fails: bool,
) -> None:
    from ci.native_runtime import probe_native_default_auto as probe

    roots: list[Path] = []
    closed: list[Path] = []
    stopped: list[Path] = []

    def smoke(root: Path) -> None:
        roots.append(root)
        (root / "guard-home").mkdir()
        (root / "hook-home").mkdir()
        if smoke_fails:
            raise RuntimeError("smoke check failed")

    def close_clients(home: Path) -> bool:
        closed.append(home)
        if client_fails:
            raise RuntimeError("client close failed")
        return True

    def stop_resident(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        home = Path(command[-1]).parent
        assert home in closed
        stopped.append(home)
        return subprocess.CompletedProcess(command, returncode=0)

    health = SimpleNamespace(state="healthy", reason="native_ready", resident_failures=0, oneshot_failures=0)
    monkeypatch.setattr(probe, "_short_temp_parent", lambda: str(tmp_path))
    monkeypatch.setattr(probe, "_run_native_smoke", smoke)
    monkeypatch.setattr(probe, "native_runtime_health", lambda home: health)
    monkeypatch.setattr(probe, "_native_state_files", lambda home: [tmp_path / "generation.json"])
    monkeypatch.setattr(probe, "_installed_hook_corpus", lambda root: {"route_count": 21})
    monkeypatch.setattr(probe, "close_native_residents", close_clients)
    monkeypatch.setattr(probe.subprocess, "run", stop_resident)
    identity = probe.NativeRuntimeIdentity(path=tmp_path / "hol-guard-runtime", size=0, mtime_ns=0, sha256="0" * 64)
    expected_error = "smoke check failed" if smoke_fails else "client close failed" if client_fails else None
    if expected_error is not None:
        with pytest.raises(RuntimeError, match=expected_error):
            probe._run_temporary_probe(identity)
    else:
        assert probe._run_temporary_probe(identity) == {"route_count": 21}

    assert len(roots) == 1
    assert closed == stopped == [roots[0] / "guard-home", roots[0] / "hook-home"]
    assert not roots[0].exists()
    diagnostic = "native_default_auto_probe_cleanup_failed: RuntimeError\n"
    assert capsys.readouterr().err == (diagnostic * 2 if client_fails else "")


def test_probe_retries_supervisor_join_after_authenticated_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ci.native_runtime import probe_native_default_auto as probe

    runtime = tmp_path / "hol-guard-runtime"
    guard_home = tmp_path / "guard-home"
    attempts: list[Path] = []
    stops: list[tuple[str, ...]] = []

    def close_supervisor(home: Path) -> bool:
        attempts.append(home)
        return len(attempts) == 2

    def stop_resident(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        stops.append(command)
        assert kwargs == {"check": False, "capture_output": True, "timeout": 2}
        return subprocess.CompletedProcess(command, returncode=0)

    monkeypatch.setattr(probe, "close_native_residents", close_supervisor)
    monkeypatch.setattr(probe, "_native_state_files", lambda _home: [tmp_path / "generation.json"])
    monkeypatch.setattr(probe.subprocess, "run", stop_resident)

    probe._stop_native_runtime(runtime, guard_home)

    assert attempts == [guard_home, guard_home]
    assert stops == [(str(runtime), "resident-stop", "--state-dir", str(guard_home / "native-runtime"))]


@pytest.mark.parametrize(
    ("returncode", "stderr", "expected"),
    [
        (1, b"native_resident_stop_unavailable\n", False),
        (2, b"native_resident_stop_unavailable\n", True),
        (2, b"different_failure\n", False),
    ],
)
def test_stop_native_process_accepts_only_documented_idempotent_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    stderr: bytes,
    expected: bool,
) -> None:
    from ci.native_runtime import probe_native_default_auto as probe

    runtime = tmp_path / "hol-guard-runtime"
    guard_home = tmp_path / "guard-home"

    monkeypatch.setattr(probe, "_native_state_files", lambda _home: [])
    monkeypatch.setattr(
        probe.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command,
            returncode=returncode,
            stderr=stderr,
        ),
    )

    assert probe._stop_native_process(runtime, guard_home) is expected
