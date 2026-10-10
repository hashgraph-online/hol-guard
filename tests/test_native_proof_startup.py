"""Exercise private workspace identity and cold-start ordering without relaxing proofs."""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest

from scripts import bench_guard_native_installed_slo as benchmark
from scripts import stress_guard_daemon_runtime as stress


def test_installed_corpus_uses_one_canonical_workspace_for_probe_and_cleanup(tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError as error:
        if os.name == "nt":
            pytest.skip(f"Directory symlinks require Windows privilege: {error}")
        raise
    events = []

    @contextmanager
    def temporary_directory(*, prefix):
        assert prefix == "hol-guard-installed-corpus-"
        yield str(alias)

    def corpus(root):
        assert root == real.resolve()
        events.append(("probe", root))
        return {
            "route_count": 23,
            "native_resident_decisions": 23,
            "native_oneshot_decisions": 0,
            "fail_safe_decisions": 0,
            "python_semantic_decisions": 0,
        }

    monkeypatch.setattr(benchmark.tempfile, "TemporaryDirectory", temporary_directory)
    monkeypatch.setattr(benchmark, "_installed_hook_corpus", corpus)
    monkeypatch.setattr(benchmark, "stop_native_resident", lambda runtime, home: events.append(("stop", home)))
    result = benchmark._installed_corpus(tmp_path / "runtime", 23)
    assert result["routes"] == result["resident"] == 23
    assert result["oneshot"] == result["fail_safe"] == result["python_semantic_decisions"] == 0
    assert events == [("probe", real.resolve()), ("stop", real.resolve() / "hook-home")]


def test_installed_corpus_failure_still_propagates_after_cleanup(tmp_path, monkeypatch):
    failure = RuntimeError("synthetic corpus failure")
    calls = []

    def corpus(root):
        assert root == root.resolve()
        calls.append(("probe", root))
        raise failure

    monkeypatch.setattr(benchmark, "_installed_hook_corpus", corpus)
    monkeypatch.setattr(benchmark, "stop_native_resident", lambda runtime, home: calls.append(("stop", home)))
    with pytest.raises(RuntimeError) as caught:
        benchmark._installed_corpus(tmp_path / "runtime", 23)
    assert caught.value is failure
    assert calls[1] == ("stop", calls[0][1] / "hook-home")
    assert not calls[0][1].exists()


@pytest.mark.parametrize("count", [1, 4])
def test_warmup_primes_before_retaining_the_whole_concurrent_wave(monkeypatch, count):
    owner = threading.get_ident()
    primed = threading.Event()
    submitted = []
    calls = []
    lock = threading.Lock()

    def request(endpoint, auth_token):
        assert endpoint == "http://127.0.0.1/fixture" and auth_token == "fixture-token"
        if threading.get_ident() == owner:
            assert not primed.is_set()
            calls.append("prime")
            primed.set()
        else:
            assert primed.is_set(), "Concurrent warm-up started before cold initialization completed"
            with lock:
                calls.append("wave")
        return 1.0

    class WaveResult:
        def __init__(self, future):
            self.future = future

        def result(self, timeout):
            assert len(submitted) == count, "The complete wave must be submitted before waiting"
            assert timeout == 6
            return self.future.result(timeout=timeout)

    class ObservedExecutor(ThreadPoolExecutor):
        def __init__(self, *, max_workers):
            assert max_workers == count
            super().__init__(max_workers=max_workers)

        def submit(self, function, *args):
            future = super().submit(function, *args)
            submitted.append(future)
            return WaveResult(future)

    monkeypatch.setattr(stress, "stress_request", request)
    monkeypatch.setattr(stress, "ThreadPoolExecutor", ObservedExecutor)
    stress.stress_warmup("http://127.0.0.1/fixture", "fixture-token", count)
    assert calls == ["prime", *(["wave"] * count)]


def test_failed_priming_does_not_submit_or_hide_a_warmup_wave(monkeypatch):
    calls = []
    failure = RuntimeError("cold request failed")

    def request(*args):
        calls.append(args)
        raise failure

    monkeypatch.setattr(stress, "stress_request", request)
    with pytest.raises(RuntimeError) as caught:
        stress.stress_warmup("fixture", "token", 4)
    assert caught.value is failure and calls == [("fixture", "token")]


def test_failed_concurrent_warmup_is_not_waived_by_successful_priming(monkeypatch):
    owner = threading.get_ident()
    failure = RuntimeError("warm-up wave failed")

    def request(*args):
        if threading.get_ident() != owner:
            raise failure
        return 1.0

    monkeypatch.setattr(stress, "stress_request", request)
    with pytest.raises(RuntimeError) as caught:
        stress.stress_warmup("fixture", "token", 4)
    assert caught.value is failure


@pytest.mark.parametrize("count", [0, -1])
def test_invalid_warmup_count_makes_no_requests(monkeypatch, count):
    calls = []
    monkeypatch.setattr(stress, "stress_request", lambda *args: calls.append(args))
    with pytest.raises(ValueError, match="positive"):
        stress.stress_warmup("fixture", "token", count)
    assert calls == []
