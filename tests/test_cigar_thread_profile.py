"""Real thread isolation and exception-safe restoration of diagnostic hooks."""

import sys
import threading
from pathlib import Path

import pytest

from scripts.cigar_thread_profile import ThreadProfile


def _foreign_marker():
    return sum(range(100))


def _own_marker():
    return sum(range(200))


def test_only_the_sampled_thread_is_recorded_and_both_clocks_stay_valid():
    entered, finished = threading.Event(), threading.Event()

    def foreign():
        assert entered.wait(2)
        _foreign_marker()
        finished.set()

    def own():
        entered.set()
        assert finished.wait(2)
        return _own_marker()

    worker = threading.Thread(target=foreign)
    worker.start()
    profile = ThreadProfile()
    previous = sys.getprofile()
    try:
        assert profile.call(own) == sum(range(200))
    finally:
        entered.set()
        worker.join(2)
    assert sys.getprofile() is previous
    assert not worker.is_alive()
    result = profile.summary({"tooling": Path(__file__).resolve().parents[1]})
    assert result["profile_complete"] and result["completed_samples"] == 1
    functions = {row["function"] for row in result["top_by_self_cpu"]}
    assert "_own_marker" in functions and "_foreign_marker" not in functions
    assert all(row["self_cpu_seconds"] >= 0 and row["self_elapsed_seconds"] >= 0 for row in result["top_by_self_cpu"])


def test_an_exception_keeps_its_result_and_restores_the_existing_hook():
    def fail():
        raise RuntimeError("synthetic sample failure")

    profile = ThreadProfile()
    previous = sys.getprofile()
    with pytest.raises(RuntimeError, match="synthetic sample failure"):
        profile.call(fail)
    assert sys.getprofile() is previous
    assert profile.summary({"tooling": Path(__file__).resolve().parents[1]})["profile_complete"]
