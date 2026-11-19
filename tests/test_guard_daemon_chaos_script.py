"""The chaos gate's own checks: what it counts as a failure."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import check_guard_daemon_chaos as chaos


def test_a_failed_launch_record_needs_a_readable_code() -> None:
    assert chaos._failure_code('{"code": "runtime_command_unknown"}') == "runtime_command_unknown"
    assert chaos._failure_code("{not json") == "unreadable"
    assert chaos._failure_code('{"code": null}') == "unreadable"
    assert chaos._failure_code('{"code": ""}') == "unreadable"
    assert chaos._failure_code('["runtime_command_unknown"]') == "unreadable"


def _traffic_with_one_connection_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    fault_at: float | None,
    served_again_at: float | None,
) -> chaos._HookTraffic:
    traffic = chaos._HookTraffic(tmp_path / "guard", tmp_path / "home", "")
    traffic.fault_at = fault_at
    traffic.served_again_at = served_again_at

    def send_once(_endpoint: str, _token: str) -> tuple[str, str]:
        traffic._stop.set()
        return "connection:ConnectionRefusedError", ""

    monkeypatch.setattr(traffic, "_target", lambda: ("http://127.0.0.1:1/v1/hooks/pi", "unused"))
    monkeypatch.setattr(traffic, "_recover", lambda: None)
    monkeypatch.setattr(chaos, "_send_hook", send_once)
    traffic._work()
    return traffic


def test_a_connection_failure_before_the_fault_is_a_stray_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    traffic = _traffic_with_one_connection_failure(monkeypatch, tmp_path, fault_at=None, served_again_at=None)
    assert dict(traffic.stray_failures) == {"connection:ConnectionRefusedError": 1}


def test_a_connection_failure_after_serving_again_is_a_stray_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    traffic = _traffic_with_one_connection_failure(monkeypatch, tmp_path, fault_at=0.0, served_again_at=0.0)
    assert dict(traffic.stray_failures) == {"connection:ConnectionRefusedError": 1}


def test_a_connection_failure_during_the_outage_is_expected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    traffic = _traffic_with_one_connection_failure(monkeypatch, tmp_path, fault_at=0.0, served_again_at=None)
    assert dict(traffic.stray_failures) == {}
    assert traffic.outcomes["connection:ConnectionRefusedError"] == 1


def _judged(answers: list[str], errors: list[str], new_publishers: list[int]) -> list[str]:
    from scripts import guard_daemon_chaos_starts as starts

    result = chaos.ScenarioResult(name="parallel-starts")
    starts.judge_starts(result, answers, errors, new_publishers)
    return result.failures


def test_parallel_starts_pass_with_one_daemon_for_every_starter() -> None:
    assert _judged(["http://127.0.0.1:1"] * 20, [], [42]) == []


def test_a_refused_start_fails_the_parallel_starts() -> None:
    failures = _judged(["http://127.0.0.1:1"] * 19, ["RuntimeError: refused"], [42])
    assert failures == ["1 of 20 starts failed: RuntimeError: refused"]


def test_starters_answered_with_different_daemons_fail() -> None:
    failures = _judged(["http://127.0.0.1:1", "http://127.0.0.1:2"], [], [42])
    assert failures == ["the starts answered with 2 different daemons"]


def test_a_second_new_daemon_fails_the_parallel_starts() -> None:
    assert _judged(["http://127.0.0.1:1"], [], [42, 43]) == ["2 new daemons published themselves, expected exactly one"]
    assert _judged(["http://127.0.0.1:1"], [], []) == ["0 new daemons published themselves, expected exactly one"]


def _judged_mixed(
    errors: list[str],
    new_publishers: list[int],
    retired: list[int],
    *,
    current: bool = True,
    overlapped: bool = True,
    journal: str = "ok",
) -> list[str]:
    from scripts import guard_daemon_chaos_starts as starts

    result = chaos.ScenarioResult(name="mixed-runtime-starts")
    starts.judge_mixed_starts(
        result, errors, 10, new_publishers, retired, current=current, overlapped=overlapped, journal=journal
    )
    return result.failures


def test_mixed_runtime_starts_pass_when_only_the_older_daemon_is_replaced() -> None:
    assert _judged_mixed([], [41, 42], [41]) == []
    assert _judged_mixed([], [41], []) == []


def test_runtimes_taking_turns_to_replace_daemons_fail_the_mixed_starts() -> None:
    thrashing = "the starters retired 2 daemons: the two runtimes replaced each other's daemons"
    assert _judged_mixed([], [41, 42], [41, 42]) == [thrashing]
    assert _judged_mixed([], [41, 42], [42]) == [
        "the starters retired 1 daemons: the two runtimes replaced each other's daemons"
    ]
    assert _judged_mixed([], [41, 42, 43], [41, 42]) == [
        "3 new daemons published themselves, expected the older runtime's and at most one more",
        thrashing,
    ]


def test_a_refused_start_or_an_older_survivor_fails_the_mixed_starts() -> None:
    assert _judged_mixed(["previous launch refused"], [41], []) == ["1 of 10 starts failed: previous launch refused"]
    assert _judged_mixed([], [41], [], current=False) == [
        "the daemon serving the home does not carry the current runtime's identity"
    ]


def test_mixed_starts_that_never_met_the_older_launch_fail() -> None:
    assert _judged_mixed([], [41, 42], [41], overlapped=False) == [
        "no current-runtime start overlapped the older runtime's held launch"
    ]


def test_an_unreadable_journal_fails_the_mixed_starts_instead_of_counting_no_retirements() -> None:
    for status in ("journal_unavailable", "invalid_entries_omitted", "journal_path_unsafe"):
        assert _judged_mixed([], [41], [], journal=status) == [
            f"the lifecycle journal could not be read in full ({status}), so retirements are unproven"
        ]


def test_retirements_count_only_the_new_publishers_records() -> None:
    from scripts import guard_daemon_chaos_starts as starts

    events: list[dict[str, object]] = [
        {"event": "published", "pid": 41},
        {"event": "retirement_requested", "pid": 41},
        {"event": "retirement_requested", "pid": 7},
        {"event": "retirement_requested", "pid": "41"},
        {"event": "published", "pid": 42},
        {"event": "published", "pid": 41},
    ]
    assert starts._published(events) == [41, 42]
    assert starts._retirements(events, [41, 42]) == [41]


class _Starter:
    def __init__(self, returncode: int | None) -> None:
        self.returncode = returncode

    def poll(self) -> int | None:
        return self.returncode


def test_a_starter_counts_as_meeting_the_held_launch_only_once_it_is_inside_ensure(tmp_path: Path) -> None:
    from scripts import guard_daemon_chaos_starts as starts

    entered = tmp_path / "1.entered"
    importing = tmp_path / "3.entered"
    entered.touch()
    # Still running but never reached ensure: it may only be importing, so it proves nothing.
    assert starts._waiting_in_ensure([(_Starter(None), importing)]) is False
    # Reached ensure, then finished: it did not wait on the held launch.
    assert starts._waiting_in_ensure([(_Starter(0), entered)]) is False
    assert starts._waiting_in_ensure([(_Starter(None), importing), (_Starter(None), entered)]) is True


def test_only_this_homes_resident_is_the_one_to_kill(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from scripts import guard_daemon_chaos_runtime as runtime_faults

    guard_home = tmp_path / "guard"
    (guard_home / "native-runtime").mkdir(parents=True)
    other = tmp_path / "other" / "native-runtime"
    other.mkdir(parents=True)
    link = tmp_path / "link"
    link.symlink_to(guard_home)
    runtime = "/opt/hol-guard-runtime"
    processes = [
        (11, [runtime, "serve-managed", "--state-dir", str(guard_home / "native-runtime"), "--generation", "1"]),
        (12, [runtime, "serve-managed", "--state-dir", str(link / "native-runtime")]),
        (13, [runtime, "serve-managed", "--state-dir", str(other)]),
        (14, [runtime, "supervise-managed", "--state-dir", str(guard_home / "native-runtime")]),
        (15, [runtime, "resident-client-stream", "--stdin", str(guard_home / "native-runtime")]),
        (16, [runtime, "serve-managed", "--state-dir"]),
        (17, [runtime]),
    ]
    monkeypatch.setattr(chaos, "_processes", lambda: processes)

    assert runtime_faults._resident_pids(guard_home) == [11, 12]


def test_a_replacement_on_the_same_port_is_not_the_same_daemon() -> None:
    from scripts.guard_daemon_chaos_runtime import _same_daemon

    first = {"pid": 11, "state_id": "a", "port": 4781}
    assert _same_daemon(first, dict(first))
    assert not _same_daemon(first, {**first, "pid": 12})
    assert not _same_daemon(first, {**first, "state_id": "b"})
    assert not _same_daemon(first, None)
    assert not _same_daemon(None, first)
    assert not _same_daemon({"port": 4781}, {"port": 4781})
