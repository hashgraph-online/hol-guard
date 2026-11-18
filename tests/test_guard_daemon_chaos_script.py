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
