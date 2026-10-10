from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_daemon_lifecycle as transport


class _Identity:
    sha256 = "identity-a"


class _Status:
    identity = _Identity()


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    transport._NEED_KEYS.clear()
    transport._VERDICTS.clear()
    monkeypatch.setattr(transport, "native_runtime_status", lambda: _Status())
    monkeypatch.setattr(transport, "_resolve_digest_home", lambda home: Path("/home"))
    monkeypatch.setattr(transport, "_record_success", lambda _home: None)


def test_repeat_request_is_answered_once_and_facts_ride_the_first_round(monkeypatch: pytest.MonkeyPatch) -> None:
    rounds: list[dict[str, object]] = []

    def round_trip(query, facts, _home, _platform):
        rounds.append(dict(facts))
        if "pid_running:7" not in facts:
            return {"need": "facts", "keys": ["pid_running:7"]}
        return {"ok": bool(facts["pid_running:7"])}

    monkeypatch.setattr(transport, "_round_trip", round_trip)
    state = {"running": True}

    def resolve(key: str) -> object:
        return state["running"]

    first = transport.native_daemon_lifecycle("live_state_gate", {"payload": {"pid": 7}}, resolve_fact=resolve)
    assert first == {"ok": True}
    assert len(rounds) == 2

    again = transport.native_daemon_lifecycle("live_state_gate", {"payload": {"pid": 7}}, resolve_fact=resolve)
    assert again == {"ok": True}
    assert len(rounds) == 2  # identical query and facts: no resident round trip

    state["running"] = False
    changed = transport.native_daemon_lifecycle("live_state_gate", {"payload": {"pid": 7}}, resolve_fact=resolve)
    assert changed == {"ok": False}
    assert rounds[-1] == {"pid_running:7": False}  # the learned fact set rode the first request


def test_time_bearing_checks_and_failures_are_never_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def round_trip(*_args):
        calls.append(1)
        return {"claim": True}

    monkeypatch.setattr(transport, "_round_trip", round_trip)
    for _ in range(2):
        transport.native_daemon_lifecycle("wake_claim", {"existing": None, "now": 1.0})
    assert len(calls) == 2

    def failing(*_args):
        raise transport.NativeDaemonLifecycleError("native_daemon_lifecycle_unavailable")

    monkeypatch.setattr(transport, "_round_trip", failing)
    for _ in range(2):
        with pytest.raises(transport.NativeDaemonLifecycleError):
            transport.native_daemon_lifecycle("ephemeral_home", {"guard_home": "/x"})
    assert not transport._VERDICTS
