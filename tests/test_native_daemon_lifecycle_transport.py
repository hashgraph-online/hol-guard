from __future__ import annotations

import copy
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_daemon_lifecycle as transport


class _Identity:
    sha256 = "identity-a"
    path = Path("/runtime/hol-guard-runtime")


class _Status:
    identity = _Identity()


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    transport._NEED_KEYS.clear()
    transport._VERDICTS.clear()
    monkeypatch.setattr(transport, "native_runtime_status", lambda: _Status())
    monkeypatch.setattr(transport, "_resolve_existing_digest_home", lambda home: Path("/home"))
    monkeypatch.setattr(transport, "_record_success", lambda _home: None)
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(transport, "native_resident_client_ready", lambda _path, _home: True)


def test_repeat_request_is_answered_once_and_facts_ride_the_first_round(monkeypatch: pytest.MonkeyPatch) -> None:
    rounds: list[dict[str, object]] = []

    def round_trip(query, facts, _home, _platform, _timeout):
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


def test_a_cached_verdict_stays_inside_the_home_that_learned_it(monkeypatch: pytest.MonkeyPatch) -> None:
    checked: list[Path] = []
    calls: list[Path] = []

    def resolve_home(home: Path | None) -> Path:
        assert home is not None
        return home

    def prerequisite(home: Path) -> bool:
        checked.append(home)
        return home == Path("/a")

    def round_trip(_query, _facts, home, _platform, _timeout):
        calls.append(home)
        return {"ok": True, "home": str(home)}

    def resolve(_key: str) -> object:
        return None

    monkeypatch.setattr(transport, "_resolve_existing_digest_home", resolve_home)
    monkeypatch.setattr(transport, "ensure_resident_prerequisite", prerequisite)
    monkeypatch.setattr(transport, "_round_trip", round_trip)

    first = transport.native_daemon_lifecycle(
        "ephemeral_home",
        {"guard_home": "/a"},
        resolve_fact=resolve,
        guard_home=Path("/a"),
    )
    again = transport.native_daemon_lifecycle(
        "ephemeral_home",
        {"guard_home": "/a"},
        resolve_fact=resolve,
        guard_home=Path("/a"),
    )
    assert first == {"ok": True, "home": "/a"}
    assert again == first
    assert calls == [Path("/a")]
    assert checked == [Path("/a")]

    def prerequisite_closed(home: Path) -> bool:
        checked.append(home)
        return False

    monkeypatch.setattr(transport, "ensure_resident_prerequisite", prerequisite_closed)
    with pytest.raises(transport.NativeDaemonLifecycleError, match="prerequisite_unavailable"):
        transport.native_daemon_lifecycle(
            "ephemeral_home",
            {"guard_home": "/a"},
            resolve_fact=resolve,
            guard_home=Path("/a"),
        )
    assert calls == [Path("/a")]

    other = transport.native_daemon_lifecycle(
        "ephemeral_home",
        {"guard_home": "/c"},
        resolve_fact=resolve,
        guard_home=Path("/c"),
    )
    assert other == {"ok": True, "home": "/c"}
    assert calls == [Path("/a"), Path("/c")]


def test_integer_float_fields_are_hashed_as_the_resident_f64_spelling(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[dict[str, object]] = []

    def resident(**kwargs: object) -> dict[str, object]:
        request = kwargs["request"]
        assert isinstance(request, dict)
        captured.append(request)
        digest = "sha256:" + transport._canonical_request_sha256(request)
        return {
            "schema": transport._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": digest,
            "status": "ok",
            "code": "ok",
            "payload": {"claim": True},
        }

    monkeypatch.setattr(transport, "_resident_request", resident)
    verdict = transport.native_daemon_lifecycle("wake_claim", {"existing": None, "now": 10, "now_ns": 10})
    assert verdict == {"claim": True}
    query = captured[0]["query"]
    assert isinstance(query, dict)
    assert query["now"] == 10.0
    assert isinstance(query["now"], float)
    assert query["now_ns"] == 10
    assert isinstance(query["now_ns"], int)
    integer_request = copy.deepcopy(captured[0])
    assert isinstance(integer_request["query"], dict)
    integer_request["query"]["now"] = 10
    assert transport._canonical_request_sha256(integer_request) != transport._canonical_request_sha256(captured[0])


def test_fact_rounds_stop_at_the_operation_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"now": 100.0}
    timeouts: list[float] = []

    monkeypatch.setattr(transport.time, "monotonic", lambda: clock["now"])

    def resident(**kwargs: object) -> dict[str, object]:
        timeout = kwargs["timeout_seconds"]
        assert isinstance(timeout, float)
        timeouts.append(timeout)
        request = kwargs["request"]
        assert isinstance(request, dict)
        clock["now"] = 107.0
        digest = "sha256:" + transport._canonical_request_sha256(request)
        return {
            "schema": transport._RESULT_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": digest,
            "status": "ok",
            "code": "ok",
            "payload": {"need": "facts", "keys": ["pid_running:1"]},
        }

    monkeypatch.setattr(transport, "_resident_request", resident)

    def resolve(_key: str) -> object:
        return True

    with pytest.raises(TimeoutError, match="deadline exceeded"):
        transport.native_daemon_lifecycle(
            "ephemeral_home",
            {"guard_home": "/x"},
            resolve_fact=resolve,
            deadline_monotonic=105.0,
        )
    assert timeouts == [5.0]


def test_resident_outage_is_not_a_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    assert issubclass(transport.NativeDaemonLifecycleError, RuntimeError)
    assert not issubclass(transport.NativeDaemonLifecycleError, ValueError)

    from codex_plugin_scanner.guard.daemon import manager

    def boom(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise transport.NativeDaemonLifecycleError("native_daemon_lifecycle_unavailable")

    monkeypatch.setattr(manager, "native_daemon_lifecycle", boom)
    with pytest.raises(transport.NativeDaemonLifecycleError):
        manager._healthz_payload_is_current("{}")


def test_startup_and_retirement_bind_the_lifecycle_deadline(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon import manager

    clock = {"now": 1000.0}
    seen: list[tuple[str, float | None]] = []
    monkeypatch.setattr(manager.time, "monotonic", lambda: clock["now"])

    def lifecycle(check: str, _query: object, **_kwargs: object) -> dict[str, object]:
        seen.append((check, transport.daemon_lifecycle_deadline()))
        return {"default": 4.0, "post_update": 30.0}

    def live(*_args: object, **_kwargs: object) -> str:
        seen.append(("live", transport.daemon_lifecycle_deadline()))
        return "http://127.0.0.1:9"

    monkeypatch.setattr(manager, "native_daemon_lifecycle", lifecycle)
    monkeypatch.setattr(manager, "_live_or_newer_daemon_url", live)
    url = manager.ensure_guard_daemon(
        tmp_path,
        deadline_monotonic=1010.0,
        background_maintenance=False,
    )
    assert url == "http://127.0.0.1:9"
    assert seen == [("start_timeouts", 1010.0), ("live", 1004.0)]
    assert transport.daemon_lifecycle_deadline() is None

    def inventory(_home: Path) -> list[tuple[int, int]]:
        seen.append(("inventory", transport.daemon_lifecycle_deadline()))
        return []

    monkeypatch.setattr(manager, "_guard_daemon_process_inventory_for_guard_home", inventory)
    monkeypatch.setattr(manager, "reap_orphaned_daemon_workers", lambda **_kwargs: None)
    assert manager.retire_all_guard_daemons_for_home(tmp_path, deadline=50.0) == []
    assert seen[-1] == ("inventory", 50.0)
    assert transport.daemon_lifecycle_deadline() is None


def _answer(kwargs: dict[str, object], timeouts: list[float]) -> dict[str, object]:
    timeout = kwargs["timeout_seconds"]
    assert isinstance(timeout, float)
    timeouts.append(timeout)
    request = kwargs["request"]
    assert isinstance(request, dict)
    return {
        "schema": transport._RESULT_SCHEMA,
        "request_id": request["request_id"],
        "request_sha256": "sha256:" + transport._canonical_request_sha256(request),
        "status": "ok",
        "code": "ok",
        "payload": {"ephemeral": False},
    }


def test_a_cold_resident_spawn_gets_a_start_allowance(monkeypatch: pytest.MonkeyPatch) -> None:
    timeouts: list[float] = []
    monkeypatch.setattr(transport, "native_resident_client_ready", lambda _path, _home: False)
    monkeypatch.setattr(transport, "_resident_request", lambda **kwargs: _answer(kwargs, timeouts))

    transport.native_daemon_lifecycle("ephemeral_home", {"guard_home": "/x"})

    assert timeouts == [transport._TIMEOUT_SECONDS + transport._COLD_START_ALLOWANCE_SECONDS]


def test_a_warm_resident_keeps_the_steady_state_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    timeouts: list[float] = []
    monkeypatch.setattr(transport, "_resident_request", lambda **kwargs: _answer(kwargs, timeouts))

    transport.native_daemon_lifecycle("ephemeral_home", {"guard_home": "/x"})

    assert timeouts == [transport._TIMEOUT_SECONDS]


def test_the_caller_deadline_bounds_the_cold_start_allowance(monkeypatch: pytest.MonkeyPatch) -> None:
    timeouts: list[float] = []
    clock = {"now": 100.0}
    monkeypatch.setattr(transport.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(transport, "native_resident_client_ready", lambda _path, _home: False)
    monkeypatch.setattr(transport, "_resident_request", lambda **kwargs: _answer(kwargs, timeouts))

    transport.native_daemon_lifecycle("ephemeral_home", {"guard_home": "/x"}, deadline_monotonic=112.0)

    assert timeouts == [12.0]
