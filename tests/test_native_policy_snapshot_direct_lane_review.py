from __future__ import annotations

import sqlite3
import threading
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_direct_lane_review as review
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane_review import (
    DIRECT_HOOK_REVIEW_FACTS_FEATURE,
    uniform_blocked_request_mode,
    with_review_facts,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publication import NativePolicySnapshotPublicationMixin

FEATURES = (DIRECT_HOOK_REVIEW_FACTS_FEATURE,)


LISTENING = {"daemon_host": "127.0.0.1", "daemon_port": 4781}


class _Store:
    def __init__(self, state: object = LISTENING, source: object = "default") -> None:
        self.state = state
        self._guard_source = source

    def get_runtime_state(self) -> object:
        return self.state


@pytest.fixture(autouse=True)
def _cwd(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(review.os, "getcwd", lambda: "/work/daemon")


def _bound(store: object, mode: str | None = "ask") -> dict[str, object]:
    bound = with_review_facts({"generation": 1}, store=store, features=FEATURES, blocked_request_mode=mode)
    assert bound is not None
    return bound


def test_facts_bind_only_for_a_resident_that_accepts_them() -> None:
    assert with_review_facts({"generation": 1}, store=_Store(), features=(), blocked_request_mode="ask") == {
        "generation": 1
    }
    assert with_review_facts(None, store=_Store(), features=FEATURES, blocked_request_mode="ask") is None
    assert _bound(_Store()) == {
        "generation": 1,
        "blocked_request_mode": "ask",
        "approval_center_origin": "http://127.0.0.1:4781",
        "review_oauth_source": "default",
        "review_host_cwd": "/work/daemon",
    }


@pytest.mark.parametrize(
    ("state", "origin"),
    [
        (None, None),
        ({}, None),
        ({"daemon_host": "127.0.0.1"}, None),
        ({"daemon_host": "127.0.0.1", "daemon_port": 0}, None),
        ({"approval_center_url": " "}, None),
        ({"daemon_host": "::1", "daemon_port": 4781}, "http://[::1]:4781"),
        ({"daemon_host": "127.0.0.1", "daemon_port": 5123}, "http://127.0.0.1:5123"),
        ({"approval_center_url": "http://localhost:6000/"}, "http://localhost:6000"),
        (
            {"approval_center_url": "http://localhost:6000/", "daemon_host": "127.0.0.1", "daemon_port": 5123},
            "http://localhost:6000",
        ),
    ],
)
def test_the_origin_is_the_one_the_daemon_links_a_queued_review_to(state: object, origin: str | None) -> None:
    # Before the daemon records where it listens it would link the default
    # port, which is not where its approval center will be, so no origin binds.
    assert _bound(_Store(state)).get("approval_center_origin") == origin


def test_a_fact_the_resident_cannot_accept_is_left_out(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_cwd() -> str:
        raise FileNotFoundError

    monkeypatch.setattr(review.os, "getcwd", no_cwd)
    bound = _bound(_Store(source=None), mode="prompt")
    assert bound == {"generation": 1, "approval_center_origin": "http://127.0.0.1:4781"}
    monkeypatch.setattr(review.os, "getcwd", lambda: "/work/\0daemon")
    assert "review_host_cwd" not in _bound(_Store())
    monkeypatch.setattr(review.os, "getcwd", lambda: "/" * 4097)
    assert "review_host_cwd" not in _bound(_Store())


def test_the_mode_binds_only_when_every_compiled_config_agrees() -> None:
    def config(mode: object) -> object:
        return SimpleNamespace(blocked_request_mode=mode)

    assert uniform_blocked_request_mode([config("ask"), config("ask")]) == "ask"
    assert uniform_blocked_request_mode([config("safe-alternative")]) == "safe-alternative"
    assert uniform_blocked_request_mode([config("ask"), config("safe-alternative")]) is None
    assert uniform_blocked_request_mode([config("prompt")]) is None
    assert uniform_blocked_request_mode([]) is None


class _Publisher(NativePolicySnapshotPublicationMixin):
    def __init__(self, store: _Store) -> None:
        self.store = store
        self._condition = threading.Condition()
        self._publish_event = threading.Event()
        self._closed = False
        self._acked = True
        self._snapshot = {"generation": 7}
        self._direct_lane_ack_target: tuple[int, str] | None = (7, "digest")
        self._direct_lane_review_facts = review.recheckable_review_facts(store)
        self._renewal_after_generation: int | None = None
        self._retry_not_before_monotonic: float | None = None
        self._failure_count = 3
        self.closed_lane = 0

    def _monotonic_clock(self) -> float:
        return 42.0

    def _close_direct_lane_ack(self) -> None:
        self.closed_lane += 1
        self._direct_lane_ack_target = None


def test_a_moved_origin_or_cwd_closes_the_lane_and_republishes_under_the_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _Store({"daemon_host": "127.0.0.1", "daemon_port": 5123})
    publisher = _Publisher(store)
    publisher._recheck_direct_lane_review_facts()
    assert publisher.closed_lane == 0
    assert not publisher._publish_event.is_set()

    store.state = {"daemon_host": "127.0.0.1", "daemon_port": 5124}
    publisher._recheck_direct_lane_review_facts()
    assert publisher.closed_lane == 1
    assert publisher._acked is True
    assert publisher._renewal_after_generation == 7
    assert publisher._retry_not_before_monotonic == 42.0
    assert publisher._failure_count == 0
    assert publisher._publish_event.is_set()

    publisher = _Publisher(store)
    monkeypatch.setattr(review.os, "getcwd", lambda: "/work/elsewhere")
    publisher._recheck_direct_lane_review_facts()
    assert publisher.closed_lane == 1


def test_an_unbound_or_closed_lane_is_not_rechecked() -> None:
    store = _Store()
    publisher = _Publisher(store)
    publisher._direct_lane_review_facts = None
    store.state = {"daemon_host": "127.0.0.1", "daemon_port": 5124}
    publisher._recheck_direct_lane_review_facts()
    publisher = _Publisher(_Store())
    publisher._direct_lane_ack_target = None
    publisher.store.state = {"daemon_host": "127.0.0.1", "daemon_port": 5124}
    publisher._recheck_direct_lane_review_facts()
    assert publisher.closed_lane == 0
    assert not publisher._publish_event.is_set()


def test_learning_the_listen_origin_after_the_first_publish_keeps_the_lane() -> None:
    store = _Store(None)
    publisher = _Publisher(store)
    assert publisher._direct_lane_review_facts == (None, "/work/daemon")

    store.state = {"daemon_host": "127.0.0.1", "daemon_port": 5123}
    publisher._recheck_direct_lane_review_facts()
    assert publisher.closed_lane == 0
    assert publisher._renewal_after_generation is None
    assert not publisher._publish_event.is_set()


def test_a_moved_cwd_still_closes_a_lane_bound_without_an_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _Store(None)
    publisher = _Publisher(store)
    store.state = {"daemon_host": "127.0.0.1", "daemon_port": 5123}
    monkeypatch.setattr(review.os, "getcwd", lambda: "/work/elsewhere")
    publisher._recheck_direct_lane_review_facts()
    assert publisher.closed_lane == 1
    assert publisher._renewal_after_generation == 7
    assert publisher._publish_event.is_set()


class _LockedStore(_Store):
    locked = False

    def get_runtime_state(self) -> object:
        if self.locked:
            raise sqlite3.OperationalError("database is locked")
        return self.state


def test_an_unreadable_runtime_state_binds_no_origin_and_keeps_the_lane() -> None:
    store = _LockedStore({"daemon_host": "127.0.0.1", "daemon_port": 5123})
    publisher = _Publisher(store)
    store.locked = True
    assert review.approval_center_origin(store) is None
    assert review.recheckable_review_facts(store) is None
    publisher._recheck_direct_lane_review_facts()
    assert publisher.closed_lane == 0
    assert not publisher._publish_event.is_set()
    store.locked = False
    publisher._recheck_direct_lane_review_facts()
    assert publisher.closed_lane == 0
