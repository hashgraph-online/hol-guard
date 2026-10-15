from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_policy_snapshot_direct_lane_saved as saved
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane import (
    DIRECT_HOOK_PERMISSION_NOTICE_FEATURE,
    DIRECT_HOOK_SAVED_DECISION_FEATURE,
    direct_lane_integrity_key,
)

DIGEST = "e" * 64
STATE = {
    "backend": "encrypted-file",
    "cutover_complete": True,
    "degraded_reasons": [],
    "enforcement": "enforce",
    "generation": 3,
    "key_id": "synthetic:0707",
    "mode": "protected",
}
FEATURES = (DIRECT_HOOK_SAVED_DECISION_FEATURE,)


class _Store:
    def __init__(self, state: object = None, error: Exception | None = None) -> None:
        self.state = dict(STATE) if state is None else state
        self.error = error

    @contextmanager
    def _connect(self):
        yield object()

    def _load_policy_integrity_state(self, connection: object) -> object:
        if self.error is not None:
            raise self.error
        return self.state


def _environ(monkeypatch: pytest.MonkeyPatch, environ: dict[str, str]) -> None:
    # The daemon's own module, so pytest's bookkeeping in os.environ stays out.
    monkeypatch.setattr(saved, "os", SimpleNamespace(environ=environ))


@pytest.fixture(autouse=True)
def _daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(saved, "current_extension_control_binding_digest", lambda: DIGEST)
    _environ(monkeypatch, {"HOME": "/home/dev", "PATH": "/usr/bin"})


def test_the_state_binds_only_for_a_resident_that_answers_saved_decisions() -> None:
    assert saved.with_saved_decision_state({"generation": 1}, store=_Store(), features=()) == {"generation": 1}
    assert saved.with_saved_decision_state(None, store=_Store(), features=FEATURES) is None

    bound = saved.with_saved_decision_state({"generation": 1}, store=_Store(), features=FEATURES)

    assert bound == {
        "generation": 1,
        "exact_action_environment": {"HOME": "/home/dev", "PATH": "/usr/bin"},
        "exact_action_control_digest": DIGEST,
        "policy_integrity_state": STATE,
    }


@pytest.mark.parametrize(
    "state",
    [
        {**STATE, "extra": 1},
        {key: value for key, value in STATE.items() if key != "mode"},
        {**STATE, "cutover_complete": 1},
        {**STATE, "generation": True},
        {**STATE, "generation": -1},
        {**STATE, "generation": 1 << 64},
        {**STATE, "key_id": 7},
        {**STATE, "mode": "pro\x85tected"},
        {**STATE, "backend": "x" * 257},
        {**STATE, "degraded_reasons": "keyring"},
        {**STATE, "degraded_reasons": ["r"] * 17},
        ["mode"],
    ],
)
def test_a_state_the_resident_rejects_leaves_the_review_to_the_daemon(state: object) -> None:
    bound = saved.with_saved_decision_state({}, store=_Store(state), features=FEATURES)

    assert bound == {}


@pytest.mark.parametrize("error", [OSError("gone"), sqlite3.OperationalError("locked"), ValueError("bad")])
def test_an_unreadable_state_leaves_the_review_to_the_daemon(error: Exception) -> None:
    assert saved.with_saved_decision_state({}, store=_Store(error=error), features=FEATURES) == {}
    assert saved.with_saved_decision_state({}, store=object(), features=FEATURES) == {}


def test_an_environment_or_digest_the_resident_rejects_leaves_the_review_to_the_daemon(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for environment in ({"A=B": "x"}, {"": "x"}, {"A": "x\0"}, {f"V{index}": "x" for index in range(1025)}):
        _environ(monkeypatch, environment)
        assert saved.with_saved_decision_state({}, store=_Store(), features=FEATURES) == {}
    _environ(monkeypatch, {"BIG": "x" * 262_145})
    assert saved.with_saved_decision_state({}, store=_Store(), features=FEATURES) == {}

    _environ(monkeypatch, {"HOME": "/home/dev"})
    monkeypatch.setattr(saved, "current_extension_control_binding_digest", lambda: None)
    assert saved.with_saved_decision_state({}, store=_Store(), features=FEATURES) == {}


def test_the_integrity_key_also_binds_for_saved_decisions() -> None:
    class _Keyed:
        def _policy_integrity_secret_material(self, *, create: bool) -> tuple[bytes, str]:
            assert create is False
            return b"\x07" * 32, "synthetic:0707"

    assert direct_lane_integrity_key(_Keyed(), ("other",)) is None
    for features in (FEATURES, (DIRECT_HOOK_PERMISSION_NOTICE_FEATURE,)):
        assert direct_lane_integrity_key(_Keyed(), features) == (b"\x07" * 32, "synthetic:0707")
