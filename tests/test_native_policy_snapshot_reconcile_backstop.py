"""The periodic reconcile recompiles unchanged inputs only on its backstop."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_policy_snapshot_reconcile import (
    _UNCHANGED_RECOMPILE_SECONDS,
    reconcile_policy_inputs,
)
from codex_plugin_scanner.guard.store import GuardStore

from .native_policy_snapshot_test_fixtures import _DeterministicClock

_READABLE = ("c" * 64, "enforce", "d" * 64)


class _Rig:
    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.clock = _DeterministicClock()
        publisher = NativePolicySnapshotPublisher(
            store=GuardStore(tmp_path / "guard-home"),
            client_request=lambda **_kwargs: b"unused",
            poll_interval_seconds=0.01,
            wall_clock=self.clock.wall_time,
            monotonic_clock=self.clock.monotonic_time,
        )
        publisher._acked = True
        self.publisher = publisher
        self.stats: tuple[object, ...] = (("config.toml", (1, 1, 1, 1)),)
        self.compiles: list[set[str] | None] = []
        self.result: tuple[str, str, str] = _READABLE
        self.error: Exception | None = None
        publisher._input_fingerprint = (self.stats, ())
        monkeypatch.setattr(publisher, "_current_input_fingerprint", lambda: (self.stats, ()))
        monkeypatch.setattr(publisher, "_policy_input_changed", self._compile)
        for name in (
            "_recheck_direct_lane_local_cli",
            "_recheck_direct_lane_review_facts",
            "_recheck_direct_lane_structured_output",
            "_recheck_direct_lane_mcp_relay",
            "_recheck_direct_lane_saved_state",
        ):
            monkeypatch.setattr(publisher, name, lambda *_args: None)

    def _compile(self, changed_paths: set[str] | None = None) -> bool:
        self.compiles.append(changed_paths)
        if self.error is not None:
            raise self.error
        self.publisher._observed_policy_fingerprint = self.result
        return False

    def periodic_pass(self, advance: float = 1.0) -> None:
        self.clock.monotonic += advance
        self.publisher._reconcile_due_monotonic = self.clock.monotonic
        reconcile_policy_inputs(self.publisher)


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    built = _Rig(tmp_path, monkeypatch)
    try:
        yield built
    finally:
        built.publisher.close()


def test_unchanged_inputs_recompile_only_on_the_backstop(rig: _Rig) -> None:
    rig.periodic_pass()
    assert len(rig.compiles) == 1, "the first pass has no compile to rely on"

    passes = int(_UNCHANGED_RECOMPILE_SECONDS) - 1
    for _ in range(passes):
        rig.periodic_pass()
    assert len(rig.compiles) == 1, "unchanged watched files and a held ACK need no recompile"

    rig.periodic_pass()
    assert len(rig.compiles) == 2, "inputs that move without a file write are still checked"


def test_a_moved_watched_file_recompiles_once(rig: _Rig) -> None:
    rig.periodic_pass()
    rig.stats = (("config.toml", (2, 1, 1, 1)),)

    rig.periodic_pass()

    assert rig.compiles == [None, {"config.toml"}], "the change hint compiles; the same pass reuses it"
    rig.periodic_pass()
    assert len(rig.compiles) == 2


def test_a_withdrawn_snapshot_recompiles_every_pass(rig: _Rig) -> None:
    rig.periodic_pass()
    rig.publisher._acked = False

    rig.periodic_pass()
    rig.periodic_pass()

    assert len(rig.compiles) == 3


def test_unavailable_inputs_recompile_every_pass(rig: _Rig) -> None:
    rig.result = ("unavailable", "", "")
    rig.periodic_pass()
    rig.publisher._acked = True

    rig.periodic_pass()

    assert len(rig.compiles) == 2


def test_a_compile_that_raised_is_no_proof(rig: _Rig) -> None:
    rig.periodic_pass()
    rig.clock.monotonic += _UNCHANGED_RECOMPILE_SECONDS
    rig.error = sqlite3.OperationalError("locking protocol")
    rig.periodic_pass(advance=0.0)
    assert len(rig.compiles) == 2
    rig.error = None
    rig.publisher._acked = True

    rig.periodic_pass()

    assert len(rig.compiles) == 3, "a failed compile must not let the next pass skip"
