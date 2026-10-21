"""A hook review that cannot read the authority lease still reviews.

Every acquirer takes the authority turnstile exclusively and a writer holds it
for the whole of its wait, so one publication commit can hold the next hook
out. Waiting the hook's whole budget for the lease leaves the native evaluator
none and the command is held for approval, so the wait is capped and the review
runs without the lease. The snapshot is bound before the fence and handed to
the review either way, so an unleased review reads the policy a leased one
would read.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_native_review_fence import (
    LEASE_WAIT_SECONDS,
    native_review_fence,
)
from codex_plugin_scanner.guard.native_command_control_authority_io import (
    hold_command_control_authority_lock,
)

_SNAPSHOT = {"command_extensions_bound": True, "generation": 1}


def _fence(guard_home: Path, *, budget: float | None) -> bool | None:
    with native_review_fence(
        policy_snapshot=_SNAPSHOT,
        event_name="PreToolUse",
        recording_only=False,
        guard_home=guard_home,
        deadline=None if budget is None else time.monotonic() + budget,
    ) as fenced:
        return fenced


def _behind_a_held_mutation(guard_home: Path, *, budget: float | None):
    """Run one fence while another thread holds the authority lock."""

    held = threading.Event()
    release = threading.Event()
    outcome: list[object] = []

    def mutate() -> None:
        with hold_command_control_authority_lock(guard_home):
            held.set()
            release.wait(10.0)

    writer = threading.Thread(target=mutate, daemon=True)
    writer.start()
    try:
        assert held.wait(5.0)
        started = time.monotonic()
        try:
            outcome.append(_fence(guard_home, budget=budget))
        except TimeoutError as error:
            outcome.append(error)
        waited = time.monotonic() - started
    finally:
        release.set()
        writer.join(10.0)
    return outcome[0], waited


def test_an_uncontended_review_holds_the_lease(tmp_path):
    assert _fence(tmp_path, budget=5.0) is True


def test_a_review_behind_a_held_mutation_is_not_refused(tmp_path):
    fenced, waited = _behind_a_held_mutation(tmp_path, budget=5.0)
    assert fenced is None
    assert waited < 2.0


def test_the_lease_wait_leaves_the_review_its_budget(tmp_path):
    """The wait is capped, so a held lock cannot spend the whole deadline."""

    budget = LEASE_WAIT_SECONDS * 8
    fenced, waited = _behind_a_held_mutation(tmp_path, budget=budget)
    assert fenced is None
    assert waited < budget / 2


def test_a_contended_review_with_no_budget_left_is_refused(tmp_path):
    """An unleased review still needs time to run, so refuse one with none."""

    refused, _waited = _behind_a_held_mutation(tmp_path, budget=0.0)
    assert isinstance(refused, TimeoutError)
    assert str(refused) == "native_review_fence_deadline"


def test_a_contended_review_with_no_deadline_is_not_refused(tmp_path):
    """No deadline is not no time: the review runs and the caller checks it."""

    fenced, waited = _behind_a_held_mutation(tmp_path, budget=None)
    assert fenced is None
    assert waited < 2.0
